use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use core::time::Duration;
use serialport::{DataBits, FlowControl, Parity, StopBits};
use slog::{debug, info, o, trace, warn, Drain, Level, Logger};
use slog_async::AsyncGuard;
use std::path::{Path, PathBuf};

use attest_data::messages::{HostToRotCommand, RotToHost};
use host_sp_messages::{Header, HostToSp, SpToHost, MAGIC, MAX_MESSAGE_SIZE};

#[derive(Subcommand, Debug)]
pub enum Command {
    GetCerts,
    GetLog,
    Attest,
    TqSign,
    ReadImage {
        #[clap(long, value_parser = parse_hash)]
        hash: [u8; 32],
    },
}

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Path to the serial port
    #[clap(long, env)]
    port: PathBuf,

    /// Log level
    #[clap(value_enum, short, long, default_value_t = LogLevel::Info)]
    log_level: LogLevel,

    /// Write logs to a file instead of stderr.
    #[clap(long)]
    logfile: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum LogLevel {
    Trace,
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

impl From<LogLevel> for Level {
    fn from(value: LogLevel) -> Self {
        match value {
            LogLevel::Trace => Level::Trace,
            LogLevel::Debug => Level::Debug,
            LogLevel::Info => Level::Info,
            LogLevel::Warning => Level::Warning,
            LogLevel::Error => Level::Error,
            LogLevel::Critical => Level::Critical,
        }
    }
}

fn build_logger(
    level: Level,
    path: Option<&Path>,
) -> Result<(Logger, AsyncGuard)> {
    fn make_drain<D: slog_term::Decorator + Send + 'static>(
        level: Level,
        decorator: D,
    ) -> (slog::Fuse<slog_async::Async>, AsyncGuard) {
        let drain = slog_term::FullFormat::new(decorator)
            .build()
            .filter_level(level)
            .fuse();
        let (drain, guard) = slog_async::Async::new(drain).build_with_guard();
        (drain.fuse(), guard)
    }

    let (drain, guard) = if let Some(path) = path {
        let file = std::fs::File::create(path).with_context(|| {
            format!("failed to create logfile {}", path.display())
        })?;
        make_drain(level, slog_term::PlainDecorator::new(file))
    } else {
        make_drain(level, slog_term::TermDecorator::new().build())
    };

    Ok((Logger::root(drain, o!("component" => "faux-ipcc")), guard))
}

fn parse_hash(s: &str) -> Result<[u8; 32]> {
    let bytes =
        hex::decode(s).with_context(|| format!("Invalid hex string: {s}"))?;
    if bytes.len() != 32 {
        bail!(
            "expected 32 bytes (64 hex chars), got {} bytes",
            bytes.len()
        );
    }
    Ok(bytes.try_into().unwrap())
}

fn main() -> Result<()> {
    let args = Args::parse();

    let (log, _guard) =
        build_logger(args.log_level.into(), args.logfile.as_deref())?;

    let mut worker = Worker::new(&args.port, log)?;
    match args.command {
        Command::ReadImage { .. } => {
            unimplemented!()
        }
        Command::GetCerts => {
            worker.do_rot_command(HostToRotCommand::GetCertificates, |_| 0)
        }
        Command::GetLog => {
            worker.do_rot_command(HostToRotCommand::GetMeasurementLog, |_| 0)
        }
        Command::Attest => {
            worker.do_rot_command(HostToRotCommand::Attest, |buf| {
                let nonce = [0x00; 32];
                buf.copy_from_slice(&nonce);
                32
            })
        }
        Command::TqSign => {
            worker.do_rot_command(HostToRotCommand::TqSign, |buf| {
                let nonce = [0x00; 32];
                buf[..nonce.len()].copy_from_slice(&nonce);
                32
            })
        }
    }
}

struct Worker {
    log: Logger,
    port: Box<dyn serialport::SerialPort>,
}

impl Worker {
    fn new(port_path: &Path, log: Logger) -> Result<Self> {
        let Some(port_name) = port_path.to_str() else {
            bail!("could not parse port name from {:?}", port_path);
        };
        info!(log, "connecting to serial port at `{port_name}`");
        let port = serialport::new(port_name, 3_000_000)
            .timeout(Duration::from_millis(100))
            .data_bits(DataBits::Eight)
            .flow_control(FlowControl::Hardware)
            .parity(Parity::None)
            .stop_bits(StopBits::One)
            .open()
            .unwrap();
        Ok(Self { log, port })
    }

    // XXX this is copy-pasted from old code and may not be relevant / correct!
    fn do_rot_command<F>(
        &mut self,
        msg: HostToRotCommand,
        fill: F,
    ) -> Result<()>
    where
        F: FnOnce(&mut [u8]) -> usize,
    {
        let mut buf = [0; MAX_MESSAGE_SIZE];
        let mut corncob_buf = [0; MAX_MESSAGE_SIZE];
        let header = Header {
            magic: MAGIC,
            version: 0x1,
            sequence: 0x1,
        };

        let message = HostToSp::RotRequest;
        let mut rot_message = vec![0; 12 + 32];
        let message_len =
            attest_data::messages::serialize(&mut rot_message, &msg, fill)?;

        let n =
            host_sp_messages::serialize(&mut buf, &header, &message, |buf| {
                buf[..message_len].copy_from_slice(&rot_message[..message_len]);
                message_len
            })
            .unwrap();

        debug!(self.log, "hubpack {} {:x?}", n, &buf[..n]);
        let n = corncobs::encode_buf(&buf[..n], &mut corncob_buf);
        debug!(self.log, "corncob {} {:x?}", n, &corncob_buf[..n]);
        self.port.write_all(&corncob_buf[..n]).unwrap();
        //port.flush().unwrap();
        //port.write(&[0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]).unwrap();
        //port.flush().unwrap();

        let mut bytes = [0; 2048];
        let mut cob_bytes: [u8; 2048] = [0; 2048];
        let mut n = 0;
        std::thread::sleep(std::time::Duration::from_millis(1000));

        loop {
            trace!(self.log, "n {}", n);
            self.port
                .read_exact(&mut bytes[n..n + 1])
                .context("failed to read back data")?;
            if bytes[n] == 0 {
                warn!(self.log, "uh oh {}", n);
                if n != 0 {
                    break;
                } else {
                    continue;
                }
            }
            n += 1;
            if n == 2046 {
                break;
            }
        }

        let start = bytes.iter().position(|&x| x != 0).unwrap();

        //println!("raw {:x?}", bytes);
        let n = corncobs::decode_buf(&bytes[start..], &mut cob_bytes).unwrap();
        info!(self.log, "received {} {:x?}", n, cob_bytes);
        //let data = attest_data::messages::parse_response(&cob_bytes[..n], RotToHost::RotTqSign).unwrap();
        let (_header, _request, data) =
            host_sp_messages::deserialize::<SpToHost>(&cob_bytes[..n]).unwrap();

        let data =
            attest_data::messages::parse_response(data, RotToHost::RotTqSign)
                .unwrap();
        info!(self.log, "got data {data:?}");

        info!(self.log, "done.");
        Ok(())
    }
}
