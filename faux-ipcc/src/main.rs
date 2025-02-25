use clap::{Parser, Subcommand};
use core::time::Duration;
use serialport::{DataBits, FlowControl, Parity, StopBits};
use std::path::PathBuf;

use attest_data::messages::{HostToRotCommand, RotToHost};
use host_sp_messages::{
    deserialize, serialize, Header, HostToSp, SpToHost, MAGIC, MAX_MESSAGE_SIZE,
};

#[derive(Subcommand, Debug)]
pub enum Command {
    GetCerts,
    GetLog,
    Attest,
    TqSign,
}

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Command,

    #[clap(long, env)]
    out: PathBuf,

    #[clap(long)]
    emit_cmd: bool,
}

fn main() {
    let args = Args::parse();

    let mut port = serialport::new("/dev/ttyUSB1", 3_000_000)
        .timeout(Duration::from_millis(100))
        .data_bits(DataBits::Eight)
        .flow_control(FlowControl::Hardware)
        .parity(Parity::None)
        .stop_bits(StopBits::One)
        .open()
        .unwrap();

    let mut buf = [0; MAX_MESSAGE_SIZE];
    let mut corncob_buf = [0; MAX_MESSAGE_SIZE];
    let header = Header {
        magic: MAGIC,
        version: 0x1,
        sequence: 0x1,
    };

    let message = HostToSp::RotRequest;
    let mut rot_message = vec![0; 12 + 32];

    let message_len = match args.command {
        Command::GetCerts => attest_data::messages::serialize(
            &mut rot_message,
            &HostToRotCommand::GetCertificates,
            |_| 0,
        )
        .unwrap(),
        Command::GetLog => attest_data::messages::serialize(
            &mut rot_message,
            &HostToRotCommand::GetMeasurementLog,
            |_| 0,
        )
        .unwrap(),
        Command::Attest => attest_data::messages::serialize(
            &mut rot_message,
            &HostToRotCommand::Attest,
            |buf| {
                let nonce = [0x00; 32];
                buf.copy_from_slice(&nonce);
                32
            },
        )
        .unwrap(),
        Command::TqSign => attest_data::messages::serialize(
            &mut rot_message,
            &HostToRotCommand::TqSign,
            |buf| {
                let nonce = [0x00; 32];
                buf[..nonce.len()].copy_from_slice(&nonce);
                32
            },
        )
        .unwrap(),
    };

    let n = serialize(&mut buf, &header, &message, |buf| {
        buf[..message_len].copy_from_slice(&rot_message[..message_len]);
        message_len
    })
    .unwrap();

    println!("hubpack {} {:x?}", n, &buf[..n]);
    let n = corncobs::encode_buf(&buf[..n], &mut corncob_buf);
    println!("corncob {} {:x?}", n, &corncob_buf[..n]);
    port.write_all(&corncob_buf[..n]).unwrap();
    //port.flush().unwrap();
    //port.write(&[0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]).unwrap();
    //port.flush().unwrap();

    let mut bytes = [0; 2048];
    let mut cob_bytes: [u8; 2048] = [0; 2048];
    let mut n = 0;
    std::thread::sleep(std::time::Duration::from_millis(1000));

    loop {
        println!("n {}", n);
        port.read_exact(&mut bytes[n..n + 1]).unwrap();
        if bytes[n] == 0 {
            println!("uh oh {}", n);
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
    println!("recevied {} {:x?}", n, cob_bytes);
    //let data = attest_data::messages::parse_response(&cob_bytes[..n], RotToHost::RotTqSign).unwrap();
    let (_header, _request, data) =
        deserialize::<SpToHost>(&cob_bytes[..n]).unwrap();

    let data =
        attest_data::messages::parse_response(data, RotToHost::RotTqSign)
            .unwrap();
    //println!("{:x?} {:x?} {:x?}", header, request, data);
    //std::fs::write(args.out, &data).unwrap();
    //let (header, request, data) = attest_data::messages::deserialize::<RotToHost>(&data).unwrap();
    //println!("{:x?} {:x?} {:x?}", header, request, data);
    std::fs::write(args.out, data).unwrap();

    println!("done.");
}
