# ipcc-data

This is a crate to allow for the interpretation of data payloads over the
inter-processor communications channel (IPCC) that are opaque to the SP.  (See
<a href="https://rfd.shared.oxide.computer/rfd/0316">RFD 316</a> for details of
this channel and its mechanics.)  Note that because this crate is designed only
for those payloads that are opaque to the SP (e.g., HSSBootFail, HSSPanic), it
is not a `no-std` crate:  it is designed to be used not by the SP, but rather
in higher level software that must interpret IPCC data payloads (e.g., the
control plane and Humility).

