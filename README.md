# ipcc-data

This is a crate to allow for the interpretation of SP-opaque data payloads
over the inter-processor communications channel (IPCC).  (See [RFD 316]
for details of this channel and its mechanics.) Because this crate is
designed *only* for those payloads that are opaque to the SP (e.g.,
`HSSBootFail`, `HSSPanic`), it is not a `no-std` crate:  it is not
designed to be used *in situ* by the SP, but rather in higher level
software that must interpret IPCC data payloads -- which is to say, the
control plane and [Humility].  For the host-side definitions of the IPCC
payloads that this crate interprets, see [`kernel_ipcc.h`].

[RFD 316]: https://rfd.shared.oxide.computer/rfd/0316
[Humility]: https://github.com/oxidecomputer/humility
[`kernel_ipcc.h`]: https://github.com/oxidecomputer/illumos-gate/blob/stlouis/usr/src/uts/oxide/sys/kernel_ipcc.h

