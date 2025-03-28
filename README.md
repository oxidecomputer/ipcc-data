# Rust tools for working with IPCC

In Oxide servers, the host CPU communicates with its colocated service processor
(SP) over a UART interface.  This is the inter-processor communication channel,
or "IPCC".

The format for IPCC messages is laid out in
[RFD 316](https://rfd.shared.oxide.computer/rfd/0316).

- [`ipcc-data`](ipcc-data): Interpreting data payloads which are opaque to the SP
- [`libipcc`](libipcc): Calling into the host OS's IPCC library
- [`faux-ipcc`](faux-ipcc): A CLI tool for working with IPCC on a desktop
