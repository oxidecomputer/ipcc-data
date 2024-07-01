# ipcc-data

This is a crate to allow for the interpretation of data payloads over
the inter-processor communications channel (IPCC).  (See RFD 316 for details
of this channel and its mechanics.)  This crate is not a `no-std` crate, as
it is not designed to be used by the SP, but rather in higher level software
that must interpret IPCC data payloads.

