# Quic-Sea

A project aiming to provide an rfc-compliant implementation of the
QUIC protocol, with the goal of providing a similar interface to `std::net::TcpStream`,
that must be constructed from an already bound socket.

## Disclaimer

This project is intended to be a "working" implementation of the QUIC protocol.
As such it is not compliant with RFC 9000 and 9001, instead it is a subset of this,
with not all behaviour implemented. As such it is not viable for production.

## Notes

This library makes use of the standard library motivated by required access to an
os-independent interface to a udp socket, however, in addition to this, the standard
library threadsafe primitives have proven incredibly helpful.

This library uses openssl for the implementations of its cryptographic algorithms,
it is planned to make openssl an opt-in feature and make the implementations for
these cryptographic algorithms to be generic as per a trait defined by the
combination of traits in rust-crypto, however, this is not in the current state

Connection ids issued by this implementation of QUIC are fixed to size u64

## Current state

[x] frame deserialization
[x] header deserialization
[x] packet deserialization
[x] packet routing
[x] `TLS_AES_128_GCM_SHA256` cipher suite support
[] packet serialization
[] packet number spaces
[] packet number reconstruction
[] initial handshake
[] stream opening
[] stream closing
[] connection migration
[] async support

## Major TODOs

- implement failure crate

