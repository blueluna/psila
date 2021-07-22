# Psila

> Psila is a European genus of flies member of the family Psilidae or Rust
> Flies.

This is a work in progress implementation of handing Z**bee packages.

**This project has not undergone any cerification or extensive testing,
it is simply a hobby project**

## Goal

The goal is to be able to use a Nordic nRF52840 SoC as a device endpoint.
Handling the on/off profile in home automation.

## Organisation

The implementation has been divided into a few separate crates.

### psila-data

Implements packing and unpacking of packets.

### psila-crypto

Defines traits for cryptographical backend for use with Psila.

### psila-crypto-rust-crypto

A implementation of the psila-cryto using Rust Crypto crates.

(RustCrypto)[https://github.com/RustCrypto].

### psila-service

A implementation of a service that handles and produce packages.

### psila-Host

A tool which listens on specially encoded packets over serial port and decodes
these packets.

## License

Licensed under the MIT license.
