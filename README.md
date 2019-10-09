# Psila

> Psila is a European genus of flies member of the family Psilidae or Rust
> Flies.

This is a work in progress implementation of handing Z**bee packages.

## Goal

The goal is to be able to use a Nordic nRF52840 SoC as a device endpoint.
Handling the on/off profile in home automation.

## Organisation

The implementation has been divided into a few separate crates.

### Psila-data

Implements packing and unpacking of packets.

### Psila-crypto

Defines traits for cryptographical backend for use with Psila.

### Psila-crypto-gcrypt

A implementation of the psila-cryto using gcrypo.

### Psila-service

A implementation of a service that handles and produce packages.

### Host-Tool

A tool which listens on specialy encoded packets over serial port and decodes
these packets.

## License

Licensed under the MIT license.
