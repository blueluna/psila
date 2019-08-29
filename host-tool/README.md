# Host tool

This tool listen on a serial port for data sent from the nRF52840-DK board.

## Usage

Make sure you have permission to use the serial port. Then figure out which
device that represents the nRF52840-DK.

Run the client (in this case with the `/dev/ttyACM0` device)

```
$ cargo run -- /dev/ttyACM0
```
