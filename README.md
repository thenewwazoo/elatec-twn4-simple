
`elatec-twn4-simple`
====================

This is an implementation of the Simple Protocol for the [Elatec TWN4](https://www.elatec-rfid.com/en/products/rfid-readerwriter-with-antenna/multi-frequency/twn4-multitech/) family of devices, based on [embedded-hal](https://github.com/japaric/embedded-hal).

It is an incomplete implementation, and contains only what the author has needed. Contributions are welcomed!

Example
-------

Because `elatec-twn4-simple` uses `embedded-hal`, we can use `serial-embedded-hal` to test functionality on a desktop computer the same way we would on an embedded device.

```rust
extern crate elatec_multitec_nano_simple as reader;
extern crate embedded_hal;
extern crate serial_embedded_hal as serial;

use std::time::Duration;

fn main() {
    env_logger::init();

    let settings = serial::PortSettings {
        baud_rate: serial::BaudRate::Baud9600,
        char_size: serial::CharSize::Bits8,
        parity: serial::Parity::ParityNone,
        stop_bits: serial::StopBits::Stop1,
        flow_control: serial::FlowControl::FlowNone,
    };
    let (tx, rx) = serial::Serial::new("/dev/tty.usbmodem142331", &settings).unwrap().split();

    let mut reader = reader::new(rx, tx);

    let mut ver_buf = [0u8; 0xFF];

    let v_len = reader.get_version_string(&mut ver_buf).unwrap();

    println!(
        "ver: {} \"{}\"",
        v_len,
        std::str::from_utf8(&ver_buf[..v_len as usize]).unwrap()
    );
}
```
