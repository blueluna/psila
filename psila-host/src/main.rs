mod parser;
mod security;

use std::fs;
use std::io::{self, Read};
use std::str::FromStr;
use std::time::Duration;

use chrono::{Local, SecondsFormat};
use clap::{App, AppSettings, Arg};

use serialport::prelude::*;

use slice_deque::SliceDeque;

use serde_derive::Deserialize;

use psila_data::common::key::Key;

#[derive(Debug, Deserialize)]
struct Config {
    keys: Vec<String>,
}

fn read_config(file_path: &str) -> Option<Config> {
    match fs::read(file_path) {
        Ok(bytes) => match toml::from_str::<Config>(&String::from_utf8_lossy(bytes.as_slice())) {
            Ok(config) => Some(config),
            Err(_) => None,
        },
        Err(_) => None,
    }
}

fn main() {
    env_logger::init();
    let matches = App::new("nRF52840 802.15.4 host companion")
        .about("Write stuff")
        .setting(AppSettings::DisableVersion)
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .help("Path to configuration file")
                .use_delimiter(false)
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("port")
                .help("The device path to a serial port")
                .use_delimiter(false)
                .required(true),
        )
        .get_matches();

    let port_name = matches.value_of("port").unwrap();
    let mut settings: SerialPortSettings = Default::default();
    settings.baud_rate = 115_200;
    settings.timeout = Duration::from_millis(1000);

    let mut parser = parser::Parser::new();

    if let Some(file_path) = matches.value_of("config") {
        if let Some(config) = read_config(file_path) {
            for (n, key) in config.keys.iter().enumerate() {
                let name = format!("User {}", n);
                if let Ok(k) = Key::from_str(&key) {
                    parser.security.add_key(k.into(), &name)
                }
            }
        }
    }

    let mut buffer: SliceDeque<u8> = SliceDeque::with_capacity(256);
    let mut work = [0u8; 2048];
    let mut data = [0u8; 256];
    let mut pkt_data = [0u8; 256];

    match serialport::open_with_settings(&port_name, &settings) {
        Ok(mut port) => {
            println!("Read packets over {}", &port_name);
            loop {
                match port.read(&mut data) {
                    Ok(rx_count) => {
                        // println!("Received {}", rx_count);
                        buffer.extend_from_slice(&data[..rx_count]);
                        loop {
                            match esercom::com_decode_ex(buffer.as_slice(), &mut data, &mut work) {
                                Ok((msg, used, written)) => {
                                    if written == 0 {
                                        break;
                                    }
                                    print!(
                                        "{} ",
                                        Local::now().to_rfc3339_opts(SecondsFormat::Millis, true)
                                    );
                                    match msg {
                                        esercom::MessageType::RadioReceive => {
                                            let pkt_len = written;
                                            let link_quality_indicator = data[pkt_len - 1];
                                            let pkt_len = pkt_len - 1; // Remove LQI
                                            pkt_data[..pkt_len].copy_from_slice(&data[..pkt_len]);
                                            println!(
                                                "Packet {} LQI {} -------------------------------",
                                                pkt_len, link_quality_indicator
                                            );
                                            for b in &pkt_data[..pkt_len] {
                                                print!("{:02x}", b);
                                            }
                                            println!();
                                            parser.parse_packet(&pkt_data[..pkt_len]);
                                        }
                                        esercom::MessageType::EnergyDetect => {
                                            if written == 2 {
                                                let channel = data[0];
                                                let energy_level = data[1];
                                                println!(
                                                    "Energy on channel {}: {} -------------------------------",
                                                    channel, energy_level
                                                );
                                            }
                                        }
                                        esercom::MessageType::RadioState => {
                                            if written == 5 {
                                                let state = data[0];
                                                let events = u32::from(data[1])
                                                    | u32::from(data[2]) << 8
                                                    | u32::from(data[3]) << 16
                                                    | u32::from(data[4]) << 24;
                                                println!(
                                                    "++++++++++++++++ Radio State {} {:032b} ++++++++++++++++",
                                                    state, events
                                                );
                                            }
                                        }
                                        _ => println!(
                                            "Other packet {:?} -------------------------------",
                                            msg
                                        ),
                                    }
                                    let front = buffer.len() - used;
                                    // println!("Drop {} bytes {} left", used, front);
                                    buffer.truncate_front(front);
                                }
                                Err(ref e) => {
                                    match *e {
                                        esercom::error::Error::EndNotFound => (),
                                        esercom::error::Error::InvalidLength(l) => {
                                            buffer.truncate_front(buffer.len() - l);
                                        }
                                        esercom::error::Error::NotEnoughBytes => {
                                            println!("Bad {:?} {}", e, buffer.len());
                                        }
                                        _ => {
                                            println!("Bad {:?}", e);
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::TimedOut => (),
                    Err(e) => eprintln!("{:?}", e),
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to open \"{}\". Error: {}", port_name, e);
            ::std::process::exit(1);
        }
    }
}
