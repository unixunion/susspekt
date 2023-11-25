use std::sync::Arc;
use std::time::SystemTime;
use clap::Parser;
use args::AppArgs;
mod whitelist;
use md5::{Digest};
use env_logger::Env;
use ja3::Ja3;
extern crate env_logger;
use log::{info};
use crate::monitor::Monitor;
use crate::whitelist::Whitelist;

mod args;
mod monitor;
mod bucket;
mod rollingwindow;


fn main() {

    // simple logger
    env_logger::Builder::from_env(Env::default().default_filter_or("ja3=error,susspekt=info"))
        .format(|buf, record| {
            use std::io::Write;
            let ts = buf.timestamp_micros();
            writeln!(buf, "{}: {} - {}", ts, record.level(), record.args())
        })
        .init();

    let args = AppArgs::parse();

    let whitelist = Whitelist::new(
        Arc::new(args.parse_whitelist_networks()),
        Arc::new(args.parse_whitelist_ja3s()),
    );


    let mut monitor = Monitor::new( whitelist, args.clone() );

    info!("susspekt-wire-sniffer");
    let mut ja3 = Ja3::new(args.network.unwrap())
        .process_live()
        .unwrap();

    while let Some(hash) = ja3.next() {
        if hash.is_handshake {
            let ja3_str = format!("{}-{}", digest_to_string(hash.hash), hash.source); // Convert the digest to String
            info!("Source: {}, Destination: {}, JA3: {}, Packet Size: {}, Is Handshake: {}", hash.source, hash.destination, ja3_str, hash.packet_size, hash.is_handshake);
            monitor.process_key(ja3_str.as_str(), SystemTime::now());
        }
    }
}

fn digest_to_string(digest_option: Option<Digest>) -> String {
    match digest_option {
        Some(digest) => format!("{:x}", digest),
        None => String::from("No Digest"),
    }
}

