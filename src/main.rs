use std::sync::Arc;
use std::time::SystemTime;
use clap::Parser;
use args::AppArgs;
mod whitelist;
use md5::Digest;
use env_logger::Env;
use ja3::Ja3;
extern crate env_logger;
use log::info;
use crate::monitor::Monitor;
use crate::poster::HttpPoster;
use crate::whitelist::Whitelist;

mod args;
mod monitor;
mod bucket;
mod rollingwindow;
mod poster;

const BUFFER_SIZE: usize = 65536 * 1;

#[cfg(not(test))]
#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {

    // simple logger, log4-rs might be better
    env_logger::Builder::from_env(Env::default().default_filter_or("ja3=error,susspekt=info"))
        .format(|buf, record| {
            use std::io::Write;
            let ts = buf.timestamp_micros();
            writeln!(buf, "{}: {} - {}", ts, record.level(), record.args())
        })
        .init();

    let logo = r#"
                               _    _
                              | |  | |
  ___ _   _ ___ ___ _ __   ___| | _| |_
 / __| | | / __/ __| '_ \ / _ \ |/ / __|
 \__ \ |_| \__ \__ \ |_) |  __/   <| |_
 |___/\__,_|___/___/ .__/ \___|_|\_\\__|
                   | |
                   |_|

"#;

    info!("{}", logo);

    // argparse
    let args = AppArgs::parse();

    // whitelist, to be used for ignoring processing, or ignoring alerting.
    let whitelist = Whitelist::new(
        Arc::new(args.parse_whitelist_networks()),
        Arc::new(args.parse_whitelist_ja3s()),
    );

    // setup the eventing system
    let (monitor_tx, mut monitor_rx) = tokio::sync::mpsc::channel::<String>(BUFFER_SIZE);
    let (alerter_tx, mut alerter_rx) = tokio::sync::mpsc::channel::<String>(BUFFER_SIZE);

    // alerter event listener
    let poster_args = args.clone();
    tokio::spawn(async move {

        // alerter
        let mut poster = HttpPoster::new(poster_args);

        // read keys from the Sender
        while let Some(key) = alerter_rx.recv().await {
            match poster.alert(key).await {
                Ok(_) => {},
                Err(e) => log::error!("Error posting: {}", e)
            }
        }
    });


    // monitoring event listener, passes keys to the monitoring impl
    let monitor_args = args.clone();
    tokio::spawn(async move {
        let mut monitor = Monitor::new(monitor_args.clone() );
        // continuously read keys from the Sender
        while let Some(key) = monitor_rx.recv().await {
            log::debug!("process key: {:?}", key);
            if monitor.process_key(&key, SystemTime::now()) {
                if let Err(e) = alerter_tx.send(key).await {
                    log::error!("Failed to send alert: {}", e);
                }
            }
        }
    });

    // file parser
    if args.pcap_file.is_some() {
        info!("Switching to file parsing mode");
        let ja3 = Ja3::new(args.pcap_file.unwrap())
            .process_pcap()
            .unwrap();
        for hash in ja3 {
            if hash.is_handshake {
                let ja3_str = format!("{}-{}", digest_to_string(hash.hash), hash.source); // Convert the digest to String
                info!("Source: {}, Destination: {}, JA3: {}, Packet Size: {}, Is Handshake: {}", hash.source, hash.destination, ja3_str, hash.packet_size, hash.is_handshake);
                let _ = monitor_tx.send(ja3_str).await; // pass to the monitoring impl
            }
        }
    } else {
        let mut ja3 = Ja3::new(args.interface.unwrap())
            .process_live()
            .unwrap();
        while let Some(hash) = ja3.next() {
            if hash.is_handshake {
                let ja3_str = format!("{}-{}", digest_to_string(hash.hash), hash.source); // Convert the digest to String
                info!("Source: {}, Destination: {}, JA3: {}, Packet Size: {}, Is Handshake: {}", hash.source, hash.destination, ja3_str, hash.packet_size, hash.is_handshake);
                let _ = monitor_tx.send(ja3_str).await; // pass to the monitoring impl
            }
        }
    }

}





/// turn a digest into a string
fn digest_to_string(digest: Digest) -> String {
    format!("{:x}", digest)
}

