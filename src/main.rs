// Copyright 2023 Kegan Holtzhausen
// Licensed under the MIT License (https://opensource.org/licenses/MIT)
// This file may not be copied, modified, or distributed except according to those terms.

use std::sync::Arc;
use std::time::{Duration, SystemTime};
use clap::builder::Str;
use clap::Parser;
use args::AppArgs;
mod whitelist;
use md5::Digest;
use env_logger::Env;
use ja3::{Ja3, Ja3Hash};
extern crate env_logger;
use log::info;
use time::Instant;
use tokio::task::JoinHandle;
use crate::logdata::LogData;
use crate::monitor::Monitor;
use crate::poster::HttpPoster;
use crate::whitelist::Whitelist;

mod args;
mod monitor;
mod bucket;
mod rollingwindow;
mod poster;
mod logdata;

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
        Arc::new(args.parse_whitelist_ja3()),
    );

    // setup the eventing system
    let (monitor_tx, mut monitor_rx) = tokio::sync::mpsc::channel::<String>(BUFFER_SIZE);
    let (alerter_tx, mut alerter_rx) = tokio::sync::mpsc::channel::<String>(BUFFER_SIZE);

    // holder for tasks
    let mut tasks: Vec<JoinHandle<()>> = Vec::new();

    // alerter event listener
    let poster_args = args.clone();
    let poster_task = tokio::spawn(async move {
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
    tasks.push(poster_task);


    // monitoring event listener, passes keys to the monitoring impl
    let monitor_args = args.clone();
    tokio::spawn(async move {
        let mut monitor = Monitor::new(monitor_args.clone() );
        let mut timer = Instant::now();
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
    if args.file.is_some() {
        info!("Switching to file parsing mode");
        let ja3 = Ja3::new(args.file.unwrap())
            .process_pcap()
            .unwrap();
        for packet in ja3 {

            let ja3_str = generate_key(&packet, args.agg_ip);

            let log_data = LogData {
                source: packet.source.to_string(),
                destination: packet.destination.to_string(),
                ja3: ja3_str.clone(),
                packet_size: packet.packet_size,
                is_handshake: packet.is_handshake,
                ethernet_frame_size: packet.ethernet_frame_size,
                is_syn: packet.is_syn,
                is_fin: packet.is_fin,
                is_rst: packet.is_rst,
            };

            if packet.is_fin || packet.is_rst || packet.is_syn || packet.is_handshake{
                let log_json = serde_json::to_string(&log_data).unwrap_or_else(|e| format!("Error serializing log data: {}", e));
                info!("{}", log_json);
                let _ = monitor_tx.send(ja3_str).await; // pass to the monitoring impl
            }
        }
        log::info!("Waiting for threads to finish up...");
        for handle in tasks {
            match handle.await {
                Ok(result) => match result {
                    () => println!("Task completed successfully")
                },
                Err(e) => println!("Task panicked: {:?}", e),
            }
        }
    } else {
        let mut ja3 = Ja3::new(args.interface.unwrap())
            .process_live()
            .unwrap();
        while let Some(packet) = ja3.next() {

            let ja3_str = generate_key(&packet, args.agg_ip);

            let log_data = LogData {
                source: packet.source.to_string(),
                destination: packet.destination.to_string(),
                ja3: ja3_str.clone(),
                packet_size: packet.packet_size,
                is_handshake: packet.is_handshake,
                ethernet_frame_size: packet.ethernet_frame_size,
                is_syn: packet.is_syn,
                is_fin: packet.is_fin,
                is_rst: packet.is_rst,
            };

            if packet.is_fin || packet.is_rst || packet.is_syn || packet.is_handshake{
                let log_json = serde_json::to_string(&log_data).unwrap_or_else(|e| format!("Error serializing log data: {}", e));
                info!("{}", log_json);
                let _ = monitor_tx.send(ja3_str).await; // pass to the monitoring impl
            }
        }
    }

}





/// turn a digest into a string
fn digest_to_string(digest: Digest) -> String {
    format!("{:x}", digest)
}

fn generate_key(packet: &Ja3Hash, agg_ip: bool) -> String {
    let ja3_str = match packet.hash {
        Some(hash) => {
            if agg_ip {
                format!("{:x}-{}", hash, packet.source)
            } else {
                format!("{:x}", hash)
            }
        }
        None => {
            if agg_ip {
                format!("None-{}", packet.source)
            } else {
                format!("None-{}", packet.source)
            }
        }
    };
    return ja3_str;
}
