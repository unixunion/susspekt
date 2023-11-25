use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;
use chrono::naive;
use clap::Parser;
use args::AppArgs;
mod whitelist;
use md5::{Digest};
use env_logger::Env;
use ja3::Ja3;
extern crate env_logger;
use log::{info};
use tokio::time::Instant;
use crate::monitor::Monitor;
use crate::whitelist::Whitelist;

mod args;
mod monitor;
mod bucket;
mod rollingwindow;
mod poster;


const BUFFER_SIZE: usize = 65536 * 1;

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

    info!("susspekt-wire-sniffer");

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
    let alerts_args = args.clone();
    tokio::spawn(async move {

        // store alerts sent in a map
        let mut alerts: HashMap<String, SystemTime> = HashMap::new();
        let mut last_alert_gc = Instant::now();

        // read keys from the Sender
        while let Some(key) = alerter_rx.recv().await {

            // check re-alert, start by checking if the key is in the alets already sent
            if let Some(last_alert_ts) = alerts.get(&key) {
                // we found a previously sent alert for this key
                log::warn!("Last alert for key: {}, was at: {:?}", key, last_alert_ts);
                // Get duration since the last alert
                if let Ok(duration_since_last_alert) = SystemTime::now().duration_since(*last_alert_ts) {
                    // Check if the duration since the last alert is less than the window // block time perhaps?
                    if duration_since_last_alert.as_secs() < alerts_args.window {
                        log::warn!("Supressing alert, last alert for key: {}, was at: {:?}, elapsed time since then: {:?}", key, last_alert_ts, duration_since_last_alert);
                    } else {
                        log::warn!("Re-Alerting for {:?}", key);
                        // TODO FIXME make the post!
                        alerts.insert(key, SystemTime::now()); 
                    }
                }
            } else {
                log::warn!("Alerting for {:?}", key);
                // TODO FIXME make the post!
                alerts.insert(key, SystemTime::now());
            }

            // GC, evict alerts that are stale
            if Instant::now().duration_since(last_alert_gc).as_secs() > 2* alerts_args.window {
                log::info!("alerts gc before: {}", alerts.len());
                alerts.retain(|_, v| {
                    match SystemTime::now().duration_since(*v) {
                        Ok(duration) => duration.as_secs() > alerts_args.window * 2,
                        Err(_) => false, // Handle the case where `duration_since` fails
                    }
                });
                log::info!("alerts gc after: {}", alerts.len());
                last_alert_gc = Instant::now();
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


    // start the ja3 processor to feed off the network device
    let mut ja3 = Ja3::new(args.network.unwrap())
        .process_live()
        .unwrap();


    // handle ja3 arriving on the network and pass on
    while let Some(hash) = ja3.next() {
        if hash.is_handshake {
            let ja3_str = format!("{}-{}", digest_to_string(hash.hash), hash.source); // Convert the digest to String
            info!("Source: {}, Destination: {}, JA3: {}, Packet Size: {}, Is Handshake: {}", hash.source, hash.destination, ja3_str, hash.packet_size, hash.is_handshake);
            let _ = monitor_tx.send(ja3_str).await; // pass to the monitoring impl
        }
    }
}


/// turn a digest into a string
fn digest_to_string(digest_option: Option<Digest>) -> String {
    match digest_option {
        Some(digest) => format!("{:x}", digest),
        None => String::from("No Digest"),
    }
}

