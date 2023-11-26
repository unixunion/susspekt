// Copyright 2023 Kegan Holtzhausen
// Licensed under the MIT License (https://opensource.org/licenses/MIT)
// This file may not be copied, modified, or distributed except according to those terms.

use clap::Parser;
use ipnetwork::Ipv4Network;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
#[group(id = "input", required = true)]
pub struct AppArgs {
    #[arg(short, long, group = "input", help = "Network device to sniff, e.g: eth0")]
    pub interface: Option<String>,

    // log file pattern
    #[arg(short, long, group = "input", help = "The pcap file to analyse for testing. NOTE: timing windows dont work with files")]
    pub file: Option<String>,

    /// Threshold for triggering an alert
    #[arg(short, long, default_value_t = 1000, help = "Threshold number of occurrences of a ja3-remote_addr-uri in the window")]
    pub threshold: u16,

    /// Time window for the threshold (in seconds)
    #[arg(short, long, default_value_t = 60, help = "Time window in seconds for calculating the threshold")]
    pub window: u64,

    // /// Number of threads for processing
    // #[arg(short, long, default_value_t = 2, help = "The number of threads to use for parallel processing")]
    // pub concurrency: usize,

    /// alert host for posting the violations to
    #[arg(short, long, default_value = "http://localhost:8080/api/block/update", help = "The endpoint for updating the block list")]
    pub alert_url: String,

    #[arg(short, long, default_value_t=false, help = "DryRun disables posting the alerts to the --alert-url")]
    pub dry_run: bool,

    /// Duration for blocking suspicious traffic (in seconds)
    #[arg(short, long, default_value_t = 86400, help = "Alert duration field value in seconds for how long to block suspicious traffic")]
    pub block_seconds: u32,

    /// Flag to parse the entire file from the beginning
    // #[arg(short, long, help = "If set, the entire log file will be parsed from the beginning before tailing")]
    // pub parse_entire_file: bool,

    /// Whitelist of network addresses in CIDR notation
    #[arg(long, default_value = "10.0.0.0/8, 192.168.0.0/16", help = "Comma-separated list of whitelisted networks in CIDR notation")]
    pub whitelist_networks: String,

    /// Whitelist of JA3 hashes
    #[arg(long, default_value = "None", help = "Optional comma-separated list of whitelisted md5_semi_ja3")]
    pub whitelist_ja3s: String,

    /// Log creation of new buckets
    #[arg(long, help = "enable logging for new buckets")]
    pub log_create_buckets: Option<bool>,


}


// implementation for parsing the weirder command line args
impl AppArgs {

    pub fn parse_whitelist_networks(&self) -> Vec<Ipv4Network> {
        self.whitelist_networks.split(',')
            .filter_map(|s| s.trim().parse::<Ipv4Network>().ok())
            .collect()
    }


    pub fn parse_whitelist_ja3(&self) -> Vec<String> {
        if self.whitelist_ja3s.is_empty() {
            log::debug!("No whitelist ja3s provided");
            Vec::new()
        } else {
            self.whitelist_ja3s.split(',')
                .map(|s| s.trim().to_string())
                .collect()
        }
    }


}