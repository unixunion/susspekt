use clap::Parser;
use ipnetwork::Ipv4Network;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct AppArgs {
    #[arg(long, default_value="eth0", help = "network device for pcap listening, e.g: eth0")]
    pub network: Option<String>,

    // log file pattern
    #[arg(short, long, default_value="idontexist.pcap", help = "pcap dump for testing")]
    pub pack_file: String,

    /// Threshold for triggering an alert
    #[arg(short, long, default_value_t = 1000, help = "Threshold number of occurrences of a ja3-remote_addr-uri in the window")]
    pub threshold: u16,

    /// Time window for the threshold (in seconds)
    #[arg(short, long, default_value_t = 30, help = "Time window in seconds for calculating the threshold")]
    pub window: u64,

    // /// Number of threads for processing
    // #[arg(short, long, default_value_t = 2, help = "The number of threads to use for parallel processing")]
    // pub concurrency: usize,

    /// ELB host for updating block list
    #[arg(short, long, default_value = "https://localhost:8443/api/block/update", help = "The endpoint for updating the block list")]
    pub elb_host: String,

    #[arg(long, help = "Pretend the ELB accepted the payload")]
    pub elb_fake_mode: Option<bool>,

    /// Duration for blocking suspicious traffic (in seconds)
    #[arg(short, long, default_value_t = 86400, help = "Duration in seconds for how long to block suspicious traffic")]
    pub block_seconds: u32,

    /// Flag to parse the entire file from the beginning
    // #[arg(short, long, help = "If set, the entire log file will be parsed from the beginning before tailing")]
    // pub parse_entire_file: bool,

    /// Whitelist of network addresses in CIDR notation
    #[arg(long, default_value = "10.0.0.0/8, 192.168.0.0/16", help = "Comma-separated list of whitelisted networks in CIDR notation")]
    pub whitelist_networks: String,

    /// Whitelist of JA3 hashes
    #[arg(long, help = "Optional comma-separated list of whitelisted md5_semi_ja3")]
    pub whitelist_ja3s: Option<String>,

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


    pub fn parse_whitelist_ja3s(&self) -> Vec<String> {
        match &self.whitelist_ja3s {
            Some(x) => {
                x.split(',')
                    .filter_map(|s| s.trim().parse::<String>().ok())
                    .collect()
            },
            None => {
                log::debug!("No whitelist ja3s provided");
                Vec::new()
            },
        }
    }

}