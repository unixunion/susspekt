use std::sync::Arc;
use std::net::Ipv4Addr;
use ipnetwork::Ipv4Network;

/**
 * This is the whitelist implementations, although the ELB is already hosting a ton of whitelists, these whitelists are for the ddos_corroder
 * itself, to save processing on excluded IP's and JA3's.
 */

#[derive(Clone)]
pub struct Whitelist {
    pub networks: Arc<Vec<Ipv4Network>>,
    pub ja3s: Arc<Vec<String>>,
    ja3s_enabled: bool,
}

impl Whitelist {
    // Constructor
    pub fn new(networks: Arc<Vec<Ipv4Network>>, ja3s: Arc<Vec<String>>) -> Self {
        let ja3s_enabled = !ja3s.is_empty(); // true if ja3s length is non-zero

        Whitelist {
            networks,
            ja3s,
            ja3s_enabled
        }
    }

    // Check if an IP is whitelisted
    pub fn is_ip_whitelisted(&self, ip: &str) -> bool {
        let ip_addr = match ip.parse::<Ipv4Addr>() {
            Ok(addr) => addr,
            Err(_) => return false,
        };

        self.networks.iter().any(|network| network.contains(ip_addr))
    }

    // Check if a JA3 is whitelisted
    pub fn is_ja3_whitelisted(&self, ja3: &str) -> bool {
        if ! self.ja3s_enabled {
            return false;
        }
        self.ja3s.contains(&ja3.to_string())
    }
}
