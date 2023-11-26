// Copyright 2023 Kegan Holtzhausen
// Licensed under the MIT License (https://opensource.org/licenses/MIT)
// This file may not be copied, modified, or distributed except according to those terms.

use std::sync::Arc;
use std::net::Ipv4Addr;
use ipnetwork::Ipv4Network;

/**
 * This is the whitelist implementations
 */

#[derive(Clone)]
pub struct Whitelist {
    pub networks: Arc<Vec<Ipv4Network>>,
    pub ja3s: Arc<Vec<String>>,
}

impl Whitelist {
    // Constructor
    pub fn new(networks: Arc<Vec<Ipv4Network>>, ja3s: Arc<Vec<String>>) -> Self {
        Whitelist {
            networks,
            ja3s,
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
        if self.ja3s.len()==0 {
            return false;
        }
        self.ja3s.contains(&ja3.to_string())
    }
}
