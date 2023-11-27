// Copyright 2023 Kegan Holtzhausen
// Licensed under the MIT License (https://opensource.org/licenses/MIT)
// This file may not be copied, modified, or distributed except according to those terms.

use std::collections::HashMap;
use std::time::SystemTime;
use time::{Duration, Instant};

use crate::args::AppArgs;
use crate::bucket::Bucket;

pub(crate) struct Monitor {
    args: AppArgs,
    buckets: HashMap<String, Bucket>, // HashMap to store Buckets against unique keys (like JA3 hashes).
    _last_check: SystemTime, // Last time the data was checked.
    last_cleanup: SystemTime, // Last time the buckets were cleaned up.
    ja3_last_alerts: HashMap<String, SystemTime>, // Tracks the last alert time for each JA3 hash.
    bucket_window: usize, // the window to bucket by, just a conversion of type for the window for speed
    counter: u64,
    last_counter_reset: Instant,
    whitelisted_ja3: Vec<String>,
}

impl Monitor {
    pub fn new(args: AppArgs) -> Self {
        let bucket_window = args.window as usize;
        Monitor {
            args: args.clone(),
            buckets: HashMap::new(), // Initialize buckets as an empty HashMap.
            _last_check: SystemTime::now(), // Initialize last check to the current time.
            last_cleanup: SystemTime::now(), // Initialize last cleanup to the current time.
            ja3_last_alerts: HashMap::new(), // Initialize ja3_last_alerts as an empty HashMap.
            bucket_window: bucket_window, // bucket window is conversion
            counter: 0,
            last_counter_reset: Instant::now(),
            whitelisted_ja3: args.clone().parse_whitelist_ja3(),
        }
    }

    // process a key, and return if its in violation or not
    pub fn process_key(&mut self, ja3: &str, current_ts: SystemTime) -> bool {

        if self.whitelisted_ja3.contains(&ja3.split("-").next().unwrap_or("None").to_string()) {
            log::debug!("{} is in whitelisted ja3", ja3);
            return false
        }

        self.counter+=1;
        // self.print_stats();

        log::debug!("{} processing key: {}", self.counter, ja3);

        let should_alert = self.update_or_insert_bucket(ja3, current_ts);
    
        if should_alert {
            log::info!("Threshold violation, threshold: {} exceeded within {:?} seconds, for ja3: {}", self.args.threshold, self.args.window, ja3);
            self.log_bucket(ja3);
        } else {
            self.periodic_cleanup(current_ts);
        }

        should_alert
    }

    // fn should_skip_alert(&self, ja3: &str, current_ts: SystemTime) -> bool {
    //     if let Some(last_alert_ts) = self.ja3_last_alerts.get(ja3) {
    //         // Calculate the duration since the last alert
    //         if let Ok(duration_since_last_alert) = current_ts.duration_since(*last_alert_ts) {
    //             log::debug!("Last alerts for ja3: {}, was at: {:?}, elapsed time since then: {:?}", ja3, last_alert_ts, duration_since_last_alert);

    //             // Check if the duration since the last alert is less than the window
    //             duration_since_last_alert.as_secs() < self.args.window
    //         } else {
    //             // In case current_ts is before last_alert_ts, which is unlikely but should be handled
    //             false
    //         }
    //     } else {
    //         false
    //     }
    // }


    fn update_or_insert_bucket(&mut self, key: &str, current_ts: SystemTime) -> bool {
        let bucket = self.buckets
            .entry(key.to_string())
            .or_insert_with(|| {
                let new_bucket = Bucket::new(key.to_string(), current_ts, self.bucket_window);
                if let Some(true) = self.args.log_create_buckets {
                    log::info!("Registering a new composite-key: {} as a bucket", key);
                }
                new_bucket
            });

        // increment the bucket for the timestamp ( which is now )
        log::debug!("Troubleshooting window for key: {}", key);
        bucket.update(current_ts);

        // check if we tripped the threshold
        bucket.check_threshold(self.args.threshold) &&
            (bucket.last_alert_ts.is_none() ||
                bucket.last_alert_ts.unwrap().elapsed().as_secs() > self.args.window)

    }

    // cleanup buckets that are quiet every 2x window time
    fn periodic_cleanup(&mut self, current_ts: SystemTime) {

        if let Ok(duration_since_last_cleanup) = current_ts.duration_since(self.last_cleanup) {

            if duration_since_last_cleanup.as_secs() >= self.args.window * 2 {
                let bucket_count_before = self.buckets.len();
                self.cleanup_old_buckets(current_ts);
                self.last_cleanup = SystemTime::now();
                log::info!("Discarded idle buckets, count before: {}, count after: {}", bucket_count_before, self.buckets.len());
            }

        }

    }

    // Cleanup function to remove old buckets.
    fn cleanup_old_buckets(&mut self, current_ts: SystemTime) {
        let expiration_duration = self.args.window * 2;

        self.buckets.retain(|_, bucket| {
            // Check if the bucket's last timestamp is within the expiration duration
            if let Ok(elapsed) = current_ts.duration_since(bucket.last_ts) {
                elapsed.as_secs() <= expiration_duration
            } else {
                // In case current_ts is before bucket.last_ts, retain this bucket
                // This scenario is unlikely but should be handled
                true
            }
        });

        self.log_current_state();
    }


    // Logs the current state of the buckets. this is for local dev, and the iterator need to be left commented out for performance!
    pub fn log_current_state(&self) {
        log::info!("Bucket count: {}", self.buckets.len());
        for (key, bucket) in self.buckets.iter() {
            if self.ja3_last_alerts.contains_key(key.split('-').next().unwrap_or_default())  {
                log::info!("JA3: {}, Last Timestamp: {:?}, Rolling Count: {:?}, Total Count: {}",
                    key, bucket.last_ts, bucket.rolling_window.window, bucket.sum_count);
            }
        }
        // log::debug!("End of dump");
    }

    pub fn log_bucket(&self, key: &str) {
        match self.buckets.get(key) {
            Some(bucket) => {
                let rolling_values: Vec<u32> = bucket
                    .rolling_window
                    .window
                    .iter()
                    .map(|(_, count)| *count)
                    .collect();
                let total_count = bucket.rolling_window.sum();

                log::info!(
                    "Bucket key: {}, Last Timestamp: {:?}, Rolling Values: {:?}, Total Count: {}",
                    key,
                    bucket.last_ts,
                    rolling_values,
                    total_count
                );
            }
            None => log::error!("Error accessing bucket?")
        }
    }



    pub fn _print_top_buckets(&self, top_n: usize) {
        let mut buckets: Vec<_> = self.buckets.iter().collect();
        // Sort buckets by sum_count in descending order
        buckets.sort_by(|a, b| b.1.rolling_window.sum().cmp(&a.1.rolling_window.sum()));

        log::info!("Top {} Buckets by sum_count:", top_n.min(buckets.len()));
        for (key, bucket) in buckets.into_iter().take(top_n) {
            log::info!("Key: {}, sum_count: {}", key, bucket.rolling_window.sum());
            self.log_bucket(&key);
        }
    }

    pub fn print_stats(&mut self) {
        if self.last_counter_reset.elapsed() >= Duration::new(1, 0) {
            log::info!("Key rate: {}", self.counter);
            self.counter = 0;
            self.last_counter_reset = Instant::now();
        }
    }
}


#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::args::AppArgs;
    use crate::whitelist::Whitelist;

    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn test_new() {
        let args = AppArgs {
            interface: Some("Foo".to_string()),           // Assuming "Foo" is a mock network device name
            file: None,                            // No pcap file for testing
            threshold: 1000,                            // Example threshold value
            window: 60,                                  // Example window value in seconds
            alert_url: "Foo".to_string(),                // Mock ELB host
            dry_run: true,                 // Enable fake mode for testing
            block_seconds: 86400,                       // Example block duration in seconds
            whitelist_networks: "10.0.0.0/8, 192.168.0.0/16".to_string(), // Example whitelisted networks
            whitelist_ja3s: "None".to_string(),                       // No whitelisted JA3 hashes for testing
            log_create_buckets: Some(false),            // Disable logging for bucket creation in test
            agg_ip: true                                // include IP in the key
        };

        let nws = Arc::new(args.parse_whitelist_networks());
        let ja3s = Arc::new(args.parse_whitelist_ja3());
        let whitelist = Whitelist::new(nws, ja3s);

        let md = Monitor::new(args);
        assert_eq!(md.args.threshold, 1000);
        assert_eq!(md.args.window, Duration::from_secs(60).as_secs());
        //... other assertions for initial state
    }

    #[test]
    fn test_process_key_new_key() {

        let args = AppArgs {
            interface: Some("Foo".to_string()),           // Assuming "Foo" is a mock network device name
            file: None,                            // No pcap file for testing
            threshold: 1000,                            // Example threshold value
            window: 60,                                  // Example window value in seconds
            alert_url: "Foo".to_string(),                // Mock ELB host
            dry_run: true,                 // Enable fake mode for testing
            block_seconds: 86400,                       // Example block duration in seconds
            whitelist_networks: "10.0.0.0/8, 192.168.0.0/16".to_string(), // Example whitelisted networks
            whitelist_ja3s: "None".to_string(),                       // No whitelisted JA3 hashes for testing
            log_create_buckets: Some(false),            // Disable logging for bucket creation in test
            agg_ip: true                                // include IP in the key
        };

        let nws = Arc::new(args.parse_whitelist_networks());
        let ja3s = Arc::new(args.parse_whitelist_ja3());
        let whitelist = Whitelist::new(nws, ja3s);

        let mut md = Monitor::new(args);
        let current_ts = SystemTime::now();
        md.process_key("testkey", current_ts);
        assert!(md.buckets.contains_key("testkey"));
        //... other assertions for the state of 'testkey' bucket
    }

    #[test]
    fn test_process_key_existing_key() {
        let args = AppArgs {
            interface: Some("Foo".to_string()),           // Assuming "Foo" is a mock network device name
            file: None,                            // No pcap file for testing
            threshold: 1000,                            // Example threshold value
            window: 60,                                  // Example window value in seconds
            alert_url: "Foo".to_string(),                // Mock ELB host
            dry_run: true,                 // Enable fake mode for testing
            block_seconds: 86400,                       // Example block duration in seconds
            whitelist_networks: "10.0.0.0/8, 192.168.0.0/16".to_string(), // Example whitelisted networks
            whitelist_ja3s: "None".to_string(),                       // No whitelisted JA3 hashes for testing
            log_create_buckets: Some(false),            // Disable logging for bucket creation in test
            agg_ip: true                                // include IP in the key
        };
        let nws = Arc::new(args.parse_whitelist_networks());
        let ja3s = Arc::new(args.parse_whitelist_ja3());
        let whitelist = Whitelist::new(nws, ja3s);

        let mut md = Monitor::new(args);
        let current_ts = SystemTime::now();
        md.process_key("testkey", current_ts);
        // simulate some time passage
        let new_ts = current_ts + Duration::from_secs(30);
        md.process_key("testkey", new_ts);
        //... assertions for updated state of 'testkey' bucket
        match md.buckets.get("testkey") {
            Some(value) => {
                println!("Value for key '{:?}'", value.last_ts);
                assert!(value.last_ts == new_ts);
            },
            None => println!("No value found for key"),
        }
    }



    #[test]
    fn test_cleanup_old_buckets() {
        let args = AppArgs {
            interface: Some("Foo".to_string()),           // Assuming "Foo" is a mock network device name
            file: None,                            // No pcap file for testing
            threshold: 1000,                            // Example threshold value
            window: 60,                                  // Example window value in seconds
            alert_url: "Foo".to_string(),                // Mock ELB host
            dry_run: true,                 // Enable fake mode for testing
            block_seconds: 86400,                       // Example block duration in seconds
            whitelist_networks: "10.0.0.0/8, 192.168.0.0/16".to_string(), // Example whitelisted networks
            whitelist_ja3s: "None".to_string(),                       // No whitelisted JA3 hashes for testing
            log_create_buckets: Some(false),            // Disable logging for bucket creation in test
            agg_ip: true                                // include IP in the key
        };
        let nws = Arc::new(args.parse_whitelist_networks());
        let ja3s = Arc::new(args.parse_whitelist_ja3());
        let whitelist = Whitelist::new(nws, ja3s);
        let mut md = Monitor::new(args);
        let current_ts = SystemTime::now();
        md.process_key("oldkey", current_ts - Duration::from_secs(500));
        md.process_key("newkey", current_ts);
        md.cleanup_old_buckets(current_ts);
        assert!(!md.buckets.contains_key("oldkey"));
        assert!(md.buckets.contains_key("newkey"));
    }

    // Additional tests for other methods and scenarios...
}
