
use std::collections::HashMap;
use std::process::Command;
use std::time::{Duration, SystemTime};

use crate::args::AppArgs;
use crate::bucket::Bucket;
use crate::whitelist::Whitelist;

pub(crate) struct Monitor {
    args: AppArgs,
    buckets: HashMap<String, Bucket>, // HashMap to store Buckets against unique keys (like JA3 hashes).
    _last_check: SystemTime, // Last time the data was checked.
    whitelist: Whitelist, // Whitelist object to filter out allowed items.
    last_cleanup: SystemTime, // Last time the buckets were cleaned up.
    ja3_last_alerts: HashMap<String, SystemTime>, // Tracks the last alert time for each JA3 hash.
    bucket_window: usize, // the window to bucket by, just a conversion of type for the window for speed
}

impl Monitor {
    pub fn new(whitelist: Whitelist, args: AppArgs) -> Self {
        let bucket_window = args.window as usize;
        Monitor {
            args: args,
            buckets: HashMap::new(), // Initialize buckets as an empty HashMap.
            _last_check: SystemTime::now(), // Initialize last check to the current time.
            whitelist, // Initialize the whitelist.
            last_cleanup: SystemTime::now(), // Initialize last cleanup to the current time.
            ja3_last_alerts: HashMap::new(), // Initialize ja3_last_alerts as an empty HashMap.
            bucket_window: bucket_window, // bucket window is conversion
        }
    }

    pub fn process_key(&mut self, ja3: &str, current_ts: SystemTime) {

        if self.should_skip_alert(ja3, current_ts) {
            log::warn!("Suppressing re-alert for ja3: {}", ja3);
            return;
        }

        let should_alert = self.update_or_insert_bucket(ja3, current_ts);

        if should_alert {
            log::info!("Threshold violation, threshold: {} exceeded within {:?} seconds, for ja3: {}", self.args.threshold, self.args.window, ja3);
            self.log_bucket(ja3);
            match self.post_suspect_traffic(ja3) {
                Ok(_) => {
                    self.ja3_last_alerts.insert(ja3.to_owned(), current_ts);
                    log::info!("Block rule posted successfully for ja3 {:?}", ja3);
                }
                Err(e) => log::error!("Failed to post alert for key {:?}: {}", ja3, e),
            }
        }

        self.periodic_cleanup(current_ts);
    }

    fn should_skip_alert(&self, ja3: &str, current_ts: SystemTime) -> bool {
        if let Some(last_alert_ts) = self.ja3_last_alerts.get(ja3) {
            // Calculate the duration since the last alert
            if let Ok(duration_since_last_alert) = current_ts.duration_since(*last_alert_ts) {
                log::debug!("Last alerts for ja3: {}, was at: {:?}, elapsed time since then: {:?}", ja3, last_alert_ts, duration_since_last_alert);

                // Check if the duration since the last alert is less than the window
                duration_since_last_alert.as_secs() < self.args.window
            } else {
                // In case current_ts is before last_alert_ts, which is unlikely but should be handled
                false
            }
        } else {
            false
        }
    }


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

    // Sends a blocking request to the ELB for suspect traffic. This uses curl because tokio is a pain to implement in.
    fn post_suspect_traffic(&self, md5_semi_ja3: &str) -> Result<(), String> {
        if let Some(true) = self.args.elb_fake_mode {
            log::info!("Faking elb post for key: {}", md5_semi_ja3);
            return Ok(());
        }

        let ja3s = md5_semi_ja3; // Extract JA3 hash from the key.
        let rule_payload = format!(r#"{{ "{}": {} }}"#, ja3s, self.args.block_seconds);

        log::info!("Posting block rule payload: {}", rule_payload);

        // Execute a curl command to post the blocking request.
        let output = Command::new("curl")
            .arg("-X")
            .arg("POST")
            .arg("-H")
            .arg("Content-Type: application/json")
            .arg("-d")
            .arg(&rule_payload)
            .arg(&self.args.elb_host)
            .arg("-k")
            .output();

        match output {
            Ok(output) => {
                if !output.status.success() {
                    let status_code = output.status.code().unwrap_or(-1);
                    log::error!("Error posting to NGINX, status: {}, output: {:?}",
                                status_code, String::from_utf8_lossy(&output.stderr));
                    Err("bad stuff".to_string())
                } else {
                    log::info!("Response from NGINX: {:?}", String::from_utf8_lossy(&output.stdout));
                    Ok(())
                }
            }
            Err(e) => {
                log::error!("Error making a POST request: {}", e);
                Err(e.to_string())
            }
        }
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



    pub fn print_top_buckets(&self, top_n: usize) {
        let mut buckets: Vec<_> = self.buckets.iter().collect();
        // Sort buckets by sum_count in descending order
        buckets.sort_by(|a, b| b.1.rolling_window.sum().cmp(&a.1.rolling_window.sum()));

        log::info!("Top {} Buckets by sum_count:", top_n.min(buckets.len()));
        for (key, bucket) in buckets.into_iter().take(top_n) {
            log::info!("Key: {}, sum_count: {}", key, bucket.rolling_window.sum());
            self.log_bucket(&key);
        }
    }

}


#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::args::AppArgs;

    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn test_new() {
        let args = AppArgs::parse();
        let nws = Arc::new(args.parse_whitelist_networks());
        let ja3s = Arc::new(args.parse_whitelist_ja3s());
        let whitelist = Whitelist::new(nws, ja3s);

        let md = Monitor::new(whitelist, args);
        assert_eq!(md.args.threshold, 30000);
        assert_eq!(md.args.window, Duration::from_secs(60).as_secs());
        //... other assertions for initial state
    }

    #[test]
    fn test_process_key_new_key() {

        let args = AppArgs::parse();
        let nws = Arc::new(args.parse_whitelist_networks());
        let ja3s = Arc::new(args.parse_whitelist_ja3s());
        let whitelist = Whitelist::new(nws, ja3s);

        let mut md = Monitor::new(whitelist, args);
        let current_ts = SystemTime::now();
        md.process_key("testkey", current_ts);
        assert!(md.buckets.contains_key("testkey"));
        //... other assertions for the state of 'testkey' bucket
    }

    #[test]
    fn test_process_key_existing_key() {
        let args = AppArgs::parse();
        let nws = Arc::new(args.parse_whitelist_networks());
        let ja3s = Arc::new(args.parse_whitelist_ja3s());
        let whitelist = Whitelist::new(nws, ja3s);

        let mut md = Monitor::new(whitelist, args);
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
        let args = AppArgs::parse();
        let nws = Arc::new(args.parse_whitelist_networks());
        let ja3s = Arc::new(args.parse_whitelist_ja3s());
        let whitelist = Whitelist::new(nws, ja3s);
        let mut md = Monitor::new(whitelist, args);
        let current_ts = SystemTime::now();
        md.process_key("oldkey", current_ts - Duration::from_secs(500));
        md.process_key("newkey", current_ts);
        md.cleanup_old_buckets(current_ts);
        assert!(!md.buckets.contains_key("oldkey"));
        assert!(md.buckets.contains_key("newkey"));
    }

    // Additional tests for other methods and scenarios...
}
