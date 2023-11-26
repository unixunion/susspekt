// Copyright 2023 Kegan Holtzhausen
// Licensed under the MIT License (https://opensource.org/licenses/MIT)
// This file may not be copied, modified, or distributed except according to those terms.

use std::{collections::HashMap, time::SystemTime};

use reqwest::Error;
use tokio::time::Instant;
use serde::Serialize;

use crate::args::AppArgs;


#[derive(Serialize)]
struct AlertPayload {
    key: String,
    block_time: i32,
    realert: &'static str,
}

// Define the struct
pub struct HttpPoster {
    client: reqwest::Client,
    alerts: HashMap<String, SystemTime>,
    args: AppArgs,
    last_gc: Instant,
}

impl HttpPoster {
    // Constructor for the struct
    pub fn new(args: AppArgs) -> Self {
        HttpPoster {
            client: reqwest::Client::new(),
            alerts: HashMap::new(),
            args,
            last_gc: Instant::now(),
        }
    }

    // Async method to post data
    pub async fn post_data<T: Serialize>(&self, data: &T) -> Result<(), Error> {
        if self.args.dry_run {
            log::info!("DryRun, not posting to {}", self.args.alert_url);
            return Ok(())
        }
        log::info!("Posting alert to: {}", &self.args.alert_url);
        match self.client.post(&self.args.alert_url)
            .json(data)
            .send()
            .await {
            Ok(_) => {
                log::info!("ok");
            },
            Err(e) => {
                log::error!("error: {}", e);
            }
        }
        Ok(())
    }

    pub async fn alert(&mut self, key: String) -> Result<(), Error> {

        // do a quick gc, this is not ideal but too much overhead to make a mutex and
        // lock and call and clone...
        self.gc();

        // check re-alert, start by checking if the key is in the alets already sent
        if let Some(last_alert_ts) = self.alerts.get(&key) {
            // we found a previously sent alert for this key
            log::warn!("Last alert for key: {}, was at: {:?}", key, last_alert_ts);
            // Get duration since the last alert
            if let Ok(duration_since_last_alert) = SystemTime::now().duration_since(*last_alert_ts) {
                // Check if the duration since the last alert is less than the window // block time perhaps?
                if duration_since_last_alert.as_secs() < self.args.window {
                    log::warn!("Supressing alert, last alert for key: {}, was at: {:?}, elapsed time since then: {:?}", key, last_alert_ts, duration_since_last_alert);
                } else {
                    let data = AlertPayload {
                        key: key.to_string(),
                        block_time: self.args.block_seconds as i32,
                        realert: "true"
                    };

                    log::warn!("Re-Alerting for {:?}", key);
                    match self.post_data(&data).await {
                        Ok(()) => {
                            log::warn!("Alert sent...");
                            self.alerts.insert(key, SystemTime::now());
                        },
                        Err(e) => {
                            log::warn!("Error posting data, {}", e)
                        }
                    };
                    
                    
                }
            }
            Ok(())
        } else {
            log::warn!("Alerting for {:?}", key);
            let data = AlertPayload {
                key: key.to_string(),
                block_time: self.args.block_seconds as i32,
                realert: "false",
            };
            match self.post_data(&data).await {
                Ok(()) => {
                    log::warn!("Alert sent...");
                    self.alerts.insert(key, SystemTime::now());
                },
                Err(e) => {
                    log::warn!("Error posting data, {}", e)
                }
            };

            Ok(())
        }

    }

    pub fn gc(&mut self) {
        // GC, evict alerts that are stale
        if Instant::now().duration_since(self.last_gc).as_secs() > 2* self.args.window {
            log::info!("alerts gc before: {}", self.alerts.len());
            self.alerts.retain(|_, v| {
                match SystemTime::now().duration_since(*v) {
                    Ok(duration) => duration.as_secs() > self.args.window * 2,
                    Err(_) => false, // Handle the case where `duration_since` fails
                }
            });
            log::info!("alerts gc after: {}", self.alerts.len());
            self.last_gc = Instant::now();
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use env_logger;
    use wiremock::{MockServer, Mock, ResponseTemplate};
    use wiremock::matchers::{method, path};
    use std::time::Duration;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_alert_submission() {

        let mock_server = MockServer::start().await;
        
        let mut http_poster = HttpPoster::new(AppArgs {
            interface: Some("Foo".to_string()),           // Assuming "Foo" is a mock network device name
            file: None,                            // No pcap file for testing
            threshold: 1000,                            // Example threshold value
            window: 1,                                  // Example window value in seconds
            alert_url: mock_server.uri(),                // Mock ELB host
            dry_run: false,                       // Enable fake mode for testing
            block_seconds: 86400,                       // Example block duration in seconds
            whitelist_networks: "10.0.0.0/8, 192.168.0.0/16".to_string(), // Example whitelisted networks
            whitelist_ja3s: "None".to_string(),                       // No whitelisted JA3 hashes for testing
            log_create_buckets: Some(false),            // Disable logging for bucket creation in test
        });

        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        // Scenario 1: Submit an alert
        http_poster.alert("test_key".to_string()).await.unwrap();
        sleep(Duration::from_millis(100)).await; // Wait for 100 milliseconds
        assert_eq!(mock_server.received_requests().await.unwrap().len(), 1);

        // Scenario 2: Resubmit the same alert
        http_poster.alert("test_key".to_string()).await.unwrap();
        sleep(Duration::from_millis(100)).await; // Wait for 100 milliseconds
        assert_eq!(mock_server.received_requests().await.unwrap().len(), 1);

        // Scenario 3: Wait and then submit the alert again
        sleep(Duration::from_secs(http_poster.args.window * 2)).await;
        http_poster.alert("test_key".to_string()).await.unwrap();
        sleep(Duration::from_millis(100)).await; // Wait for 100 milliseconds
        // The server should now have received a second request
        assert_eq!(mock_server.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_dryrun() {

        let mock_server = MockServer::start().await;

        let mut http_poster = HttpPoster::new(AppArgs {
            interface: Some("Foo".to_string()),           // Assuming "Foo" is a mock network device name
            file: None,                            // No pcap file for testing
            threshold: 1000,                            // Example threshold value
            window: 1,                                  // Example window value in seconds
            alert_url: mock_server.uri(),                // Mock ELB host
            dry_run: true,                 // Enable fake mode for testing
            block_seconds: 86400,                       // Example block duration in seconds
            whitelist_networks: "10.0.0.0/8, 192.168.0.0/16".to_string(), // Example whitelisted networks
            whitelist_ja3s: "None".to_string(),                       // No whitelisted JA3 hashes for testing
            log_create_buckets: Some(false),            // Disable logging for bucket creation in test
        });

        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        // Scenario 1: Submit an alert
        http_poster.alert("test_key".to_string()).await.unwrap();
        sleep(Duration::from_millis(100)).await; // Wait for 100 milliseconds
        assert_eq!(mock_server.received_requests().await.unwrap().len(), 0);
    }
}
