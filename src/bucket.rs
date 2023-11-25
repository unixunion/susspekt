use std::time::{Instant, SystemTime, UNIX_EPOCH};

// Define a struct 'Bucket' to represent a bucket in a rolling window time series analysis.
pub(crate) struct Bucket {
    pub last_ts: SystemTime, // Timestamp of the last update to the bucket.
    // pub rolling_count: Vec<u16>, // A vector to hold counts for each second in a 5-minute rolling window.
    pub rolling_window: RollingWindow,
    pub sum_count: u16, // Sum of counts over the current rolling window.
    pub last_alert_ts: Option<Instant>, // Optional timestamp of the last alert. 'None' if no alert has been triggered.
    pub window_size: usize, // the rolling window size
    start_ts: SystemTime,
}

// Implementation of methods for the 'Bucket' struct.
impl Bucket {
    // Constructor for a new 'Bucket'. Initializes the struct.
    pub fn new(_ja3: String, current_ts: SystemTime, window_size: usize) -> Self {
        Bucket {
            last_ts: current_ts, // Set the last timestamp to the current timestamp.
            // rolling_count: vec![0; window_size], // Initialize rolling_count with 300 zeroes, representing a 5-minute window with 1-second intervals.
            rolling_window: RollingWindow::new(window_size),
            sum_count: 0, // Initialize sum_count to 0.
            last_alert_ts: None, // Initialize last_alert_ts to None, indicating no alerts have been triggered yet.
            window_size, // window size
            start_ts: current_ts,
        }
    }

    // Updates the bucket with the current timestamp. This method adjusts the rolling window and count.
    pub fn update(&mut self, current_ts: SystemTime) {
        // Calculate the elapsed time in seconds since the UNIX epoch for both timestamps
        let last_ts_secs = match self.last_ts.duration_since(UNIX_EPOCH) {
            Ok(n) => n.as_secs(),
            Err(_) => 0, // Handle the case where last_ts is earlier than UNIX_EPOCH
        };

        let current_ts_secs = match current_ts.duration_since(UNIX_EPOCH) {
            Ok(n) => n.as_secs(),
            Err(_) => 0, // Handle the case where current_ts is earlier than UNIX_EPOCH
        };

        // Calculate the number of seconds elapsed between the last and current timestamps
        let elapsed_secs = if current_ts_secs > last_ts_secs {
            current_ts_secs - last_ts_secs
        } else {
            0 // Handle case where current_ts is earlier than or equal to last_ts
        };

        log::debug!("elapsed_secs: {}", elapsed_secs);

        // Calculate the index based on elapsed time
        let current_idx = elapsed_secs as usize % self.window_size;
        log::debug!("current_idx: {}", current_idx);

        // Reset window if necessary
        if elapsed_secs as usize >= self.window_size {
            log::debug!("elapsed_secs > window_size, new window");
            self.rolling_window = RollingWindow::new(self.window_size);
        }

        // Update the rolling window
        log::debug!("updating rolling window with 1");
        self.rolling_window.update(1, current_ts);
        log::debug!("window sum: {}", self.rolling_window.sum());

        // Update the last timestamp
        self.last_ts = current_ts;
    }

    /// check the threshold
    pub fn check_threshold(&self, threshold: u16) -> bool {
        // Sum the counts in the rolling window and check against the threshold
        log::debug!("checking threshold: {} > {}", self.rolling_window.sum(), threshold);
        self.rolling_window.sum() > threshold
    }

}

#[cfg(test)]
use std::{println as info, println as warn};

use crate::rollingwindow::RollingWindow;

mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn test_bucket_initialization() {
        let now = SystemTime::now();
        let window_size = 300; // 5 minutes
        let bucket = Bucket::new("some_ja3".to_string(), now, window_size);

        assert_eq!(bucket.last_ts, now);
        assert_eq!(bucket.sum_count, 0);
        assert!(bucket.last_alert_ts.is_none());
        assert_eq!(bucket.window_size, window_size);
    }

    #[test]    #[test]
    fn test_update() {
        let mut bucket = Bucket::new("test_ja3".to_string(), SystemTime::now(), 60);
        let current_ts = SystemTime::now();

        bucket.update(current_ts);
        assert_eq!(bucket.last_ts, current_ts);
        // Further assertions can be made depending on the internal structure of RollingWindow
    }

    #[test]
    fn test_rolling_window_behavior() {
        let mut bucket = Bucket::new("test_ja3".to_string(), SystemTime::now(), 60);
        let start_ts = SystemTime::now();

        // Simulate updates over time
        for _ in 0..70 {
            bucket.update(start_ts + Duration::new(1, 0));
        }

        println!("rw-1 {}", bucket.rolling_window.sum());
        assert!(bucket.rolling_window.sum()==70);

        let start_ts = SystemTime::now();
        for _ in 0..60 {
            bucket.update(start_ts + Duration::new(1, 0));
            // bucket.update(start_ts + Duration::new(1, 0));
        }
        println!("rw-2 {}", bucket.rolling_window.sum());
        assert!(bucket.rolling_window.sum()==130);
        // Assert that the rolling window has discarded old values
        // (specific assertions depend on the implementation details of RollingWindow)
    }

    #[test]
    fn test_threshold_check() {
        let mut bucket = Bucket::new("test_ja3".to_string(), SystemTime::now(), 60);

        // Update the bucket to exceed the threshold
        for _ in 0..100 {
            bucket.update(SystemTime::now());
        }

        assert!(bucket.check_threshold(50)); // Assuming the threshold is 50
    }
}
