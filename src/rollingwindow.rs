use std::collections::VecDeque;
use std::time::Duration;
use std::time::SystemTime;

#[derive(Debug)]
pub struct RollingWindow {
    pub window: VecDeque<(SystemTime, u32)>,
    capacity: usize,
}

impl RollingWindow {
    pub fn new(capacity: usize) -> RollingWindow {
        RollingWindow {
            window: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    pub fn update(&mut self, value: u32, timestamp: SystemTime) {
        // Remove values older than capacity seconds
        while self.window.front().map_or(false, |&(t, _)| {
            if let Ok(duration) = timestamp.duration_since(t) {
                duration > Duration::new(self.capacity as u64, 0)
            } else {
                false
            }
        }) {
            self.window.pop_front();
        }

        // Check if the last entry in the window has the same second as the timestamp
        if let Some(&mut (t, ref mut last_value)) = self.window.back_mut() {
            if let Ok(duration) = timestamp.duration_since(t) {
                if duration.as_secs() == 0 {
                    // If the timestamps are in the same second, merge the value
                    *last_value += value;
                    return;
                }
            }
        }

        // If the timestamp is new or the window is empty, add the new value
        if self.window.len() < self.capacity {
            self.window.push_back((timestamp, value));
        }
    }

    pub fn sum(&self) -> u16 {
        self.window.iter().map(|&(_, count)| count as u16).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_initialization() {
        let window = RollingWindow::new(60);
        assert!(window.window.is_empty());
        assert_eq!(window.capacity, 60);
    }

    #[test]
    fn test_single_update() {
        let mut window = RollingWindow::new(60);
        window.update(10, SystemTime::now());
        assert_eq!(window.window.len(), 1);
        assert_eq!(window.sum(), 10);
    }

    #[test]
    fn test_multiple_updates_within_capacity() {
        let mut window = RollingWindow::new(60);


        // multiple updates in same instant should be one object in the window
        for i in 0..30 {
            window.update(1, SystemTime::now());
        }
        print!("window len {:?}", window.window.len());
        assert_eq!(window.window.len(), 1);
        assert_eq!(window.sum(), 30);

        // multiple updates over a time span should be spread out in the window
        for i in 0..30 {
            window.update(1, SystemTime::now() + Duration::new(i, 0));
        }
        print!("window len {:?}", window.window.len());
        assert_eq!(window.window.len(), 30);
        assert_eq!(window.sum(), 60); // merged with previous data in the window

    }

    #[test]
    fn test_capacity_limit() {
        let ts = SystemTime::now();
        let mut window = RollingWindow::new(60);
        for i in 0..100 {
            window.update(1, ts + Duration::new(i.try_into().unwrap(), 0));
        }
        assert_eq!(window.window.len(), 60);
        assert_eq!(window.sum(), 60);
    }

    #[test]
    fn test_time_based_removal() {
        let mut window = RollingWindow::new(5);
        let start = SystemTime::now();
        window.update(1, start);
        sleep(Duration::new(6, 0));  // Sleep for 6 seconds
        window.update(2, SystemTime::now());
        assert_eq!(window.window.len(), 1);
    }

    #[test]
    fn test_sparse_update() {
        let mut window = RollingWindow::new(5);
        let start = SystemTime::now();
        window.update(1, start);
        sleep(Duration::new(10, 0));  // Sleep for 10 seconds
        window.update(2, SystemTime::now());
        assert_eq!(window.window.len(), 1);
    }
}
