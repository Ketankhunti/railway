//! Sliding window of 1-second aggregate buckets for streaming metric evaluation.
//!
//! Each bucket tracks: request count, error count, total duration, min/max duration,
//! and a sorted sample for approximate percentile computation.
//!
//! The window is a circular buffer sized to the maximum lookback needed
//! (e.g., 3600 entries for a 1-hour baseline).

use std::collections::VecDeque;

/// A single 1-second aggregate bucket.
#[derive(Debug, Clone)]
pub struct WindowBucket {
    /// The second this bucket represents (Unix timestamp, truncated to second).
    pub timestamp_sec: u64,
    /// Number of requests in this second.
    pub count: u64,
    /// Number of error responses (status >= 400) in this second.
    pub error_count: u64,
    /// Sum of all durations in microseconds.
    pub duration_sum_us: u64,
    /// Min duration in this second.
    pub duration_min_us: u64,
    /// Max duration in this second.
    pub duration_max_us: u64,
    /// Reservoir sample of durations for percentile computation.
    /// Kept sorted for efficient percentile lookup.
    durations: Vec<u64>,
}

/// Maximum samples per bucket for percentile estimation.
const MAX_SAMPLES_PER_BUCKET: usize = 100;

impl WindowBucket {
    pub fn new(timestamp_sec: u64) -> Self {
        Self {
            timestamp_sec,
            count: 0,
            error_count: 0,
            duration_sum_us: 0,
            duration_min_us: u64::MAX,
            duration_max_us: 0,
            durations: Vec::new(),
        }
    }

    /// Record a span into this bucket.
    pub fn record(&mut self, duration_us: u64, is_error: bool) {
        self.count += 1;
        if is_error {
            self.error_count += 1;
        }
        self.duration_sum_us += duration_us;
        self.duration_min_us = self.duration_min_us.min(duration_us);
        self.duration_max_us = self.duration_max_us.max(duration_us);

        // Reservoir sampling: keep up to MAX_SAMPLES for percentile estimation.
        if self.durations.len() < MAX_SAMPLES_PER_BUCKET {
            self.durations.push(duration_us);
        }
    }

    /// Average duration in microseconds. Returns 0 if no data.
    pub fn avg_duration_us(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.duration_sum_us as f64 / self.count as f64
        }
    }

    /// Error rate (0.0 to 1.0). Returns 0 if no data.
    pub fn error_rate(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.error_count as f64 / self.count as f64
        }
    }

    /// Returns true if this bucket has any data.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Get the sorted durations for percentile computation.
    pub fn sorted_durations(&self) -> Vec<u64> {
        let mut sorted = self.durations.clone();
        sorted.sort_unstable();
        sorted
    }
}

/// A sliding window of 1-second buckets for a specific (service_id, metric) pair.
#[derive(Debug)]
pub struct SlidingWindow {
    /// Circular buffer of buckets. Back = newest, front = oldest.
    buckets: VecDeque<WindowBucket>,
    /// Maximum number of seconds to retain.
    max_seconds: usize,
}

impl SlidingWindow {
    pub fn new(max_seconds: usize) -> Self {
        Self {
            buckets: VecDeque::with_capacity(max_seconds),
            max_seconds,
        }
    }

    /// Record a span at the given timestamp. Creates/advances buckets as needed.
    pub fn record(&mut self, timestamp_ns: u64, duration_us: u64, is_error: bool) {
        let ts_sec = timestamp_ns / 1_000_000_000;

        // If empty, create the first bucket.
        if self.buckets.is_empty() {
            self.buckets.push_back(WindowBucket::new(ts_sec));
            self.buckets.back_mut().unwrap().record(duration_us, is_error);
            return;
        }

        let newest = self.buckets.back().unwrap().timestamp_sec;

        if ts_sec == newest {
            // Same second as the newest bucket — add to it.
            self.buckets.back_mut().unwrap().record(duration_us, is_error);
        } else if ts_sec > newest {
            // Advance: fill any gap seconds with empty buckets.
            let gap = (ts_sec - newest) as usize;
            // Don't create more than max_seconds of empty buckets.
            let fill = gap.min(self.max_seconds).saturating_sub(1);
            for i in 1..=fill {
                self.buckets.push_back(WindowBucket::new(newest + i as u64));
                self.trim();
            }
            self.buckets.push_back(WindowBucket::new(ts_sec));
            self.buckets.back_mut().unwrap().record(duration_us, is_error);
            self.trim();
        } else {
            // Late arrival: try to find the matching bucket. Common for out-of-order events
            // within the window. Don't create new buckets for very old events.
            if let Some(bucket) = self.buckets.iter_mut().find(|b| b.timestamp_sec == ts_sec) {
                bucket.record(duration_us, is_error);
            }
            // Else: event is too old, silently drop.
        }
    }

    /// Trim the buffer to the maximum size.
    fn trim(&mut self) {
        while self.buckets.len() > self.max_seconds {
            self.buckets.pop_front();
        }
    }

    /// Query aggregated stats over the last `window_secs` seconds.
    /// Returns (total_count, error_count, avg_duration_us).
    pub fn aggregate(&self, window_secs: u64) -> WindowAggregate {
        let cutoff = self.newest_timestamp().saturating_sub(window_secs);
        let mut agg = WindowAggregate::default();

        for bucket in &self.buckets {
            if bucket.timestamp_sec > cutoff {
                agg.count += bucket.count;
                agg.error_count += bucket.error_count;
                agg.duration_sum_us += bucket.duration_sum_us;
                if bucket.duration_min_us < agg.duration_min_us {
                    agg.duration_min_us = bucket.duration_min_us;
                }
                if bucket.duration_max_us > agg.duration_max_us {
                    agg.duration_max_us = bucket.duration_max_us;
                }
                agg.all_durations.extend(bucket.sorted_durations());
            }
        }

        agg.all_durations.sort_unstable();
        agg
    }

    /// Get aggregate for a range [from_secs_ago, to_secs_ago) relative to the newest bucket.
    /// Used by rate-of-change to compare "previous window" vs "current window".
    pub fn aggregate_range(&self, from_secs_ago: u64, to_secs_ago: u64) -> WindowAggregate {
        let newest = self.newest_timestamp();
        let start = newest.saturating_sub(from_secs_ago);
        let end = newest.saturating_sub(to_secs_ago);

        let mut agg = WindowAggregate::default();
        for bucket in &self.buckets {
            if bucket.timestamp_sec > start && bucket.timestamp_sec <= end {
                agg.count += bucket.count;
                agg.error_count += bucket.error_count;
                agg.duration_sum_us += bucket.duration_sum_us;
                agg.all_durations.extend(bucket.sorted_durations());
            }
        }
        agg.all_durations.sort_unstable();
        agg
    }

    /// Returns the timestamp of the newest bucket, or 0 if empty.
    pub fn newest_timestamp(&self) -> u64 {
        self.buckets.back().map_or(0, |b| b.timestamp_sec)
    }

    /// Returns the number of buckets in the window.
    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    /// Returns true if no buckets exist.
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }
}

/// Aggregated statistics over a time window.
#[derive(Debug, Default)]
pub struct WindowAggregate {
    pub count: u64,
    pub error_count: u64,
    pub duration_sum_us: u64,
    pub duration_min_us: u64,
    pub duration_max_us: u64,
    /// All sampled durations, sorted. Used for percentile computation.
    pub all_durations: Vec<u64>,
}

impl WindowAggregate {
    /// Error rate (0.0 to 1.0).
    pub fn error_rate(&self) -> f64 {
        if self.count == 0 { 0.0 } else { self.error_count as f64 / self.count as f64 }
    }

    /// Average duration in microseconds.
    pub fn avg_duration_us(&self) -> f64 {
        if self.count == 0 { 0.0 } else { self.duration_sum_us as f64 / self.count as f64 }
    }

    /// Approximate percentile from sampled durations.
    /// `p` in [0.0, 1.0], e.g., 0.99 for p99.
    pub fn percentile(&self, p: f64) -> f64 {
        if self.all_durations.is_empty() {
            return 0.0;
        }
        let idx = ((self.all_durations.len() as f64 * p).ceil() as usize)
            .saturating_sub(1)
            .min(self.all_durations.len() - 1);
        self.all_durations[idx] as f64
    }

    /// Mean of all sampled durations (for z-score baseline).
    pub fn mean_duration(&self) -> f64 {
        if self.all_durations.is_empty() {
            return 0.0;
        }
        let sum: u64 = self.all_durations.iter().sum();
        sum as f64 / self.all_durations.len() as f64
    }

    /// Standard deviation of sampled durations (for z-score).
    pub fn stddev_duration(&self) -> f64 {
        if self.all_durations.len() < 2 {
            return 0.0;
        }
        let mean = self.mean_duration();
        let variance = self.all_durations.iter()
            .map(|&d| {
                let diff = d as f64 - mean;
                diff * diff
            })
            .sum::<f64>() / (self.all_durations.len() - 1) as f64;
        variance.sqrt()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_record_basic() {
        let mut b = WindowBucket::new(100);
        assert!(b.is_empty());

        b.record(500, false); // 500µs, not error
        b.record(1000, true); // 1000µs, error
        b.record(200, false);

        assert_eq!(b.count, 3);
        assert_eq!(b.error_count, 1);
        assert_eq!(b.duration_min_us, 200);
        assert_eq!(b.duration_max_us, 1000);
        assert!((b.error_rate() - 1.0 / 3.0).abs() < 1e-10);
        assert!(!b.is_empty());
    }

    #[test]
    fn window_sequential_recording() {
        let mut w = SlidingWindow::new(10);
        // 3 events in second 100
        w.record(100_000_000_000, 500, false);
        w.record(100_500_000_000, 1000, true);
        w.record(100_900_000_000, 200, false);

        assert_eq!(w.len(), 1);
        let agg = w.aggregate(10);
        assert_eq!(agg.count, 3);
        assert_eq!(agg.error_count, 1);
    }

    #[test]
    fn window_advance_seconds() {
        let mut w = SlidingWindow::new(10);
        w.record(100_000_000_000, 100, false); // second 100
        w.record(101_000_000_000, 200, false); // second 101
        w.record(103_000_000_000, 300, false); // second 103 (gap at 102)

        assert_eq!(w.len(), 4); // 100, 101, 102 (empty), 103
        let agg = w.aggregate(10);
        assert_eq!(agg.count, 3);
    }

    #[test]
    fn window_trim_to_max() {
        let mut w = SlidingWindow::new(5);
        for i in 0..10u64 {
            w.record(i * 1_000_000_000, 100, false);
        }
        assert_eq!(w.len(), 5);
        // Oldest should be second 5, newest second 9
        assert_eq!(w.newest_timestamp(), 9);
    }

    #[test]
    fn window_aggregate_recent_only() {
        let mut w = SlidingWindow::new(100);
        // Record at seconds 0, 10, 20
        w.record(0, 100, false);
        w.record(10_000_000_000, 200, false);
        w.record(20_000_000_000, 300, true);

        // Aggregate last 15 seconds from second 20 → includes second 10 and 20
        let agg = w.aggregate(15);
        assert_eq!(agg.count, 2);
        assert_eq!(agg.error_count, 1);
    }

    #[test]
    fn aggregate_range_for_rate_of_change() {
        let mut w = SlidingWindow::new(100);
        // Window A: seconds 1-5
        for i in 1..=5u64 {
            w.record(i * 1_000_000_000, 100, false);
        }
        // Window B: seconds 6-10
        for i in 6..=10u64 {
            w.record(i * 1_000_000_000, 100, false);
        }

        // At newest=10, previous window (10..5 secs ago) = seconds 1-5
        let prev = w.aggregate_range(10, 5);
        assert_eq!(prev.count, 5);

        // Current window (5..0 secs ago) = seconds 6-10
        let curr = w.aggregate_range(5, 0);
        assert_eq!(curr.count, 5);
    }

    #[test]
    fn percentile_computation() {
        let mut w = SlidingWindow::new(100);
        // 100 requests with durations 1..=100
        for i in 1..=100u64 {
            w.record(1_000_000_000, i * 1000, false); // all in same second
        }

        let agg = w.aggregate(10);
        assert_eq!(agg.count, 100);

        let p50 = agg.percentile(0.50);
        let p99 = agg.percentile(0.99);
        let p100 = agg.percentile(1.0);

        assert!(p50 >= 49_000.0 && p50 <= 51_000.0, "p50={}", p50);
        assert!(p99 >= 98_000.0 && p99 <= 100_000.0, "p99={}", p99);
        assert_eq!(p100, 100_000.0);
    }

    #[test]
    fn stddev_computation() {
        let mut w = SlidingWindow::new(100);
        // Known values: [2, 4, 4, 4, 5, 5, 7, 9]
        for &v in &[2u64, 4, 4, 4, 5, 5, 7, 9] {
            w.record(1_000_000_000, v, false);
        }
        let agg = w.aggregate(10);
        let mean = agg.mean_duration();
        let stddev = agg.stddev_duration();

        assert!((mean - 5.0).abs() < 1e-10, "mean={}", mean);
        // Sample stddev of [2,4,4,4,5,5,7,9] ≈ 2.138
        assert!((stddev - 2.138).abs() < 0.01, "stddev={}", stddev);
    }

    #[test]
    fn late_arrival() {
        let mut w = SlidingWindow::new(100);
        w.record(10_000_000_000, 100, false); // second 10
        w.record(20_000_000_000, 200, false); // second 20

        // Late event for second 10 — should be absorbed
        w.record(10_500_000_000, 300, true); // second 10

        let agg = w.aggregate(100);
        assert_eq!(agg.count, 3);
        assert_eq!(agg.error_count, 1);
    }

    #[test]
    fn empty_window() {
        let w = SlidingWindow::new(10);
        assert!(w.is_empty());
        let agg = w.aggregate(10);
        assert_eq!(agg.count, 0);
        assert_eq!(agg.error_rate(), 0.0);
        assert_eq!(agg.percentile(0.99), 0.0);
    }
}
