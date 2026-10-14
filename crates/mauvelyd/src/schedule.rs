//! When to check in next.
//!
//! After a check-in: the server's `interval_s`, floored at 60 s. While the
//! server is unreachable: 60 s, doubling, capped at 1 h. Both get ±10 %
//! jitter so a fleet that lost the server together does not return together.

use std::time::Duration;

pub const FLOOR_S: u64 = 60;
pub const BACKOFF_START_S: u64 = 60;
pub const BACKOFF_CAP_S: u64 = 3600;

/// The interval the server asked for, floored.
pub fn interval(interval_s: u64) -> u64 {
    interval_s.max(FLOOR_S)
}

/// `secs` scaled by a random factor in [0.9, 1.1].
pub fn jitter(secs: u64) -> Duration {
    with_factor(secs, rand::random_range(0.9..=1.1))
}

fn with_factor(secs: u64, factor: f64) -> Duration {
    Duration::from_secs_f64(secs as f64 * factor)
}

/// Exponential backoff over consecutive failures.
#[derive(Debug, Default)]
pub struct Backoff {
    failures: u32,
}

impl Backoff {
    /// The wait after one more failure, before jitter.
    pub fn next(&mut self) -> u64 {
        let secs = BACKOFF_START_S
            .saturating_mul(1u64 << self.failures.min(32))
            .min(BACKOFF_CAP_S);
        self.failures = self.failures.saturating_add(1);
        secs
    }

    pub fn reset(&mut self) {
        self.failures = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_to_an_hour() {
        let mut b = Backoff::default();
        let seq: Vec<u64> = (0..10).map(|_| b.next()).collect();
        assert_eq!(seq, [60, 120, 240, 480, 960, 1920, 3600, 3600, 3600, 3600]);
        for _ in 0..100 {
            assert_eq!(b.next(), 3600);
        }
        b.reset();
        assert_eq!(b.next(), 60);
    }

    #[test]
    fn interval_is_floored() {
        assert_eq!(interval(0), 60);
        assert_eq!(interval(30), 60);
        assert_eq!(interval(900), 900);
    }

    #[test]
    fn jitter_stays_within_ten_percent() {
        assert_eq!(with_factor(900, 0.9), Duration::from_secs(810));
        assert_eq!(with_factor(900, 1.1).as_secs(), 990);
        let (mut lo, mut hi) = (Duration::MAX, Duration::ZERO);
        for _ in 0..2000 {
            let d = jitter(900);
            assert!(d >= Duration::from_secs(810) && d <= Duration::from_secs(990), "{d:?}");
            lo = lo.min(d);
            hi = hi.max(d);
        }
        // Both halves of the range are used.
        assert!(lo < Duration::from_secs(870) && hi > Duration::from_secs(930));
    }
}
