use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

/// Simple in-memory rate limiter for authentication endpoints.
/// Uses a sliding window approach per IP address.
pub struct AuthRateLimiter {
    attempts: Mutex<HashMap<IpAddr, Vec<Instant>>>,
    max_attempts: usize,
    window_secs: u64,
}

impl AuthRateLimiter {
    pub fn new(max_attempts: usize, window_secs: u64) -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
            max_attempts,
            window_secs,
        }
    }

    /// Check if a request from the given IP is allowed.
    /// Returns true if allowed, false if rate limited.
    pub fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut attempts = self.attempts.lock().unwrap();

        let entry = attempts.entry(ip).or_default();

        // Remove expired entries outside the window
        entry.retain(|t| now.duration_since(*t).as_secs() < self.window_secs);

        if entry.len() >= self.max_attempts {
            return false;
        }

        entry.push(now);
        true
    }

    /// Get remaining attempts for the given IP.
    pub fn remaining(&self, ip: IpAddr) -> usize {
        let now = Instant::now();
        let attempts = self.attempts.lock().unwrap();

        if let Some(entry) = attempts.get(&ip) {
            let active: usize = entry
                .iter()
                .filter(|t| now.duration_since(**t).as_secs() < self.window_secs)
                .count();
            self.max_attempts.saturating_sub(active)
        } else {
            self.max_attempts
        }
    }

    /// Reset attempts for the given IP (used after successful login).
    pub fn reset(&self, ip: IpAddr) {
        let mut attempts = self.attempts.lock().unwrap();
        attempts.remove(&ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let limiter = AuthRateLimiter::new(3, 60);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        assert!(limiter.check(ip));
        assert!(limiter.check(ip));
        assert!(limiter.check(ip));
        assert_eq!(limiter.remaining(ip), 0);
        assert!(!limiter.check(ip));
    }

    #[test]
    fn test_rate_limiter_reset() {
        let limiter = AuthRateLimiter::new(1, 60);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        assert!(limiter.check(ip));
        assert!(!limiter.check(ip));

        limiter.reset(ip);
        assert!(limiter.check(ip));
    }
}
