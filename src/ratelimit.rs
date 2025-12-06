//! Rate limiting for auth attempts
//! 
//! Protects against:
//! - DoS attacks (per-IP limiting)
//! - Brute-force attacks (per-address limiting)

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use crate::config::CONFIG;

/// Tracks auth attempts with sliding window
struct RateLimiter {
    /// IP -> (attempts, window_start)
    ip_attempts: HashMap<IpAddr, (u32, Instant)>,
    /// Claimed address -> (attempts, window_start)  
    addr_attempts: HashMap<String, (u32, Instant)>,
    /// Last cleanup time
    last_cleanup: Instant,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            ip_attempts: HashMap::new(),
            addr_attempts: HashMap::new(),
            last_cleanup: Instant::now(),
        }
    }

    /// Cleanup old entries (call periodically)
    fn cleanup(&mut self) {
        let now = Instant::now();
        let window = Duration::from_secs(CONFIG.rate_limit_window_secs);

        // Only cleanup every 60 seconds
        if now.duration_since(self.last_cleanup) < Duration::from_secs(60) {
            return;
        }
        self.last_cleanup = now;

        self.ip_attempts
            .retain(|_, (_, start)| now.duration_since(*start) < window);
        self.addr_attempts
            .retain(|_, (_, start)| now.duration_since(*start) < window);
    }

    /// Check and record an attempt. Returns Ok(()) if allowed, Err with wait time if blocked.
    fn check_and_record(&mut self, ip: IpAddr, address: &str) -> Result<(), Duration> {
        self.cleanup();

        let now = Instant::now();
        let window = Duration::from_secs(CONFIG.rate_limit_window_secs);

        // Check IP rate limit
        let ip_entry = self.ip_attempts.entry(ip).or_insert((0, now));
        if now.duration_since(ip_entry.1) >= window {
            // Window expired, reset
            *ip_entry = (0, now);
        }
        if ip_entry.0 >= CONFIG.rate_limit_max_attempts_ip {
            let wait = window - now.duration_since(ip_entry.1);
            return Err(wait);
        }

        // Check address rate limit
        let addr_key = address.to_lowercase();
        let addr_entry = self.addr_attempts.entry(addr_key).or_insert((0, now));
        if now.duration_since(addr_entry.1) >= window {
            *addr_entry = (0, now);
        }
        if addr_entry.0 >= CONFIG.rate_limit_max_attempts_addr {
            let wait = window - now.duration_since(addr_entry.1);
            return Err(wait);
        }

        // Record attempt
        ip_entry.0 += 1;
        addr_entry.0 += 1;

        Ok(())
    }

    /// Record a failed attempt (adds extra penalty)
    fn record_failure(&mut self, ip: IpAddr, address: &str) {
        let now = Instant::now();

        // Add extra attempts on failure to penalize bad actors
        if let Some(entry) = self.ip_attempts.get_mut(&ip) {
            entry.0 = entry.0.saturating_add(2); // +2 extra on failure
        }
        
        let addr_key = address.to_lowercase();
        if let Some(entry) = self.addr_attempts.get_mut(&addr_key) {
            entry.0 = entry.0.saturating_add(2);
        }

        // Also add to blocklist temporarily for repeated failures
        let ip_attempts = self.ip_attempts.get(&ip).map(|e| e.0).unwrap_or(0);
        if ip_attempts >= CONFIG.rate_limit_max_attempts_ip * 2 {
            // Extended block - reset window to now
            if let Some(entry) = self.ip_attempts.get_mut(&ip) {
                entry.1 = now;
            }
        }
    }
}

static LIMITER: LazyLock<Mutex<RateLimiter>> = LazyLock::new(|| Mutex::new(RateLimiter::new()));

/// Check if an auth attempt is allowed
pub fn check_rate_limit(ip: IpAddr, address: &str) -> Result<(), Duration> {
    let mut limiter = LIMITER.lock().unwrap();
    limiter.check_and_record(ip, address)
}

/// Record a failed auth attempt (increases rate limit counters)
pub fn record_auth_failure(ip: IpAddr, address: &str) {
    let mut limiter = LIMITER.lock().unwrap();
    limiter.record_failure(ip, address);
}

/// Get current stats for monitoring
pub fn get_stats() -> (usize, usize) {
    let limiter = LIMITER.lock().unwrap();
    (limiter.ip_attempts.len(), limiter.addr_attempts.len())
}

