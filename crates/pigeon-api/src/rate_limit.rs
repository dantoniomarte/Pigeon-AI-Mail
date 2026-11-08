//! Per-key request rate limiting: token bucket, 10 req/s sustained, burst 50.
//!
//! The bucket is keyed by account rather than by key id on purpose: a client
//! that rotates keys to dodge the limit still shares one budget, and the
//! contract describes the limit as "per key" only because one key is the usual
//! case. Refill is continuous (a token every 100 ms), so a client that sends a
//! burst and then goes quiet gets capacity back without waiting for a window
//! boundary.
//!
//! Exceeding the bucket is a `429` with `Retry-After` pointing at the next token;
//! every authenticated response carries `X-RateLimit-Limit/Remaining/Reset`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::time::now_unix;

/// Sustained requests per second.
pub const SUSTAINED_RPS: u32 = 10;
/// Burst allowance on top of the sustained rate.
pub const BURST: u32 = 50;

/// Sustained requests per second for the **unauthenticated** WKD endpoints.
///
/// Tighter than the keyed API limit because there is no credential to throttle:
/// the bucket is per source address, and a key directory is a cheap read that a
/// stranger should not be able to use to enumerate an instance at speed.
pub const WKD_RATE_RPS: u32 = 5;
/// Burst capacity of a WKD bucket (a full client sync is a handful of lookups).
pub const WKD_RATE_BURST: u32 = 20;
/// Buckets idle for longer than this are dropped when the map is pruned.
const IDLE_EVICTION: Duration = Duration::from_secs(600);
/// Above this many buckets, the next check prunes idle entries.
const PRUNE_THRESHOLD: usize = 4096;

/// What a caller may advertise about the current window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Permit {
    /// Sustained limit, for `X-RateLimit-Limit`.
    pub limit: u32,
    /// Whole tokens left, for `X-RateLimit-Remaining`.
    pub remaining: u32,
    /// Unix second the bucket refills completely, for `X-RateLimit-Reset`.
    pub reset_at: i64,
}

struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

/// Token bucket limiter shared by every handler.
pub struct RateLimiter {
    buckets: Mutex<HashMap<i64, Bucket>>,
    rps: f64,
    burst: f64,
}

impl RateLimiter {
    /// Limiter with the given sustained rate and burst capacity.
    pub fn new(rps: u32, burst: u32) -> Self {
        let rps = f64::from(rps.max(1));
        let burst = f64::from(burst.max(1));
        Self {
            buckets: Mutex::new(HashMap::new()),
            rps,
            burst,
        }
    }

    /// Limiter at the contract defaults.
    pub fn with_defaults() -> Self {
        Self::new(SUSTAINED_RPS, BURST)
    }

    /// Take one token for `account_id`.
    ///
    /// `Ok(permit)` when the request may proceed (the headers describe the
    /// bucket *after* the token was taken); `Err(retry_after_secs)` when it may
    /// not.
    pub fn check(&self, account_id: i64) -> Result<Permit, u64> {
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if buckets.len() > PRUNE_THRESHOLD {
            buckets.retain(|_, bucket| bucket.last_refill.elapsed() < IDLE_EVICTION);
        }
        let now = Instant::now();
        let bucket = buckets.entry(account_id).or_insert(Bucket {
            tokens: self.burst,
            last_refill: now,
        });
        let elapsed = now.saturating_duration_since(bucket.last_refill);
        bucket.tokens = (bucket.tokens + elapsed.as_secs_f64() * self.rps).min(self.burst);
        bucket.last_refill = now;

        if bucket.tokens < 1.0 {
            // Seconds until one token exists again, rounded up so the client
            // never retries a hair too early.
            let deficit = 1.0 - bucket.tokens;
            let retry_after = (deficit / self.rps).ceil().max(1.0);
            return Err(retry_after as u64);
        }

        bucket.tokens -= 1.0;
        let remaining = bucket.tokens.floor().max(0.0);
        let refill_secs = (self.burst - bucket.tokens) / self.rps;
        Ok(Permit {
            limit: self.rps as u32,
            remaining: remaining as u32,
            reset_at: now_unix() + refill_secs.ceil().max(0.0) as i64,
        })
    }
}

impl RateLimiter {
    /// Limiter tuned for the unauthenticated WKD surface.
    pub fn for_wkd() -> Self {
        Self::new(WKD_RATE_RPS, WKD_RATE_BURST)
    }
}

/// Bucket key for an unauthenticated caller identified only by address.
///
/// IPv4 keeps its exact value (no collisions at all); IPv6 keeps 63 bits of its
/// address, which is enough for an abuse guard. The port is deliberately ignored:
/// a client must not be able to refresh its budget by opening a new connection.
pub fn client_bucket(ip: std::net::IpAddr) -> i64 {
    match ip {
        std::net::IpAddr::V4(v4) => i64::from(u32::from(v4)),
        std::net::IpAddr::V6(v6) => {
            let octets = v6.octets();
            let mut folded: u64 = 0;
            for (index, byte) in octets.iter().enumerate() {
                folded ^= u64::from(*byte) << ((index % 8) * 8);
            }
            (folded & 0x7fff_ffff_ffff_ffff) as i64
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wkd_buckets_are_per_address_and_ignore_the_port() {
        use std::net::{IpAddr, SocketAddr};

        let first = SocketAddr::from(([203, 0, 113, 7], 4242));
        let same_host_other_port = SocketAddr::from(([203, 0, 113, 7], 9999));
        let other = SocketAddr::from(([203, 0, 113, 8], 4242));
        assert_eq!(
            client_bucket(first.ip()),
            client_bucket(same_host_other_port.ip()),
            "a new source port must not refresh the budget"
        );
        assert_ne!(client_bucket(first.ip()), client_bucket(other.ip()));
        assert_ne!(client_bucket(IpAddr::from([0, 0, 0, 0])), -1);

        let limiter = RateLimiter::for_wkd();
        assert_eq!(WKD_RATE_RPS, 5);
        // The first burst passes, the next request is refused with a retry hint.
        for _ in 0..WKD_RATE_BURST {
            assert!(limiter.check(client_bucket(first.ip())).is_ok());
        }
        let retry = limiter
            .check(client_bucket(first.ip()))
            .expect_err("the bucket is empty");
        assert!(retry >= 1, "the retry hint is at least a second");
        assert!(
            limiter.check(client_bucket(other.ip())).is_ok(),
            "another address has its own bucket"
        );
    }

    #[test]
    fn a_full_burst_passes_then_the_bucket_is_empty() {
        let limiter = RateLimiter::new(10, 5);
        for expected_remaining in (0..5).rev() {
            let permit = limiter.check(1).expect("within burst");
            assert_eq!(permit.limit, 10);
            assert_eq!(permit.remaining, expected_remaining);
        }
        let retry_after = limiter.check(1).expect_err("burst exhausted");
        assert!(retry_after >= 1, "Retry-After must be at least 1s");
    }

    #[test]
    fn buckets_are_per_account() {
        let limiter = RateLimiter::new(10, 2);
        limiter.check(1).expect("first");
        limiter.check(1).expect("second");
        assert!(limiter.check(1).is_err(), "account 1 is empty");
        limiter.check(2).expect("account 2 has its own bucket");
    }

    #[test]
    fn tokens_refill_over_time() {
        let limiter = RateLimiter::new(1000, 1);
        limiter.check(7).expect("burst capacity 1");
        assert!(limiter.check(7).is_err());
        std::thread::sleep(Duration::from_millis(20));
        limiter.check(7).expect("refilled at 1000 rps");
    }

    #[test]
    fn reset_is_in_the_future_and_remaining_never_underflows() {
        let limiter = RateLimiter::new(10, 3);
        let permit = limiter.check(9).expect("token");
        assert!(permit.reset_at >= now_unix());
        assert!(permit.remaining <= permit.limit);
    }

    #[test]
    fn defaults_match_the_contract() {
        let limiter = RateLimiter::default();
        let permit = limiter.check(1).expect("first request");
        assert_eq!(permit.limit, SUSTAINED_RPS);
        assert_eq!(permit.remaining, BURST - 1);
    }
}
