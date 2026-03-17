//! Time and date utilities for certificate validity.

use chrono::{DateTime, Utc};

/// Format an ASN.1 time as a human-readable string.
#[allow(dead_code)] // Public API utility
pub fn format_asn1_time_utc(timestamp: i64) -> String {
    DateTime::from_timestamp(timestamp, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| format!("timestamp {timestamp}"))
}

/// Format a duration in human-readable form.
#[allow(dead_code)] // Public API utility
pub fn format_duration(seconds: i64) -> String {
    const SECONDS_PER_MINUTE: i64 = 60;
    const SECONDS_PER_HOUR: i64 = 60 * SECONDS_PER_MINUTE;
    const SECONDS_PER_DAY: i64 = 24 * SECONDS_PER_HOUR;

    if seconds < SECONDS_PER_MINUTE {
        format!("{} seconds", seconds)
    } else if seconds < SECONDS_PER_HOUR {
        format!("{} minutes", seconds / SECONDS_PER_MINUTE)
    } else if seconds < SECONDS_PER_DAY {
        format!("{} hours", seconds / SECONDS_PER_HOUR)
    } else {
        format!("{} days", seconds / SECONDS_PER_DAY)
    }
}

/// Get the current Unix timestamp.
#[allow(dead_code)] // Public API utility
pub fn now_timestamp() -> i64 {
    Utc::now().timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_asn1_time_utc() {
        let timestamp = 1_700_000_000; // 2023-11-15
        let formatted = format_asn1_time_utc(timestamp);
        assert!(formatted.contains("2023"));
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(30), "30 seconds");
        assert_eq!(format_duration(120), "2 minutes");
        assert_eq!(format_duration(7200), "2 hours");
        assert_eq!(format_duration(172800), "2 days");
    }

    #[test]
    fn test_now_timestamp() {
        let ts = now_timestamp();
        assert!(ts > 1_700_000_000); // After 2023
    }
}
