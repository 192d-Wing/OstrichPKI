// NIST 800-53: AU-3 - Audit record content (timestamps)
// RFC 5280: X.509 validity periods

use chrono::{DateTime, Utc};

/// Get current UTC timestamp
/// Used for audit logs and certificate validity checks
pub fn now() -> DateTime<Utc> {
    Utc::now()
}

/// Format timestamp in RFC 3339 format
pub fn format_rfc3339(dt: &DateTime<Utc>) -> String {
    dt.to_rfc3339()
}

/// Parse RFC 3339 timestamp
pub fn parse_rfc3339(s: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
    DateTime::parse_from_rfc3339(s).map(|dt| dt.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_now() {
        let ts = now();
        assert!(ts <= Utc::now());
    }

    #[test]
    fn test_rfc3339_roundtrip() {
        let original = now();
        let formatted = format_rfc3339(&original);
        let parsed = parse_rfc3339(&formatted).unwrap();

        // Allow for microsecond precision differences
        let diff = (original.timestamp() - parsed.timestamp()).abs();
        assert!(diff < 1);
    }
}
