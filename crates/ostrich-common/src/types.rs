// RFC 5280: X.509 PKI Certificate and CRL Profile
// NIST 800-53: IA-2 - User identification and authentication

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for certificates in the database
pub type CertificateId = Uuid;

/// Unique identifier for keys in the database
pub type KeyId = Uuid;

/// Distinguished Name representation
///
/// RFC 5280 §4.1.2.4 - Issuer and Subject
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DistinguishedName {
    pub common_name: Option<String>,
    pub organization: Option<String>,
    pub organizational_unit: Option<String>,
    pub locality: Option<String>,
    pub state_or_province: Option<String>,
    pub country: Option<String>,
    pub serial_number: Option<String>,
}

impl DistinguishedName {
    /// Create a new DN with just a common name
    pub fn new_cn(cn: impl Into<String>) -> Self {
        Self {
            common_name: Some(cn.into()),
            ..Default::default()
        }
    }

    /// Convert to RFC 4514 string representation
    /// Example: "CN=example.com,O=Example Inc,C=US"
    pub fn to_string_rfc4514(&self) -> String {
        let mut parts = Vec::new();

        if let Some(cn) = &self.common_name {
            parts.push(format!("CN={}", escape_rdn_value(cn)));
        }
        if let Some(ou) = &self.organizational_unit {
            parts.push(format!("OU={}", escape_rdn_value(ou)));
        }
        if let Some(o) = &self.organization {
            parts.push(format!("O={}", escape_rdn_value(o)));
        }
        if let Some(l) = &self.locality {
            parts.push(format!("L={}", escape_rdn_value(l)));
        }
        if let Some(st) = &self.state_or_province {
            parts.push(format!("ST={}", escape_rdn_value(st)));
        }
        if let Some(c) = &self.country {
            parts.push(format!("C={}", escape_rdn_value(c)));
        }
        if let Some(sn) = &self.serial_number {
            parts.push(format!("SERIALNUMBER={}", escape_rdn_value(sn)));
        }

        parts.join(",")
    }
}

impl Default for DistinguishedName {
    fn default() -> Self {
        Self {
            common_name: None,
            organization: None,
            organizational_unit: None,
            locality: None,
            state_or_province: None,
            country: None,
            serial_number: None,
        }
    }
}

impl std::fmt::Display for DistinguishedName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string_rfc4514())
    }
}

/// Escape special characters in RDN values per RFC 4514
fn escape_rdn_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            ',' | '+' | '"' | '\\' | '<' | '>' | ';' => {
                escaped.push('\\');
                escaped.push(ch);
            }
            '#' if escaped.is_empty() => {
                escaped.push('\\');
                escaped.push(ch);
            }
            ' ' if escaped.is_empty() => {
                escaped.push('\\');
                escaped.push(ch);
            }
            _ => escaped.push(ch),
        }
    }
    // Escape trailing space
    if escaped.ends_with(' ') && !escaped.ends_with("\\ ") {
        let len = escaped.len();
        escaped.insert(len - 1, '\\');
    }
    escaped
}

/// Certificate validity period
///
/// RFC 5280 §4.1.2.5 - Validity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validity {
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

impl Validity {
    /// Create a validity period starting now with the given duration in days
    pub fn days_from_now(days: u32) -> Self {
        let not_before = Utc::now();
        let not_after = not_before + chrono::Duration::days(days as i64);
        Self {
            not_before,
            not_after,
        }
    }

    /// Check if the validity period is currently valid
    pub fn is_valid(&self) -> bool {
        let now = Utc::now();
        now >= self.not_before && now <= self.not_after
    }

    /// Check if the validity period has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.not_after
    }

    /// Check if the validity period is not yet valid
    pub fn is_not_yet_valid(&self) -> bool {
        Utc::now() < self.not_before
    }
}

/// Serial number for certificates
///
/// RFC 5280 §4.1.2.2 - Serial number must be positive integer ≤ 20 octets
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SerialNumber(pub Vec<u8>);

impl SerialNumber {
    /// Create a serial number from bytes
    /// RFC 5280: Must be positive and ≤ 20 octets
    pub fn from_bytes(bytes: Vec<u8>) -> crate::Result<Self> {
        if bytes.is_empty() {
            return Err(crate::Error::validation("Serial number cannot be empty"));
        }
        if bytes.len() > 20 {
            return Err(crate::Error::validation("Serial number exceeds 20 octets"));
        }
        // Ensure positive (MSB must be 0 if next bit is 1)
        if bytes[0] & 0x80 != 0 {
            return Err(crate::Error::validation("Serial number must be positive"));
        }
        Ok(Self(bytes))
    }

    /// Convert to hex string for display
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Display for SerialNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dn_rfc4514() {
        let dn = DistinguishedName {
            common_name: Some("example.com".to_string()),
            organization: Some("Example Inc".to_string()),
            country: Some("US".to_string()),
            ..Default::default()
        };

        assert_eq!(dn.to_string_rfc4514(), "CN=example.com,O=Example Inc,C=US");
    }

    #[test]
    fn test_dn_escaping() {
        let value = "Example, Inc.";
        assert_eq!(escape_rdn_value(value), "Example\\, Inc.");
    }

    #[test]
    fn test_validity() {
        let validity = Validity::days_from_now(365);
        assert!(validity.is_valid());
        assert!(!validity.is_expired());
        assert!(!validity.is_not_yet_valid());
    }

    #[test]
    fn test_serial_number() {
        // Valid serial number
        let sn = SerialNumber::from_bytes(vec![0x01, 0x23, 0x45]).unwrap();
        assert_eq!(sn.to_hex(), "012345");

        // Too long
        let long_sn = SerialNumber::from_bytes(vec![0; 21]);
        assert!(long_sn.is_err());

        // Negative (MSB set)
        let neg_sn = SerialNumber::from_bytes(vec![0x80, 0x00]);
        assert!(neg_sn.is_err());
    }
}
