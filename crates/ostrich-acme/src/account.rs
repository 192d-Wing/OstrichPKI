//! ACME account management
//!
//! RFC 8555 §7.1.2: Account objects
//! RFC 8555 §7.3: Account management

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// ACME account status
///
/// RFC 8555 §7.1.6
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AccountStatus {
    /// Account is valid and can be used
    Valid,
    /// Account has been deactivated
    Deactivated,
    /// Account has been revoked
    Revoked,
}

/// ACME account
///
/// RFC 8555 §7.1.2
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    /// Account ID (internal)
    #[serde(skip)]
    pub id: Uuid,

    /// Account status
    pub status: AccountStatus,

    /// Contact information (email addresses)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub contact: Vec<String>,

    /// Terms of service agreed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_of_service_agreed: Option<bool>,

    /// External account binding (for hosted ACME)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_account_binding: Option<ExternalAccountBinding>,

    /// Orders URL
    pub orders: String,

    /// Account key (JWK)
    #[serde(skip)]
    pub key: AccountKey,

    /// Created timestamp
    #[serde(skip)]
    pub created_at: DateTime<Utc>,

    /// Updated timestamp
    #[serde(skip)]
    pub updated_at: DateTime<Utc>,
}

/// External account binding
///
/// RFC 8555 §7.3.4
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalAccountBinding {
    /// Key identifier
    pub kid: String,
    /// MAC key
    #[serde(skip)]
    pub mac_key: Vec<u8>,
}

/// Account key (JWK)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccountKey {
    /// Key type (e.g., "RSA", "EC")
    pub kty: String,
    /// Algorithm
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    /// Key use
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "use")]
    pub key_use: Option<String>,
    /// Key ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// Public key parameters (RSA: n, e; EC: crv, x, y)
    #[serde(flatten)]
    pub params: serde_json::Value,
}

impl Account {
    /// Create a new account
    pub fn new(key: AccountKey, contact: Vec<String>) -> Self {
        let id = Uuid::new_v4();
        Self {
            id,
            status: AccountStatus::Valid,
            contact,
            terms_of_service_agreed: Some(true),
            external_account_binding: None,
            orders: format!("/acme/account/{}/orders", id),
            key,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// Deactivate account
    pub fn deactivate(&mut self) {
        self.status = AccountStatus::Deactivated;
        self.updated_at = Utc::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_creation() {
        let key = AccountKey {
            kty: "RSA".to_string(),
            alg: Some("RS256".to_string()),
            key_use: None,
            kid: None,
            params: serde_json::json!({
                "n": "base64url_encoded_n",
                "e": "AQAB"
            }),
        };

        let account = Account::new(key, vec!["mailto:admin@example.com".to_string()]);
        assert_eq!(account.status, AccountStatus::Valid);
        assert_eq!(account.contact.len(), 1);
    }

    #[test]
    fn test_account_deactivation() {
        let key = AccountKey {
            kty: "RSA".to_string(),
            alg: None,
            key_use: None,
            kid: None,
            params: serde_json::json!({}),
        };

        let mut account = Account::new(key, vec![]);
        account.deactivate();
        assert_eq!(account.status, AccountStatus::Deactivated);
    }
}
