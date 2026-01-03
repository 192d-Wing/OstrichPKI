//! ACME order management
//!
//! RFC 8555 §7.1.3: Order objects
//! RFC 8555 §7.4: Applying for certificate issuance

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// ACME order status
///
/// RFC 8555 §7.1.6
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OrderStatus {
    /// Order is pending authorization
    Pending,
    /// Order is ready for finalization
    Ready,
    /// Order is being processed
    Processing,
    /// Certificate has been issued
    Valid,
    /// Order is invalid (failed)
    Invalid,
}

/// ACME identifier
///
/// RFC 8555 §9.7.7
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identifier {
    /// Identifier type ("dns" or "ip")
    #[serde(rename = "type")]
    pub id_type: String,
    /// Identifier value
    pub value: String,
}

/// ACME order
///
/// RFC 8555 §7.1.3
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Order {
    /// Order ID (internal)
    #[serde(skip)]
    pub id: Uuid,

    /// Account ID that owns this order
    #[serde(skip)]
    pub account_id: Uuid,

    /// Order status
    pub status: OrderStatus,

    /// Expiration time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<DateTime<Utc>>,

    /// Identifiers to be included in certificate
    pub identifiers: Vec<Identifier>,

    /// Not before time (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,

    /// Not after time (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<DateTime<Utc>>,

    /// Error (if order failed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<serde_json::Value>,

    /// Authorization URLs
    pub authorizations: Vec<String>,

    /// Finalize URL
    pub finalize: String,

    /// Certificate URL (when ready)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,

    /// Created timestamp
    #[serde(skip)]
    pub created_at: DateTime<Utc>,

    /// Updated timestamp
    #[serde(skip)]
    pub updated_at: DateTime<Utc>,
}

impl Order {
    /// Create a new pending order
    pub fn new(
        account_id: Uuid,
        identifiers: Vec<Identifier>,
        not_before: Option<DateTime<Utc>>,
        not_after: Option<DateTime<Utc>>,
    ) -> Self {
        let id = Uuid::new_v4();
        let now = Utc::now();

        // Create authorization URLs for each identifier
        let authorizations: Vec<String> = (0..identifiers.len())
            .map(|i| format!("/acme/authz/{}-{}", id, i))
            .collect();

        Self {
            id,
            account_id,
            status: OrderStatus::Pending,
            expires: Some(now + chrono::Duration::hours(24)),
            identifiers,
            not_before,
            not_after,
            error: None,
            authorizations,
            finalize: format!("/acme/order/{}/finalize", id),
            certificate: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Mark order as ready for finalization
    pub fn mark_ready(&mut self) {
        self.status = OrderStatus::Ready;
        self.updated_at = Utc::now();
    }

    /// Mark order as processing
    pub fn mark_processing(&mut self) {
        self.status = OrderStatus::Processing;
        self.updated_at = Utc::now();
    }

    /// Mark order as valid with certificate URL
    pub fn mark_valid(&mut self, certificate_url: String) {
        self.status = OrderStatus::Valid;
        self.certificate = Some(certificate_url);
        self.updated_at = Utc::now();
    }

    /// Mark order as invalid
    pub fn mark_invalid(&mut self, error: serde_json::Value) {
        self.status = OrderStatus::Invalid;
        self.error = Some(error);
        self.updated_at = Utc::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_order_creation() {
        let identifiers = vec![Identifier {
            id_type: "dns".to_string(),
            value: "example.com".to_string(),
        }];

        let order = Order::new(Uuid::new_v4(), identifiers.clone(), None, None);
        assert_eq!(order.status, OrderStatus::Pending);
        assert_eq!(order.identifiers, identifiers);
        assert_eq!(order.authorizations.len(), 1);
    }

    #[test]
    fn test_order_lifecycle() {
        let mut order = Order::new(
            Uuid::new_v4(),
            vec![Identifier {
                id_type: "dns".to_string(),
                value: "test.com".to_string(),
            }],
            None,
            None,
        );

        assert_eq!(order.status, OrderStatus::Pending);

        order.mark_ready();
        assert_eq!(order.status, OrderStatus::Ready);

        order.mark_processing();
        assert_eq!(order.status, OrderStatus::Processing);

        order.mark_valid("/acme/cert/123".to_string());
        assert_eq!(order.status, OrderStatus::Valid);
        assert!(order.certificate.is_some());
    }
}
