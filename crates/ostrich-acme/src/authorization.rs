//! ACME authorization objects
//!
//! RFC 8555 §7.1.4: Authorization objects

use crate::challenge::Challenge;
use crate::order::Identifier;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Authorization status
///
/// RFC 8555 §7.1.6
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AuthorizationStatus {
    /// Pending challenge completion
    Pending,
    /// Authorization is valid
    Valid,
    /// Authorization is invalid
    Invalid,
    /// Authorization has been deactivated
    Deactivated,
    /// Authorization has expired
    Expired,
    /// Authorization is being revoked
    Revoked,
}

/// Authorization object
///
/// RFC 8555 §7.1.4
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Authorization {
    /// Authorization ID (internal)
    #[serde(skip)]
    pub id: Uuid,

    /// Order ID this authorization belongs to
    #[serde(skip)]
    pub order_id: Uuid,

    /// Authorization status
    pub status: AuthorizationStatus,

    /// Expiration time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<DateTime<Utc>>,

    /// Identifier being authorized
    pub identifier: Identifier,

    /// Challenges for this authorization
    pub challenges: Vec<Challenge>,

    /// Wildcard indicator
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wildcard: Option<bool>,

    /// Created timestamp
    #[serde(skip)]
    pub created_at: DateTime<Utc>,

    /// Updated timestamp
    #[serde(skip)]
    pub updated_at: DateTime<Utc>,
}

impl Authorization {
    /// Create a new pending authorization
    pub fn new(order_id: Uuid, identifier: Identifier, challenges: Vec<Challenge>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            order_id,
            status: AuthorizationStatus::Pending,
            expires: Some(now + chrono::Duration::hours(24)),
            identifier,
            challenges,
            wildcard: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Mark authorization as valid
    pub fn mark_valid(&mut self) {
        self.status = AuthorizationStatus::Valid;
        self.updated_at = Utc::now();
    }

    /// Mark authorization as invalid
    pub fn mark_invalid(&mut self) {
        self.status = AuthorizationStatus::Invalid;
        self.updated_at = Utc::now();
    }

    /// Deactivate authorization
    pub fn deactivate(&mut self) {
        self.status = AuthorizationStatus::Deactivated;
        self.updated_at = Utc::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge::ChallengeType;

    #[test]
    fn test_authorization_creation() {
        let identifier = Identifier {
            id_type: "dns".to_string(),
            value: "example.com".to_string(),
        };

        let challenge = Challenge::new(
            Uuid::new_v4(),
            ChallengeType::Http01,
            "test-token".to_string(),
        );

        let authz = Authorization::new(Uuid::new_v4(), identifier.clone(), vec![challenge]);

        assert_eq!(authz.status, AuthorizationStatus::Pending);
        assert_eq!(authz.identifier, identifier);
        assert_eq!(authz.challenges.len(), 1);
    }

    #[test]
    fn test_authorization_lifecycle() {
        let mut authz = Authorization::new(
            Uuid::new_v4(),
            Identifier {
                id_type: "dns".to_string(),
                value: "test.com".to_string(),
            },
            vec![],
        );

        assert_eq!(authz.status, AuthorizationStatus::Pending);

        authz.mark_valid();
        assert_eq!(authz.status, AuthorizationStatus::Valid);

        authz.deactivate();
        assert_eq!(authz.status, AuthorizationStatus::Deactivated);
    }
}
