//! KRA database models
//!
//! Key Recovery Authority models

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

/// Escrowed Key
///
/// Private keys wrapped and stored by KRA
#[derive(Debug, Clone, FromRow)]
pub struct EscrowedKey {
    pub id: Uuid,
    pub certificate_id: Uuid,
    pub wrapped_key: Vec<u8>,
    pub wrapping_key_id: Uuid,
    pub key_type: String,
    pub algorithm: String,
    pub escrow_time: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Recovery Agent
///
/// Authorized agents for M-of-N key recovery
#[derive(Debug, Clone, FromRow)]
pub struct RecoveryAgent {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub public_key_der: Vec<u8>,
    pub active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Recovery Request
///
/// Tracks key recovery requests
#[derive(Debug, Clone, FromRow)]
pub struct RecoveryRequest {
    pub id: Uuid,
    pub escrowed_key_id: Uuid,
    pub requestor: String,
    pub justification: String,
    pub status: String,
    pub required_shares: i32,
    pub total_agents: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Recovery Share
///
/// Encrypted shares for M-of-N recovery
#[derive(Debug, Clone, FromRow)]
pub struct RecoveryShare {
    pub id: Uuid,
    pub recovery_request_id: Uuid,
    pub agent_id: Uuid,
    pub encrypted_share: Vec<u8>,
    pub submitted_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escrowed_key_structure() {
        let now = Utc::now();
        let escrowed = EscrowedKey {
            id: Uuid::new_v4(),
            certificate_id: Uuid::new_v4(),
            wrapped_key: vec![0x30, 0x82, 0x01, 0x00, 0xAE, 0x12],
            wrapping_key_id: Uuid::new_v4(),
            key_type: "RSA".to_string(),
            algorithm: "RSA-OAEP-256".to_string(),
            escrow_time: now,
            created_at: now,
        };

        assert_eq!(escrowed.key_type, "RSA");
        assert_eq!(escrowed.algorithm, "RSA-OAEP-256");
        assert!(!escrowed.wrapped_key.is_empty());
    }

    #[test]
    fn test_escrowed_key_ec() {
        let now = Utc::now();
        let escrowed = EscrowedKey {
            id: Uuid::new_v4(),
            certificate_id: Uuid::new_v4(),
            wrapped_key: vec![0x04, 0x30, 0x45],
            wrapping_key_id: Uuid::new_v4(),
            key_type: "EC".to_string(),
            algorithm: "ECDH-P256".to_string(),
            escrow_time: now,
            created_at: now,
        };

        assert_eq!(escrowed.key_type, "EC");
        assert_eq!(escrowed.algorithm, "ECDH-P256");
    }

    #[test]
    fn test_recovery_agent_structure() {
        let now = Utc::now();
        let agent = RecoveryAgent {
            id: Uuid::new_v4(),
            name: "Security Officer 1".to_string(),
            email: "secoff1@example.com".to_string(),
            public_key_der: vec![0x30, 0x82, 0x01, 0x22],
            active: true,
            created_at: now,
            updated_at: now,
        };

        assert_eq!(agent.name, "Security Officer 1");
        assert!(agent.active);
        assert!(!agent.public_key_der.is_empty());
    }

    #[test]
    fn test_recovery_agent_inactive() {
        let now = Utc::now();
        let agent = RecoveryAgent {
            id: Uuid::new_v4(),
            name: "Former Officer".to_string(),
            email: "former@example.com".to_string(),
            public_key_der: vec![0x30, 0x82],
            active: false,
            created_at: now,
            updated_at: now,
        };

        assert!(!agent.active);
    }

    #[test]
    fn test_recovery_request_structure() {
        let now = Utc::now();
        let request = RecoveryRequest {
            id: Uuid::new_v4(),
            escrowed_key_id: Uuid::new_v4(),
            requestor: "admin@example.com".to_string(),
            justification: "Emergency key recovery for lost device".to_string(),
            status: "pending".to_string(),
            required_shares: 3,
            total_agents: 5,
            created_at: now,
            updated_at: now,
        };

        assert_eq!(request.requestor, "admin@example.com");
        assert_eq!(request.status, "pending");
        assert_eq!(request.required_shares, 3);
        assert_eq!(request.total_agents, 5);
        // M-of-N: 3 of 5 required
        assert!(request.required_shares <= request.total_agents);
    }

    #[test]
    fn test_recovery_request_approved() {
        let now = Utc::now();
        let request = RecoveryRequest {
            id: Uuid::new_v4(),
            escrowed_key_id: Uuid::new_v4(),
            requestor: "manager@example.com".to_string(),
            justification: "Scheduled key rotation".to_string(),
            status: "approved".to_string(),
            required_shares: 2,
            total_agents: 3,
            created_at: now,
            updated_at: now,
        };

        assert_eq!(request.status, "approved");
        assert_eq!(request.required_shares, 2);
    }

    #[test]
    fn test_recovery_share_structure() {
        let now = Utc::now();
        let share = RecoveryShare {
            id: Uuid::new_v4(),
            recovery_request_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            encrypted_share: vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE],
            submitted_at: Some(now),
        };

        assert!(!share.encrypted_share.is_empty());
        assert!(share.submitted_at.is_some());
    }

    #[test]
    fn test_recovery_share_pending() {
        let share = RecoveryShare {
            id: Uuid::new_v4(),
            recovery_request_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            encrypted_share: vec![],
            submitted_at: None,
        };

        // Share allocated but not yet submitted
        assert!(share.encrypted_share.is_empty());
        assert!(share.submitted_at.is_none());
    }

    #[test]
    fn test_m_of_n_threshold_validity() {
        // Test various M-of-N configurations
        let valid_configs = [(2, 3), (3, 5), (5, 9), (1, 2)];

        for (required, total) in valid_configs {
            let now = Utc::now();
            let request = RecoveryRequest {
                id: Uuid::new_v4(),
                escrowed_key_id: Uuid::new_v4(),
                requestor: "test".to_string(),
                justification: format!("{}-of-{} test", required, total),
                status: "pending".to_string(),
                required_shares: required,
                total_agents: total,
                created_at: now,
                updated_at: now,
            };

            assert!(
                request.required_shares <= request.total_agents,
                "M ({}) should be <= N ({})",
                required,
                total
            );
            assert!(request.required_shares > 0, "M should be positive");
        }
    }
}
