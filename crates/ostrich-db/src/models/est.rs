//! EST database models
//!
//! RFC 7030: Enrollment over Secure Transport

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

/// EST Enrollment
///
/// RFC 7030 enrollment records
#[derive(Debug, Clone, FromRow)]
pub struct EstEnrollment {
    pub id: Uuid,
    pub client_identifier: String,
    pub enrollment_type: String,
    pub csr_der: Vec<u8>,
    pub certificate_id: Option<Uuid>,
    pub status: String,
    /// Certificate profile used for this enrollment
    pub profile_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// EST Authorized Client
///
/// Clients authorized for EST enrollment
#[derive(Debug, Clone, FromRow)]
pub struct EstClient {
    pub id: Uuid,
    pub client_identifier: String,
    pub client_certificate_der: Vec<u8>,
    pub authorized_profiles: Vec<Uuid>,
    pub active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_est_enrollment_structure() {
        let now = Utc::now();
        let enrollment = EstEnrollment {
            id: Uuid::new_v4(),
            client_identifier: "client-device-001".to_string(),
            enrollment_type: "simpleenroll".to_string(),
            csr_der: vec![0x30, 0x82, 0x01, 0x00, 0x30, 0x81],
            certificate_id: None,
            status: "pending".to_string(),
            profile_name: Some("tls-server".to_string()),
            created_at: now,
            updated_at: now,
        };

        assert_eq!(enrollment.client_identifier, "client-device-001");
        assert_eq!(enrollment.enrollment_type, "simpleenroll");
        assert_eq!(enrollment.status, "pending");
        assert!(enrollment.certificate_id.is_none());
        assert_eq!(enrollment.profile_name, Some("tls-server".to_string()));
    }

    #[test]
    fn test_est_enrollment_completed() {
        let now = Utc::now();
        let cert_id = Uuid::new_v4();
        let enrollment = EstEnrollment {
            id: Uuid::new_v4(),
            client_identifier: "client-device-002".to_string(),
            enrollment_type: "simplereenroll".to_string(),
            csr_der: vec![0x30, 0x82, 0x02, 0x00],
            certificate_id: Some(cert_id),
            status: "completed".to_string(),
            profile_name: Some("tls-client".to_string()),
            created_at: now,
            updated_at: now,
        };

        assert_eq!(enrollment.status, "completed");
        assert_eq!(enrollment.certificate_id, Some(cert_id));
        assert_eq!(enrollment.enrollment_type, "simplereenroll");
    }

    #[test]
    fn test_est_client_structure() {
        let now = Utc::now();
        let profile1 = Uuid::new_v4();
        let profile2 = Uuid::new_v4();
        let client = EstClient {
            id: Uuid::new_v4(),
            client_identifier: "device-serial-123".to_string(),
            client_certificate_der: vec![0x30, 0x82, 0x03, 0x00],
            authorized_profiles: vec![profile1, profile2],
            active: true,
            created_at: now,
            updated_at: now,
        };

        assert_eq!(client.client_identifier, "device-serial-123");
        assert!(client.active);
        assert_eq!(client.authorized_profiles.len(), 2);
        assert!(client.authorized_profiles.contains(&profile1));
        assert!(client.authorized_profiles.contains(&profile2));
    }

    #[test]
    fn test_est_client_inactive() {
        let now = Utc::now();
        let client = EstClient {
            id: Uuid::new_v4(),
            client_identifier: "revoked-device".to_string(),
            client_certificate_der: vec![0x30, 0x82, 0x01, 0x00],
            authorized_profiles: vec![],
            active: false,
            created_at: now,
            updated_at: now,
        };

        assert!(!client.active);
        assert!(client.authorized_profiles.is_empty());
    }

    #[test]
    fn test_est_enrollment_types() {
        let now = Utc::now();

        // Test various enrollment types per RFC 7030
        for enrollment_type in &["simpleenroll", "simplereenroll", "serverkeygen", "fullcmc"] {
            let enrollment = EstEnrollment {
                id: Uuid::new_v4(),
                client_identifier: format!("client-{}", enrollment_type),
                enrollment_type: enrollment_type.to_string(),
                csr_der: vec![0x30],
                certificate_id: None,
                status: "pending".to_string(),
                profile_name: None,
                created_at: now,
                updated_at: now,
            };
            assert_eq!(&enrollment.enrollment_type, *enrollment_type);
        }
    }
}
