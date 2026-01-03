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
