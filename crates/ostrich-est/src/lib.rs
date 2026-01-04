//! EST (Enrollment over Secure Transport) Server
//!
//! RFC 7030: Enrollment over Secure Transport
//! NIST 800-53: SC-12 - Certificate enrollment and renewal

pub mod ca_integration;
pub mod enrollment;
pub mod error;
pub mod mtls;
pub mod rest;

pub use ca_integration::EstCaClient;
pub use enrollment::{
    CsrAttributes, Enrollment, EnrollmentRequest, EnrollmentResponse, EnrollmentStatus,
};
pub use error::{Error, Result};
pub use mtls::{ClientCertExtractor, MtlsClientCert, validate_client};
pub use rest::create_router;
