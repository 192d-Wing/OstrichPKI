//! OCSP Responder service
//!
//! RFC 6960: X.509 Internet Public Key Infrastructure Online Certificate Status Protocol
//! NIST 800-53: AU-2, AU-3 - Audit events and content

pub mod error;
pub mod request;
pub mod responder;
pub mod response;
pub mod rest;

pub use error::{Error, Result};
pub use request::OcspRequest;
pub use responder::OcspResponder;
pub use response::{CertStatus, OcspResponse, ResponseStatus, SingleResponse};
pub use rest::create_router;
