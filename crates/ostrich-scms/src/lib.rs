//! SCMS (Smartcard Management System)
//!
//! Token lifecycle management, PKCS#11 operations, and inventory tracking
//! NIST 800-53: IA-2, IA-5 - Multi-factor authentication with smartcards

pub mod error;
pub mod rest;
pub mod token;

pub use error::{Error, Result};
pub use rest::create_router;
pub use token::{Token, TokenEvent, TokenKey, TokenModel, TokenStatus};
