//! ACME (Automated Certificate Management Environment) Responder
//!
//! RFC 8555: Automatic Certificate Management Environment (ACME)
//! NIST 800-53: SC-12 - Automated certificate lifecycle management

pub mod account;
pub mod authorization;
pub mod challenge;
pub mod error;
pub mod jws;
pub mod order;
pub mod rest;
pub mod validation;

pub use account::{Account, AccountStatus};
pub use authorization::{Authorization, AuthorizationStatus};
pub use challenge::{Challenge, ChallengeStatus, ChallengeType};
pub use error::{Error, Result};
pub use order::{Order, OrderStatus};
pub use rest::create_router;
pub use validation::{Dns01Validator, Http01Validator, TlsAlpn01Validator};
