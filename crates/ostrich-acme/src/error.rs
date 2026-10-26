//! ACME error types
//!
//! RFC 8555 §6.7: Error responses

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Account does not exist")]
    AccountDoesNotExist,

    #[error("Already revoked")]
    AlreadyRevoked,

    #[error("Bad CSR: {0}")]
    BadCsr(String),

    #[error("Bad nonce")]
    BadNonce,

    #[error("Bad public key")]
    BadPublicKey,

    #[error("Bad revocation reason")]
    BadRevocationReason,

    #[error("Bad signature algorithm")]
    BadSignatureAlgorithm,

    #[error("CAA error: {0}")]
    Caa(String),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("DNS error: {0}")]
    Dns(String),

    #[error("External account required")]
    ExternalAccountRequired,

    #[error("Incorrect response: {0}")]
    IncorrectResponse(String),

    #[error("Invalid contact: {0}")]
    InvalidContact(String),

    #[error("Malformed request: {0}")]
    Malformed(String),

    #[error("Order not ready")]
    OrderNotReady,

    #[error("Rate limited")]
    RateLimited,

    #[error("Rejected identifier: {0}")]
    RejectedIdentifier(String),

    #[error("Server internal error: {0}")]
    ServerInternal(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Unsupported contact: {0}")]
    UnsupportedContact(String),

    #[error("Unsupported identifier: {0}")]
    UnsupportedIdentifier(String),

    #[error("User action required: {0}")]
    UserActionRequired(String),

    #[error("Resource not found")]
    NotFound,

    #[error("Database error: {0}")]
    Database(#[from] ostrich_db::Error),

    #[error("Common error: {0}")]
    Common(#[from] ostrich_common::Error),
}

/// ACME error response
///
/// RFC 8555 §6.7
#[derive(Debug, Serialize, Deserialize)]
pub struct AcmeError {
    /// Error type (URN)
    #[serde(rename = "type")]
    pub error_type: String,

    /// Human-readable error description
    pub detail: String,

    /// HTTP status code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,

    /// Sub-problems
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subproblems: Option<Vec<AcmeError>>,
}

impl Error {
    /// Get ACME error type URN
    ///
    /// Every arm returns a type registered in RFC 8555 §6.7 (checked by the
    /// `every_error_type_is_registered` test). Challenge failures use the
    /// specific registered types (`connection`, `dns`, `tls`,
    /// `incorrectResponse`, ...); there is no generic "challenge failed" type.
    // COMPLIANCE MAPPING:
    // - RFC 8555 §6.7 - only registered `urn:ietf:params:acme:error:` types
    pub fn error_type(&self) -> &'static str {
        match self {
            Self::AccountDoesNotExist => "urn:ietf:params:acme:error:accountDoesNotExist",
            Self::AlreadyRevoked => "urn:ietf:params:acme:error:alreadyRevoked",
            Self::BadCsr(_) => "urn:ietf:params:acme:error:badCSR",
            Self::BadNonce => "urn:ietf:params:acme:error:badNonce",
            Self::BadPublicKey => "urn:ietf:params:acme:error:badPublicKey",
            Self::BadRevocationReason => "urn:ietf:params:acme:error:badRevocationReason",
            Self::BadSignatureAlgorithm => "urn:ietf:params:acme:error:badSignatureAlgorithm",
            Self::Caa(_) => "urn:ietf:params:acme:error:caa",
            Self::Connection(_) => "urn:ietf:params:acme:error:connection",
            Self::Dns(_) => "urn:ietf:params:acme:error:dns",
            Self::ExternalAccountRequired => "urn:ietf:params:acme:error:externalAccountRequired",
            Self::IncorrectResponse(_) => "urn:ietf:params:acme:error:incorrectResponse",
            Self::InvalidContact(_) => "urn:ietf:params:acme:error:invalidContact",
            Self::Malformed(_) => "urn:ietf:params:acme:error:malformed",
            Self::OrderNotReady => "urn:ietf:params:acme:error:orderNotReady",
            Self::RateLimited => "urn:ietf:params:acme:error:rateLimited",
            Self::RejectedIdentifier(_) => "urn:ietf:params:acme:error:rejectedIdentifier",
            Self::ServerInternal(_) => "urn:ietf:params:acme:error:serverInternal",
            Self::Tls(_) => "urn:ietf:params:acme:error:tls",
            Self::Unauthorized(_) => "urn:ietf:params:acme:error:unauthorized",
            Self::UnsupportedContact(_) => "urn:ietf:params:acme:error:unsupportedContact",
            Self::UnsupportedIdentifier(_) => "urn:ietf:params:acme:error:unsupportedIdentifier",
            Self::UserActionRequired(_) => "urn:ietf:params:acme:error:userActionRequired",
            Self::NotFound => "urn:ietf:params:acme:error:serverInternal",
            Self::Database(_) | Self::Common(_) => "urn:ietf:params:acme:error:serverInternal",
        }
    }

    /// Get HTTP status code
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::AccountDoesNotExist => StatusCode::BAD_REQUEST,
            Self::AlreadyRevoked => StatusCode::BAD_REQUEST,
            Self::BadCsr(_) => StatusCode::BAD_REQUEST,
            Self::BadNonce => StatusCode::BAD_REQUEST,
            Self::BadPublicKey => StatusCode::BAD_REQUEST,
            Self::BadRevocationReason => StatusCode::BAD_REQUEST,
            Self::BadSignatureAlgorithm => StatusCode::BAD_REQUEST,
            Self::Caa(_) => StatusCode::FORBIDDEN,
            Self::Connection(_) => StatusCode::BAD_REQUEST,
            Self::Dns(_) => StatusCode::BAD_REQUEST,
            Self::ExternalAccountRequired => StatusCode::FORBIDDEN,
            Self::IncorrectResponse(_) => StatusCode::BAD_REQUEST,
            Self::InvalidContact(_) => StatusCode::BAD_REQUEST,
            Self::Malformed(_) => StatusCode::BAD_REQUEST,
            Self::OrderNotReady => StatusCode::FORBIDDEN,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::RejectedIdentifier(_) => StatusCode::BAD_REQUEST,
            Self::ServerInternal(_) | Self::Database(_) | Self::Common(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::Tls(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::UnsupportedContact(_) => StatusCode::BAD_REQUEST,
            Self::UnsupportedIdentifier(_) => StatusCode::BAD_REQUEST,
            Self::UserActionRequired(_) => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
        }
    }
}

impl Error {
    /// Whether this error is internal-class (a 500 whose cause must not leak to
    /// the client). Raw DB/SQLx messages and wrapped internal errors reveal
    /// backend internals (schema, constraint names, source lines).
    fn is_internal(&self) -> bool {
        matches!(
            self,
            Self::Database(_) | Self::Common(_) | Self::ServerInternal(_)
        )
    }

    /// The problem-document `detail` safe to return to the ACME client.
    ///
    /// Internal-class errors collapse to a generic message (the real cause is
    /// logged server-side by [`IntoResponse`]); client-class errors (malformed,
    /// unauthorized, badNonce, ...) keep their descriptive detail — those are
    /// actionable and reveal no internals.
    /// COMPLIANCE: NIST 800-53 SI-11 (error handling), SI-10; RFC 8555 §6.7.
    pub(crate) fn client_detail(&self) -> String {
        if self.is_internal() {
            "Internal server error".to_string()
        } else {
            self.to_string()
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        // Log the full cause server-side for internal errors; only a generic
        // detail is returned to the client (see `client_detail`).
        if self.is_internal() {
            tracing::error!(error = %self, "ACME internal error (detail withheld from client)");
        }

        let acme_error = AcmeError {
            error_type: self.error_type().to_string(),
            detail: self.client_detail(),
            status: Some(self.status_code().as_u16()),
            subproblems: None,
        };

        (self.status_code(), Json(acme_error)).into_response()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn internal_errors_do_not_leak_detail() {
        // A raw DB error (constraint names, source lines, SQLx text) must never
        // appear in the client-facing problem document — the exact leak seen as
        // "duplicate key value violates unique constraint ... at line 666".
        let db = Error::Database(ostrich_db::Error::ConstraintViolation(
            "duplicate key value violates unique constraint \
             \"acme_accounts_jwk_thumbprint_key\""
                .to_string(),
        ));
        assert!(db.is_internal());
        assert_eq!(db.client_detail(), "Internal server error");
        assert!(!db.client_detail().contains("constraint"));

        // ServerInternal messages are also internal-class.
        let si = Error::ServerInternal("Failed to serialize JWK: oops".to_string());
        assert_eq!(si.client_detail(), "Internal server error");

        // ...but the problem type/status are still correct for the client.
        assert_eq!(db.error_type(), "urn:ietf:params:acme:error:serverInternal");
        assert_eq!(db.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// The `urn:ietf:params:acme:error:` types registered by RFC 8555 §6.7.
    pub(crate) const RFC8555_REGISTERED_TYPES: &[&str] = &[
        "accountDoesNotExist",
        "alreadyRevoked",
        "badCSR",
        "badNonce",
        "badPublicKey",
        "badRevocationReason",
        "badSignatureAlgorithm",
        "caa",
        "compound",
        "connection",
        "dns",
        "externalAccountRequired",
        "incorrectResponse",
        "invalidContact",
        "malformed",
        "orderNotReady",
        "rateLimited",
        "rejectedIdentifier",
        "serverInternal",
        "tls",
        "unauthorized",
        "unsupportedContact",
        "unsupportedIdentifier",
        "userActionRequired",
    ];

    /// One value of every `Error` variant. The `match` has no wildcard arm, so
    /// adding a variant fails to compile until it is listed here too.
    pub(crate) fn one_of_every_variant() -> Vec<Error> {
        let s = || "x".to_string();
        let all = vec![
            Error::AccountDoesNotExist,
            Error::AlreadyRevoked,
            Error::BadCsr(s()),
            Error::BadNonce,
            Error::BadPublicKey,
            Error::BadRevocationReason,
            Error::BadSignatureAlgorithm,
            Error::Caa(s()),
            Error::Connection(s()),
            Error::Dns(s()),
            Error::ExternalAccountRequired,
            Error::IncorrectResponse(s()),
            Error::InvalidContact(s()),
            Error::Malformed(s()),
            Error::OrderNotReady,
            Error::RateLimited,
            Error::RejectedIdentifier(s()),
            Error::ServerInternal(s()),
            Error::Tls(s()),
            Error::Unauthorized(s()),
            Error::UnsupportedContact(s()),
            Error::UnsupportedIdentifier(s()),
            Error::UserActionRequired(s()),
            Error::NotFound,
            Error::Database(ostrich_db::Error::ConstraintViolation(s())),
            Error::Common(ostrich_common::Error::Config(s())),
        ];
        for e in &all {
            match e {
                Error::AccountDoesNotExist
                | Error::AlreadyRevoked
                | Error::BadCsr(_)
                | Error::BadNonce
                | Error::BadPublicKey
                | Error::BadRevocationReason
                | Error::BadSignatureAlgorithm
                | Error::Caa(_)
                | Error::Connection(_)
                | Error::Dns(_)
                | Error::ExternalAccountRequired
                | Error::IncorrectResponse(_)
                | Error::InvalidContact(_)
                | Error::Malformed(_)
                | Error::OrderNotReady
                | Error::RateLimited
                | Error::RejectedIdentifier(_)
                | Error::ServerInternal(_)
                | Error::Tls(_)
                | Error::Unauthorized(_)
                | Error::UnsupportedContact(_)
                | Error::UnsupportedIdentifier(_)
                | Error::UserActionRequired(_)
                | Error::NotFound
                | Error::Database(_)
                | Error::Common(_) => {}
            }
        }
        all
    }

    /// RFC-013: no variant maps to a problem type outside RFC 8555 §6.7 (the
    /// removed `ChallengeValidation` variant emitted `challengeFailed`).
    #[test]
    fn every_error_type_is_registered() {
        let all = one_of_every_variant();
        assert_eq!(all.len(), 26);
        for e in &all {
            let t = e.error_type();
            let name = t
                .strip_prefix("urn:ietf:params:acme:error:")
                .unwrap_or_else(|| panic!("{t} lacks the ACME error namespace"));
            assert!(
                RFC8555_REGISTERED_TYPES.contains(&name),
                "{e:?} maps to unregistered type {t}"
            );
        }
    }

    #[test]
    fn client_errors_keep_descriptive_detail() {
        // Client-class errors are safe and useful to return verbatim.
        let malformed = Error::Malformed("JWK required for new-account".to_string());
        assert!(!malformed.is_internal());
        assert_eq!(
            malformed.client_detail(),
            "Malformed request: JWK required for new-account"
        );
    }
}
