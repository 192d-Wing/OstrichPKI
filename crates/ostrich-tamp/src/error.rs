//! Error types for the Trust Anchor Management Protocol implementation.
//!
//! Every protocol-level failure maps to a RFC 5934 §5 [`StatusCode`] so that a
//! `TAMPError` (or a confirm carrying the code) can be emitted to the peer
//! without losing fidelity.
//!
//! COMPLIANCE MAPPING:
//! - RFC 5934 §4.11 - TAMP Error message
//! - NIST 800-53: SI-11 (error handling) - fail secure, deny on error
//! - NIST 800-53: AU-3 - outcome captured via StatusCode

use crate::statuscode::StatusCode;

/// Result alias for TAMP operations.
pub type Result<T> = std::result::Result<T, Error>;

/// A TAMP processing error, carrying the [`StatusCode`] that should be reported
/// to the peer.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// DER decode/encode failure (maps to `decodeFailure`).
    #[error("ASN.1 codec error: {0}")]
    Asn1(#[from] der::Error),

    /// CMS structure could not be parsed or was malformed.
    #[error("CMS error: {0}")]
    Cms(String),

    /// The message signature could not be verified against a resident TA.
    #[error("signature verification failed: {0}")]
    SignatureFailure(String),

    /// No resident trust anchor matched the signer (by subjectKeyIdentifier).
    #[error("no trust anchor found for signer")]
    NoTrustAnchor,

    /// The signer is resident but not authorized for this operation.
    #[error("signer not authorized for this operation")]
    NotAuthorized,

    /// Sequence number was not strictly greater than the stored baseline
    /// (replay protection; RFC 5934 §4.1).
    #[error("sequence number check failed (replay): {0}")]
    SeqNumFailure(String),

    /// The message target did not match this responder.
    #[error("incorrect target")]
    IncorrectTarget,

    /// A trust anchor add/change/remove could not be applied as requested.
    #[error("trust anchor update rejected: {0}")]
    TrustAnchorUpdate(String),

    /// Cryptographic provider error (signing, hashing).
    #[error("crypto provider error: {0}")]
    Crypto(#[from] ostrich_crypto::Error),

    /// Persistence error.
    #[error("storage error: {0}")]
    Storage(String),

    /// Catch-all for conditions not otherwise modeled.
    #[error("{0}")]
    Other(String),
}

impl Error {
    /// The RFC 5934 status code corresponding to this error.
    ///
    /// RFC 5934 §5 - StatusCode mapping for confirm/error messages.
    pub fn status_code(&self) -> StatusCode {
        match self {
            Error::Asn1(_) => StatusCode::DecodeFailure,
            Error::Cms(_) => StatusCode::CmsError,
            Error::SignatureFailure(_) => StatusCode::SignatureFailure,
            Error::NoTrustAnchor => StatusCode::NoTrustAnchor,
            Error::NotAuthorized => StatusCode::NotAuthorized,
            Error::SeqNumFailure(_) => StatusCode::SeqNumFailure,
            Error::IncorrectTarget => StatusCode::IncorrectTarget,
            Error::TrustAnchorUpdate(_) => StatusCode::ImproperTaChange,
            Error::Crypto(_) => StatusCode::SignatureFailure,
            Error::Storage(_) => StatusCode::InsufficientMemory,
            Error::Other(_) => StatusCode::Other,
        }
    }
}

impl From<ostrich_db::Error> for Error {
    fn from(e: ostrich_db::Error) -> Self {
        Error::Storage(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_maps_to_status_code() {
        assert_eq!(
            Error::NoTrustAnchor.status_code(),
            StatusCode::NoTrustAnchor
        );
        assert_eq!(
            Error::SeqNumFailure("replay".into()).status_code(),
            StatusCode::SeqNumFailure
        );
        assert_eq!(
            Error::NotAuthorized.status_code(),
            StatusCode::NotAuthorized
        );
    }
}
