//! REST API for the TAMP manager (RFC 5934).
//!
//! Exposes operationally useful manager functions over HTTPS: issuing signed
//! TAMP messages (status query, community update) and ingesting the signed
//! confirmations / status responses returned by targets, plus reading the
//! authoritative trust-anchor store. The full set of `TargetIdentifier` forms
//! and trust-anchor edits is available programmatically via [`crate::TampManager`];
//! this HTTP surface uses the URI target form for convenience.
//!
//! Authentication is by bearer session (mirroring the CA service); each
//! mutating endpoint requires `Permission::ModifyConfig` and each read requires
//! `Permission::ViewConfig`, mapping trust-anchor management to NIAP FMT_SMF.1.
//!
//! COMPLIANCE MAPPING:
//! - RFC 5934 §4 - TAMP message exchanges
//! - NIST 800-53: AC-3 (access enforcement via RBAC), SC-8 (TLS), AU-2 (audit)
//! - NIAP PP-CA: FMT_SMF.1 (trust anchor management), FTP_ITC.1 (TLS channel)

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use der::asn1::Ia5String;
use ostrich_common::auth::{AuthLayer, AuthProvider, AuthzLayer, Permission, RbacPolicy};
use ostrich_crypto::{Algorithm, CryptoProvider, KeyHandle};
use serde::{Deserialize, Serialize};

use crate::asn1::TargetIdentifier;
use crate::error::Error;
use crate::manager::{SignerContext, TampManager, TrustAnchorEdit};

/// Signing identity (apex/management key) used to protect outbound messages.
pub struct TampSigner {
    /// Crypto provider holding the signing key (HSM-backed in production).
    pub provider: Arc<dyn CryptoProvider>,
    /// Handle to the signing key.
    pub key: KeyHandle,
    /// subjectKeyIdentifier of the signing trust anchor.
    pub ski: Vec<u8>,
    /// Signature algorithm matching the key.
    pub algorithm: Algorithm,
}

impl TampSigner {
    fn context(&self) -> SignerContext<'_> {
        SignerContext {
            provider: self.provider.as_ref(),
            key: &self.key,
            ski: self.ski.clone(),
            algorithm: self.algorithm,
        }
    }
}

/// Shared state for the TAMP REST service.
#[derive(Clone)]
pub struct TampState {
    /// Protocol manager over the authoritative store + audit sink.
    pub manager: Arc<TampManager>,
    /// Outbound signing identity.
    pub signer: Arc<TampSigner>,
    /// Authentication provider (bearer session).
    pub auth_provider: Arc<dyn AuthProvider>,
    /// RBAC policy for per-route authorization.
    pub rbac_policy: Arc<RbacPolicy>,
}

/// Build a URI-form `TargetIdentifier` (RFC 5934 §4.1).
fn target_from_uri(uri: &str) -> Result<TargetIdentifier, Error> {
    let ia5 = Ia5String::new(uri)
        .map_err(|e| Error::Other(format!("target URI is not a valid IA5String: {e}")))?;
    Ok(TargetIdentifier::Uri(ia5))
}

/// Map a protocol error to an HTTP response, preserving the RFC 5934 status code.
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = match &self {
            Error::Asn1(_) | Error::TrustAnchorUpdate(_) | Error::Other(_) => {
                StatusCode::BAD_REQUEST
            }
            Error::SignatureFailure(_)
            | Error::NoTrustAnchor
            | Error::NotAuthorized
            | Error::SeqNumFailure(_)
            | Error::IncorrectTarget
            | Error::Cms(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Error::Crypto(_) | Error::Storage(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let body = Json(serde_json::json!({
            "error": self.to_string(),
            "status_code": self.status_code().as_str(),
        }));
        (status, body).into_response()
    }
}

// ---------------------------------------------------------------------------
// Request / response bodies
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct StatusQueryRequest {
    /// URI identifying the target module(s).
    pub target_uri: String,
    /// Operator-facing label for the target.
    pub label: String,
    /// Request a terse (key-ids only) response. Defaults to verbose.
    #[serde(default)]
    pub terse: bool,
}

#[derive(Debug, Serialize)]
pub struct IssuedMessageResponse {
    pub content_type: String,
    pub message_name: String,
    pub seq_num: u64,
    /// Base64 DER CMS `ContentInfo` envelope to transmit to the target.
    pub envelope_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct CommunityUpdateRequest {
    pub target_uri: String,
    pub label: String,
    /// Community OIDs (dotted strings) to add.
    #[serde(default)]
    pub add: Vec<String>,
    /// Community OIDs (dotted strings) to remove.
    #[serde(default)]
    pub remove: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct TrustAnchorUpdateRequest {
    pub target_uri: String,
    pub label: String,
    /// Base64 DER `TrustAnchorChoice` values to add.
    #[serde(default)]
    pub add: Vec<String>,
    /// Base64 DER SubjectPublicKeyInfo values to remove.
    #[serde(default)]
    pub remove: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct IngestRequest {
    pub target_uri: String,
    pub label: String,
    /// Base64 DER CMS `ContentInfo` received from the target. The verifying key
    /// is resolved from the target's registered signers by SKI, not supplied here.
    pub envelope_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterSignerRequest {
    pub target_uri: String,
    pub label: String,
    /// Base64 subjectKeyIdentifier (SKI) of the target's response-signing key.
    pub signer_ski_b64: String,
    /// Base64 DER SubjectPublicKeyInfo used to verify the target's responses.
    pub signer_spki_b64: String,
    /// Optional operator description.
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct IngestResponse {
    pub content_type: String,
    pub message_name: String,
    pub seq_num: Option<u64>,
    pub status_codes: Vec<String>,
    pub signer_ski_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct ListTrustAnchorsRequest {
    pub target_uri: String,
    pub label: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn ready() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ready" }))
}

async fn issue_status_query(
    State(state): State<TampState>,
    Json(req): Json<StatusQueryRequest>,
) -> Result<Json<IssuedMessageResponse>, Error> {
    let target = target_from_uri(&req.target_uri)?;
    let signer = state.signer.context();
    let issued = state
        .manager
        .issue_status_query(&target, &req.label, &signer, req.terse)
        .await?;
    Ok(Json(issued_to_response(issued)))
}

async fn issue_community_update(
    State(state): State<TampState>,
    Json(req): Json<CommunityUpdateRequest>,
) -> Result<Json<IssuedMessageResponse>, Error> {
    let target = target_from_uri(&req.target_uri)?;
    let add = parse_oids(&req.add)?;
    let remove = parse_oids(&req.remove)?;
    let signer = state.signer.context();
    let issued = state
        .manager
        .issue_community_update(&target, &req.label, &signer, add, remove)
        .await?;
    Ok(Json(issued_to_response(issued)))
}

async fn issue_trust_anchor_update(
    State(state): State<TampState>,
    Json(req): Json<TrustAnchorUpdateRequest>,
) -> Result<Json<IssuedMessageResponse>, Error> {
    use der::Decode;
    let target = target_from_uri(&req.target_uri)?;
    let mut edits = Vec::new();
    for b64 in &req.add {
        let der = STANDARD
            .decode(b64)
            .map_err(|e| Error::Other(format!("invalid base64 trust anchor: {e}")))?;
        let ta = crate::asn1::TrustAnchorChoice::from_der(&der)?;
        edits.push(TrustAnchorEdit::Add(ta));
    }
    for b64 in &req.remove {
        let der = STANDARD
            .decode(b64)
            .map_err(|e| Error::Other(format!("invalid base64 SPKI: {e}")))?;
        edits.push(TrustAnchorEdit::Remove(der));
    }
    let signer = state.signer.context();
    let issued = state
        .manager
        .issue_trust_anchor_update(&target, &req.label, &signer, edits)
        .await?;
    Ok(Json(issued_to_response(issued)))
}

async fn register_signer(
    State(state): State<TampState>,
    Json(req): Json<RegisterSignerRequest>,
) -> Result<Json<serde_json::Value>, Error> {
    let target = target_from_uri(&req.target_uri)?;
    let ski = STANDARD
        .decode(&req.signer_ski_b64)
        .map_err(|e| Error::Other(format!("invalid base64 signer SKI: {e}")))?;
    let spki = STANDARD
        .decode(&req.signer_spki_b64)
        .map_err(|e| Error::Other(format!("invalid base64 signer SPKI: {e}")))?;
    state
        .manager
        .register_target_signer(&target, &req.label, &ski, &spki, req.description.as_deref())
        .await?;
    Ok(Json(serde_json::json!({ "status": "registered" })))
}

async fn ingest(
    State(state): State<TampState>,
    Json(req): Json<IngestRequest>,
) -> Result<Json<IngestResponse>, Error> {
    let target = target_from_uri(&req.target_uri)?;
    let envelope = STANDARD
        .decode(&req.envelope_b64)
        .map_err(|e| Error::Other(format!("invalid base64 envelope: {e}")))?;
    let outcome = state.manager.ingest(&target, &req.label, &envelope).await?;
    Ok(Json(IngestResponse {
        content_type: outcome.content_type.to_string(),
        message_name: outcome.message_name,
        seq_num: outcome.seq_num,
        status_codes: outcome
            .status_codes
            .iter()
            .map(|s| s.as_str().to_string())
            .collect(),
        signer_ski_hex: hex::encode(&outcome.signer_ski),
    }))
}

async fn list_trust_anchors(
    State(state): State<TampState>,
    Json(req): Json<ListTrustAnchorsRequest>,
) -> Result<Json<serde_json::Value>, Error> {
    let target = target_from_uri(&req.target_uri)?;
    let tas = state
        .manager
        .list_trust_anchors(&target, &req.label)
        .await?;
    Ok(Json(serde_json::json!({ "trust_anchors": tas })))
}

fn issued_to_response(issued: crate::manager::IssuedMessage) -> IssuedMessageResponse {
    IssuedMessageResponse {
        content_type: issued.content_type.to_string(),
        message_name: issued.message_name.to_string(),
        seq_num: issued.seq_num,
        envelope_b64: STANDARD.encode(&issued.envelope),
    }
}

fn parse_oids(oids: &[String]) -> Result<Vec<const_oid::ObjectIdentifier>, Error> {
    oids.iter()
        .map(|s| {
            s.parse::<const_oid::ObjectIdentifier>()
                .map_err(|e| Error::Other(format!("invalid community OID '{s}': {e}")))
        })
        .collect()
}

/// Build the TAMP manager REST router.
pub fn create_router(state: TampState) -> Router {
    let auth_provider = state.auth_provider.clone();
    let rbac_policy = state.rbac_policy.clone();

    let authz = |permission: Permission| {
        middleware::from_fn_with_state(
            (rbac_policy.clone(), permission, None::<String>),
            AuthzLayer::authorize,
        )
    };

    // Public probes (no authentication).
    let public_routes = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready));

    // Protected manager operations. RFC 5934 trust-anchor management is a
    // security management function (NIAP FMT_SMF.1); mutating routes require
    // ModifyConfig, reads require ViewConfig (NIST 800-53: AC-3).
    let protected_routes = Router::new()
        .route(
            "/api/v1/tamp/status-query",
            post(issue_status_query).route_layer(authz(Permission::ModifyConfig)),
        )
        .route(
            "/api/v1/tamp/trust-anchor-update",
            post(issue_trust_anchor_update).route_layer(authz(Permission::ModifyConfig)),
        )
        .route(
            "/api/v1/tamp/community-update",
            post(issue_community_update).route_layer(authz(Permission::ModifyConfig)),
        )
        .route(
            "/api/v1/tamp/target-signers",
            post(register_signer).route_layer(authz(Permission::ModifyConfig)),
        )
        .route(
            "/api/v1/tamp/ingest",
            post(ingest).route_layer(authz(Permission::ModifyConfig)),
        )
        .route(
            "/api/v1/tamp/trust-anchors",
            post(list_trust_anchors).route_layer(authz(Permission::ViewConfig)),
        )
        .layer(middleware::from_fn_with_state(
            auth_provider,
            AuthLayer::authenticate,
        ));

    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .with_state(state)
}
