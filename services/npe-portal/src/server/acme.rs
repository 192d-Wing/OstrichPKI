//! ACME client (RFC 8555) for the NPE portal's own TLS server certificate.
//!
//! The portal enrolls + renews its server certificate from an ACME directory
//! using the HTTP-01 challenge (RFC 8555 §8.3): it serves the key authorization
//! at `/.well-known/acme-challenge/{token}` and the ACME server validates by
//! fetching that URL over HTTP.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-8 (transmission confidentiality — server cert lifecycle),
//!   SC-12 (key establishment), CM-6 (configured trust anchor for the directory)
//! - RFC 8555 (ACME), HTTP-01 challenge

// This module is the standalone ACME client; it is wired into the server
// (challenge route + acquire-or-load + renewal) in the next increment, so its
// public surface is not referenced from the binary yet.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
    RetryPolicy,
};

use super::config::AcmeConfig;

/// Shared map of HTTP-01 challenge `token -> key authorization`, populated while
/// an order is in flight and read by the challenge responder.
pub type ChallengeStore = Arc<tokio::sync::RwLock<HashMap<String, String>>>;

/// Create an empty challenge store.
pub fn new_challenge_store() -> ChallengeStore {
    Arc::new(tokio::sync::RwLock::new(HashMap::new()))
}

/// `GET /.well-known/acme-challenge/{token}` — return the key authorization for a
/// pending challenge, or 404. Served over plain HTTP for ACME validation
/// (RFC 8555 §8.3: the response body is exactly the key authorization).
pub async fn challenge_handler(
    State(store): State<ChallengeStore>,
    Path(token): Path<String>,
) -> Response {
    match store.read().await.get(&token) {
        Some(key_auth) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream")],
            key_auth.clone(),
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "unknown challenge").into_response(),
    }
}

/// The issued certificate material.
pub struct CertMaterial {
    /// PEM certificate chain, leaf first.
    pub cert_chain_pem: String,
    /// PEM PKCS#8 private key (generated during finalize).
    pub private_key_pem: String,
}

/// Run the ACME HTTP-01 flow and return the issued certificate + key. The caller
/// must have the challenge responder ([`challenge_handler`], backed by `store`)
/// mounted and reachable on the configured challenge port before this runs.
pub async fn obtain_certificate(
    cfg: &AcmeConfig,
    store: &ChallengeStore,
) -> anyhow::Result<CertMaterial> {
    if cfg.domains.is_empty() {
        anyhow::bail!("acme.domains must list at least one domain");
    }

    // Trust the ACME directory's own HTTPS cert: the OstrichPKI ACME server
    // presents a private-CA certificate, so the public web-PKI roots used by the
    // default client would reject it.
    let builder = match &cfg.ca_bundle {
        Some(path) => Account::builder_with_root(path)?,
        None => Account::builder()?,
    };

    let contact: Vec<String> = cfg.contact.iter().cloned().collect();
    let contact_refs: Vec<&str> = contact.iter().map(String::as_str).collect();
    let (account, _credentials) = builder
        .create(
            &NewAccount {
                contact: &contact_refs,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            cfg.directory_url.clone(),
            None,
        )
        .await?;

    let identifiers: Vec<Identifier> =
        cfg.domains.iter().map(|d| Identifier::Dns(d.clone())).collect();
    let mut order = account.new_order(&NewOrder::new(identifiers.as_slice())).await?;

    // Answer each pending authorization's HTTP-01 challenge.
    let mut tokens = Vec::new();
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result?;
        if authz.status == AuthorizationStatus::Valid {
            continue;
        }
        let mut challenge = authz
            .challenge(ChallengeType::Http01)
            .ok_or_else(|| anyhow::anyhow!("ACME server offered no http-01 challenge"))?;
        let token = challenge.token.to_string();
        let key_auth = challenge.key_authorization().as_str().to_string();
        store.write().await.insert(token.clone(), key_auth);
        tokens.push(token);
        challenge.set_ready().await?;
    }

    // Wait for validation, finalize (generates the keypair + CSR), fetch the cert.
    let result = async {
        let status = order.poll_ready(&RetryPolicy::default()).await?;
        if status != OrderStatus::Ready {
            anyhow::bail!("ACME order did not become ready (status: {status:?})");
        }
        let private_key_pem = order.finalize().await?;
        let cert_chain_pem = order.poll_certificate(&RetryPolicy::default()).await?;
        Ok(CertMaterial { cert_chain_pem, private_key_pem })
    }
    .await;

    // Always drop the served challenge tokens, success or failure.
    let mut map = store.write().await;
    for t in &tokens {
        map.remove(t);
    }
    drop(map);

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Path, State};

    #[tokio::test]
    async fn challenge_handler_serves_known_token_and_404s_unknown() {
        let store = new_challenge_store();
        store
            .write()
            .await
            .insert("tok123".to_string(), "tok123.keyauth".to_string());

        let ok = challenge_handler(State(store.clone()), Path("tok123".to_string())).await;
        assert_eq!(ok.status(), StatusCode::OK);

        let missing = challenge_handler(State(store), Path("nope".to_string())).await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn acme_config_applies_secure_defaults() {
        let cfg: AcmeConfig = serde_json::from_str(
            r#"{"directoryUrl":"https://acme.example/directory","domains":["a.example"]}"#,
        )
        .unwrap();
        assert_eq!(cfg.challenge_port, 80);
        assert_eq!(cfg.renew_before_days, 30);
        assert!(cfg.ca_bundle.is_none());
        assert_eq!(cfg.domains, vec!["a.example".to_string()]);
    }
}
