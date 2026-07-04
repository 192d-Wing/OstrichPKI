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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path as FsPath, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
    RetryPolicy,
};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

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

    let identifiers: Vec<Identifier> = cfg
        .domains
        .iter()
        .map(|d| Identifier::Dns(d.clone()))
        .collect();
    let mut order = account
        .new_order(&NewOrder::new(identifiers.as_slice()))
        .await?;

    // Run the whole challenge -> finalize flow inside one fallible block so that
    // EVERY exit path (including an authorization-fetch or set_ready error) falls
    // through to the token cleanup below — a served challenge token must never be
    // left in the store after the order ends.
    let mut tokens = Vec::new();
    let result: anyhow::Result<CertMaterial> = async {
        // Answer each pending authorization's HTTP-01 challenge.
        {
            let mut authorizations = order.authorizations();
            while let Some(result) = authorizations.next().await {
                let mut authz = result?;
                match authz.status {
                    // Already validated (e.g. a reused authorization) — nothing to do.
                    AuthorizationStatus::Valid => continue,
                    AuthorizationStatus::Pending => {}
                    // Invalid / Revoked / Expired / Deactivated are terminal: do not
                    // attempt to answer a challenge on them (RFC 8555 §7.1.4).
                    other => anyhow::bail!("authorization is in a non-pending state: {other:?}"),
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
        }

        // Wait for validation, finalize (generates the keypair + CSR), fetch cert.
        let status = order.poll_ready(&RetryPolicy::default()).await?;
        if status != OrderStatus::Ready {
            anyhow::bail!("ACME order did not become ready (status: {status:?})");
        }

        // Finalize with a CSR that carries a subject Common Name (the primary
        // domain), not just Subject Alternative Names. instant-acme's default
        // `finalize()` emits a CN-less CSR (empty subject); an empty subject
        // paired with a NON-critical SAN violates RFC 5280 §4.1.2.6 ("If the
        // subject field contains an empty sequence ... the issuing CA MUST include
        // a subjectAltName extension that is marked as critical") and is rejected
        // as invalid by strict validators (notably Windows/schannel), besides
        // showing a blank "Issued To". Supplying our own CSR with a CN avoids
        // both. The keypair generated here is the certificate's private key.
        let primary = cfg.domains[0].clone();
        let key = rcgen::KeyPair::generate()
            .map_err(|e| anyhow::anyhow!("failed to generate certificate key: {e}"))?;
        let mut params = rcgen::CertificateParams::new(cfg.domains.clone())
            .map_err(|e| anyhow::anyhow!("invalid domains for CSR: {e}"))?;
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, primary);
        params.distinguished_name = dn;
        let csr = params
            .serialize_request(&key)
            .map_err(|e| anyhow::anyhow!("failed to build CSR: {e}"))?;
        order.finalize_csr(csr.der()).await?;
        let cert_chain_pem = order.poll_certificate(&RetryPolicy::default()).await?;
        let private_key_pem = key.serialize_pem();
        Ok(CertMaterial {
            cert_chain_pem,
            private_key_pem,
        })
    }
    .await;

    // Always drop the served challenge tokens, success or failure.
    {
        let mut map = store.write().await;
        for t in &tokens {
            map.remove(t);
        }
    }

    result
}

/// A rustls server-cert resolver whose certificate can be swapped at runtime.
///
/// The portal serves mTLS with this resolver installed in its [`ServerConfig`];
/// the ACME renewal task calls [`AcmeCertResolver::install`] with freshly issued
/// material and every subsequent TLS handshake picks it up — no restart, no
/// reload of the listener. Reads happen on the TLS hot path, so `resolve` only
/// takes a short read lock and clones the `Arc`.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-8 (transmission confidentiality), SC-12 (key management —
///   server key rotated on renewal without downtime)
pub struct AcmeCertResolver {
    current: RwLock<Option<Arc<CertifiedKey>>>,
}

impl std::fmt::Debug for AcmeCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let has_cert = self.current.read().map(|c| c.is_some()).unwrap_or(false);
        f.debug_struct("AcmeCertResolver")
            .field("has_cert", &has_cert)
            .finish()
    }
}

impl Default for AcmeCertResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl AcmeCertResolver {
    /// Create a resolver with no certificate yet. Until [`install`](Self::install)
    /// is called, TLS handshakes are refused (no cert to present).
    pub fn new() -> Self {
        Self {
            current: RwLock::new(None),
        }
    }

    /// Swap in a new certificate + key. Applies to subsequent handshakes.
    pub fn install(&self, certified: Arc<CertifiedKey>) {
        // A poisoned lock means a writer panicked mid-swap; recover the guard and
        // overwrite anyway — a stale cert is worse than a recovered one.
        let mut guard = self.current.write().unwrap_or_else(|e| e.into_inner());
        *guard = Some(certified);
    }

    /// Whether a certificate is currently installed (readiness / test accessor).
    #[allow(dead_code)]
    pub fn has_cert(&self) -> bool {
        self.current.read().map(|c| c.is_some()).unwrap_or(false)
    }
}

impl ResolvesServerCert for AcmeCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.current.read().ok().and_then(|c| c.clone())
    }
}

/// Build a [`CertifiedKey`] from PEM material (the ACME-issued chain + key),
/// using the aws-lc-rs/FIPS provider to load the signing key.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-13 (FIPS-validated crypto provider), SC-12
/// - FIPS 140-3 (aws-lc-rs provider)
pub fn certified_key_from_pem(
    cert_chain_pem: &str,
    private_key_pem: &str,
) -> anyhow::Result<CertifiedKey> {
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(cert_chain_pem.as_bytes())
            .collect::<Result<_, _>>()
            .map_err(|e| anyhow::anyhow!("failed to parse ACME certificate chain: {e}"))?;
    if certs.is_empty() {
        anyhow::bail!("ACME certificate chain contained no certificates");
    }
    let key = PrivateKeyDer::from_pem_slice(private_key_pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("failed to parse ACME private key: {e}"))?;
    let signing_key = rustls::crypto::aws_lc_rs::default_provider()
        .key_provider
        .load_private_key(key)
        .map_err(|e| anyhow::anyhow!("failed to load ACME private key: {e}"))?;
    Ok(CertifiedKey::new(certs, signing_key))
}

/// Build the portal's mTLS [`ServerConfig`]: TLS 1.3 only, client certificates
/// **required** and verified against `client_ca_pem_path`, and the server
/// certificate supplied dynamically by `resolver` (ACME).
///
/// Mirrors `ostrich_common::tls` (same aws-lc-rs/FIPS provider, TLS 1.3 floor)
/// but swaps the static `with_single_cert` for `with_cert_resolver` so the ACME
/// renewal task can rotate the server cert in place.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-8 (TLS 1.3), SC-13 (FIPS provider), AC-17/IA-2 (mTLS client
///   authentication — every operator presents a verified client certificate)
/// - NIAP PP-CA: FCS_TLSS_EXT (TLS server), FIA_X509_EXT (client cert validation)
pub fn build_mtls_server_config(
    client_ca_pem_path: &str,
    resolver: Arc<AcmeCertResolver>,
) -> anyhow::Result<ServerConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

    let mut roots = RootCertStore::empty();
    for ca in CertificateDer::pem_file_iter(client_ca_pem_path)
        .map_err(|e| anyhow::anyhow!("failed to read client CA bundle {client_ca_pem_path}: {e}"))?
    {
        let ca = ca.map_err(|e| anyhow::anyhow!("invalid certificate in client CA bundle: {e}"))?;
        roots
            .add(ca)
            .map_err(|e| anyhow::anyhow!("failed to add client CA to trust store: {e}"))?;
    }
    if roots.is_empty() {
        anyhow::bail!("client CA bundle {client_ca_pem_path} contained no certificates");
    }

    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build client certificate verifier: {e}"))?;

    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| anyhow::anyhow!("failed to set TLS 1.3 protocol version: {e}"))?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(resolver);

    Ok(config)
}

// --- Orchestration: challenge responder, certificate cache, acquire + renew ---

/// Single combined PEM bundle (cert chain followed by the private key) cached
/// under `cache_dir`. One file written atomically can never present a torn
/// cert/key pair the way two separate files can across a re-enrollment.
const CACHE_BUNDLE_FILE: &str = "tls.pem";

/// Minimum interval between renewal checks, so a clock skew or an
/// already-past renewal deadline cannot spin the renewal loop.
const MIN_RENEWAL_RECHECK: Duration = Duration::from_secs(3600);

/// Bind the HTTP-01 challenge responder's listener on `port`. Done synchronously
/// (and its error propagated) *before* enrollment so a bind failure (port in
/// use, insufficient privilege) is a direct fatal error rather than a stalled
/// enrollment with the root cause buried in a detached task's log.
pub async fn bind_challenge_responder(port: u16) -> anyhow::Result<tokio::net::TcpListener> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("failed to bind ACME challenge responder on {addr}: {e}"))
}

/// Serve the HTTP-01 challenge responder on an already-bound `listener` over
/// plain HTTP. The ACME server fetches
/// `http://<domain>/.well-known/acme-challenge/{token}` during validation
/// (RFC 8555 §8.3). Runs until the process exits; intended to be spawned as a
/// detached task once [`bind_challenge_responder`] has succeeded.
pub async fn run_challenge_responder(
    listener: tokio::net::TcpListener,
    store: ChallengeStore,
) -> anyhow::Result<()> {
    let app = axum::Router::new()
        .route(
            "/.well-known/acme-challenge/{token}",
            axum::routing::get(challenge_handler),
        )
        .with_state(store);
    tracing::info!(addr = ?listener.local_addr().ok(), "ACME HTTP-01 challenge responder listening");
    axum::serve(listener, app)
        .await
        .map_err(|e| anyhow::anyhow!("ACME challenge responder error: {e}"))
}

/// notAfter (unix seconds) of the leaf certificate in a PEM chain (leaf first).
fn leaf_not_after_unix(cert_chain_pem: &str) -> anyhow::Result<i64> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(cert_chain_pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("failed to parse leaf certificate PEM: {e}"))?;
    let cert = pem
        .parse_x509()
        .map_err(|e| anyhow::anyhow!("failed to parse leaf X.509 certificate: {e}"))?;
    Ok(cert.validity().not_after.timestamp())
}

/// Whether `not_after` is within `renew_before_days` of now (i.e. due to renew).
fn is_due_for_renewal(not_after_unix: i64, renew_before_days: i64) -> bool {
    let renew_at = not_after_unix - renew_before_days * 86_400;
    chrono::Utc::now().timestamp() >= renew_at
}

fn bundle_path(cache_dir: &str) -> PathBuf {
    FsPath::new(cache_dir).join(CACHE_BUNDLE_FILE)
}

/// Load the cached bundle from `cache_dir`, or `None` if absent/unreadable.
///
/// The returned `CertMaterial` carries the *whole* combined bundle in both
/// fields: the cert/key parsers each select only the PEM blocks they recognize
/// (`pem_slice_iter` → CERTIFICATE blocks, `from_pem_slice` → the key), so a
/// loaded bundle is consumed correctly without splitting it back apart. It is
/// only ever installed, never re-saved, so the fields are never re-combined.
async fn load_cached(cache_dir: &str) -> Option<CertMaterial> {
    let bundle = tokio::fs::read_to_string(bundle_path(cache_dir))
        .await
        .ok()?;
    Some(CertMaterial {
        cert_chain_pem: bundle.clone(),
        private_key_pem: bundle,
    })
}

/// Write `contents` to `path` atomically: create a temp sibling (with `mode`
/// permissions from the outset on Unix — no relax-then-tighten window), fsync,
/// then rename over `path`. A crash or partial write therefore never leaves a
/// torn file, and the private key is never momentarily world-readable.
async fn write_atomic(path: &FsPath, contents: &[u8], mode: u32) -> anyhow::Result<()> {
    let _ = mode; // used only on Unix
    let tmp = path.with_extension("tmp");
    #[cfg(unix)]
    {
        use tokio::io::AsyncWriteExt;
        let mut f = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)
            .await
            .map_err(|e| anyhow::anyhow!("failed to create {}: {e}", tmp.display()))?;
        f.write_all(contents)
            .await
            .map_err(|e| anyhow::anyhow!("failed to write {}: {e}", tmp.display()))?;
        f.sync_all()
            .await
            .map_err(|e| anyhow::anyhow!("failed to fsync {}: {e}", tmp.display()))?;
    }
    #[cfg(not(unix))]
    tokio::fs::write(&tmp, contents)
        .await
        .map_err(|e| anyhow::anyhow!("failed to write {}: {e}", tmp.display()))?;
    tokio::fs::rename(&tmp, path).await.map_err(|e| {
        anyhow::anyhow!(
            "failed to rename {} -> {}: {e}",
            tmp.display(),
            path.display()
        )
    })
}

/// Persist the cert chain + key as one combined PEM bundle under `cache_dir`,
/// written atomically (temp + rename) with owner-only permissions (0600) on Unix
/// from the outset. A single atomic file can never present a torn cert/key pair,
/// and the key is never momentarily world-readable. NIST 800-53: SC-12, SC-28.
async fn save_cached(cache_dir: &str, material: &CertMaterial) -> anyhow::Result<()> {
    tokio::fs::create_dir_all(cache_dir)
        .await
        .map_err(|e| anyhow::anyhow!("failed to create ACME cache dir {cache_dir}: {e}"))?;
    // Cert chain first so the leaf is the first PEM block (read by
    // `leaf_not_after_unix`), then the private key.
    let bundle = format!(
        "{}\n{}",
        material.cert_chain_pem.trim_end(),
        material.private_key_pem
    );
    write_atomic(&bundle_path(cache_dir), bundle.as_bytes(), 0o600).await
}

/// Parse `material` and install it into the resolver (no caching).
fn install(resolver: &Arc<AcmeCertResolver>, material: &CertMaterial) -> anyhow::Result<()> {
    let certified = certified_key_from_pem(&material.cert_chain_pem, &material.private_key_pem)?;
    resolver.install(Arc::new(certified));
    Ok(())
}

/// Install freshly issued material into the resolver and cache it (best effort).
async fn install_and_cache(
    cfg: &AcmeConfig,
    resolver: &Arc<AcmeCertResolver>,
    material: &CertMaterial,
) -> anyhow::Result<()> {
    install(resolver, material)?;
    // A cache write failure is non-fatal: the cert is live in memory; we just
    // re-enroll on the next restart. Log it for operability.
    if let Some(dir) = &cfg.cache_dir
        && let Err(e) = save_cached(dir, material).await
    {
        tracing::warn!(error = %e, "failed to cache ACME certificate");
    }
    Ok(())
}

/// Acquire the portal's certificate on startup: reuse a still-fresh cached cert
/// if present, otherwise enroll via ACME. Installs it into `resolver` and returns
/// the leaf notAfter (unix seconds) for renewal scheduling.
pub async fn acquire_on_startup(
    cfg: &AcmeConfig,
    store: &ChallengeStore,
    resolver: &Arc<AcmeCertResolver>,
) -> anyhow::Result<i64> {
    if let Some(dir) = &cfg.cache_dir
        && let Some(material) = load_cached(dir).await
    {
        match leaf_not_after_unix(&material.cert_chain_pem) {
            Ok(not_after) if !is_due_for_renewal(not_after, cfg.renew_before_days) => {
                // Already on disk and fresh — install without rewriting it.
                install(resolver, &material)?;
                tracing::info!(dir = %dir, "loaded cached ACME certificate");
                return Ok(not_after);
            }
            Ok(_) => tracing::info!("cached ACME certificate is near expiry; re-enrolling"),
            Err(e) => {
                tracing::warn!(error = %e, "cached ACME certificate unreadable; re-enrolling")
            }
        }
    }

    let material = obtain_certificate(cfg, store).await?;
    let not_after = leaf_not_after_unix(&material.cert_chain_pem)?;
    install_and_cache(cfg, resolver, &material).await?;
    tracing::info!(domains = ?cfg.domains, "obtained ACME certificate");
    Ok(not_after)
}

/// Background renewal loop: sleeps until the certificate is within
/// `renew_before_days` of expiry, re-enrolls, and swaps the new cert into the
/// resolver in place (no restart). Retries with backoff on failure.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-12 (key lifecycle — automated rotation), CP-10 (recovery —
///   the portal self-heals an expiring certificate without operator action)
pub async fn renewal_loop(
    cfg: AcmeConfig,
    store: ChallengeStore,
    resolver: Arc<AcmeCertResolver>,
    mut not_after_unix: i64,
) {
    loop {
        // Sleep until the renewal deadline. The MIN_RENEWAL_RECHECK floor both
        // prevents a busy-loop and rate-limits re-enrollment for pathologically
        // short-lived certs (lifetime < renew_before_days): such a cert is always
        // "due", so without the floor the loop would re-enroll back-to-back.
        let renew_at = not_after_unix - cfg.renew_before_days * 86_400;
        let now = chrono::Utc::now().timestamp();
        let wait = Duration::from_secs((renew_at - now).max(0) as u64).max(MIN_RENEWAL_RECHECK);
        tokio::time::sleep(wait).await;

        // Re-enroll, retrying with backoff until it succeeds.
        let mut backoff = MIN_RENEWAL_RECHECK;
        loop {
            match obtain_certificate(&cfg, &store).await {
                Ok(material) => match leaf_not_after_unix(&material.cert_chain_pem) {
                    Ok(new_not_after) => {
                        if let Err(e) = install_and_cache(&cfg, &resolver, &material).await {
                            tracing::error!(error = %e, "failed to install renewed ACME certificate");
                        } else {
                            not_after_unix = new_not_after;
                            tracing::info!("ACME certificate renewed");
                            break;
                        }
                    }
                    Err(e) => tracing::error!(error = %e, "renewed certificate unparseable"),
                },
                Err(e) => tracing::warn!(error = %e, "ACME renewal attempt failed; will retry"),
            }
            tokio::time::sleep(backoff).await;
            // Exponential backoff capped at 12h so a prolonged outage doesn't
            // hammer the ACME server but still retries before the cert expires.
            backoff = (backoff * 2).min(Duration::from_secs(12 * 3600));
        }
    }
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

    /// Generate a throwaway self-signed cert + PKCS#8 key as PEM for the TLS
    /// plumbing tests (no network, no ACME server needed).
    fn self_signed_pem() -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["npe-portal.test".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        (cert.pem(), key.serialize_pem())
    }

    #[test]
    fn resolver_starts_empty_then_serves_installed_cert() {
        let resolver = AcmeCertResolver::new();
        assert!(!resolver.has_cert());

        let (cert_pem, key_pem) = self_signed_pem();
        let ck = certified_key_from_pem(&cert_pem, &key_pem).unwrap();
        resolver.install(Arc::new(ck));
        assert!(resolver.has_cert());
    }

    #[test]
    fn certified_key_from_pem_round_trips_real_material() {
        let (cert_pem, key_pem) = self_signed_pem();
        let ck = certified_key_from_pem(&cert_pem, &key_pem).unwrap();
        assert_eq!(ck.cert.len(), 1, "leaf certificate should be present");
    }

    #[test]
    fn certified_key_from_pem_rejects_empty_chain() {
        let (_cert_pem, key_pem) = self_signed_pem();
        let err = certified_key_from_pem("", &key_pem).unwrap_err();
        assert!(err.to_string().contains("no certificates"));
    }

    #[test]
    fn certified_key_from_pem_rejects_bad_key() {
        let (cert_pem, _key_pem) = self_signed_pem();
        assert!(certified_key_from_pem(&cert_pem, "not a key").is_err());
    }

    #[test]
    fn build_mtls_server_config_requires_nonempty_ca_bundle() {
        // Missing file path -> error (no client CA to verify against).
        let resolver = Arc::new(AcmeCertResolver::new());
        assert!(build_mtls_server_config("/nonexistent/ca.pem", resolver).is_err());
    }

    #[test]
    fn is_due_for_renewal_respects_window() {
        let now = chrono::Utc::now().timestamp();
        // Expires in 10 days, renew window 30 days -> due now.
        assert!(is_due_for_renewal(now + 10 * 86_400, 30));
        // Expires in 60 days, renew window 30 days -> not yet.
        assert!(!is_due_for_renewal(now + 60 * 86_400, 30));
    }

    #[test]
    fn leaf_not_after_unix_reads_validity() {
        let (cert_pem, _key_pem) = self_signed_pem();
        let na = leaf_not_after_unix(&cert_pem).unwrap();
        assert!(
            na > chrono::Utc::now().timestamp(),
            "cert should not be expired"
        );
    }

    #[tokio::test]
    async fn cache_round_trips_material() {
        let dir = std::env::temp_dir().join(format!("npe-acme-test-{}", std::process::id()));
        let dir_str = dir.to_string_lossy().to_string();
        let (cert_pem, key_pem) = self_signed_pem();
        let material = CertMaterial {
            cert_chain_pem: cert_pem.clone(),
            private_key_pem: key_pem.clone(),
        };
        save_cached(&dir_str, &material).await.unwrap();

        // The cached bundle round-trips: the loaded material parses into a usable
        // cert+key, and the leaf validity is recoverable for renewal scheduling.
        let loaded = load_cached(&dir_str)
            .await
            .expect("cached material present");
        certified_key_from_pem(&loaded.cert_chain_pem, &loaded.private_key_pem)
            .expect("loaded bundle yields a valid cert + key");
        assert!(leaf_not_after_unix(&loaded.cert_chain_pem).unwrap() > 0);
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn load_cached_returns_none_when_absent() {
        let missing = std::env::temp_dir().join("npe-acme-nonexistent-dir-xyz");
        assert!(load_cached(&missing.to_string_lossy()).await.is_none());
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
