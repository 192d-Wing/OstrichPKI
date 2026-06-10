//! ACME Full Issuance Flow End-to-End Test
//!
//! A minimal RFC 8555 ACME client that drives the complete certificate
//! issuance flow against a live acme-server:
//!
//!   directory -> new-nonce -> new-account -> new-order -> authorization
//!   -> http-01 challenge -> finalize (CSR) -> certificate download
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Security Testing)
//! - NIST 800-53: CA-2 (Security Assessments)
//! - NIST 800-53: SC-17 (PKI Certificates - end-to-end issuance evidence)
//! - RFC 8555 §7.1.1 (Directory), §7.2 (Nonce), §7.3 (Account),
//!   §7.4 (Order/Finalize), §7.5 (Authorization/Challenge), §8.3 (HTTP-01)
//! - RFC 7515 (JWS), RFC 7638 (JWK Thumbprint)
//!
//! This test is #[ignore]d by default because it requires:
//! - A running acme-server (env ACME_URL, default http://localhost:8081)
//!   configured with a CA backend (profile "acme-default") and an HTTP-01
//!   validator pointed at port ACME_HTTP01_PORT (default 8099) that permits
//!   the "localhost" identifier.
//!
//! Run with:
//!   cargo test -p ostrich-integration-tests --test acme_full_flow_test -- --ignored --nocapture
//!
//! NOTE: comments prefixed `// SERVER QUIRK:` document observed deviations
//! of crates/ostrich-acme from RFC 8555. The client deliberately matches the
//! server's actual behavior; the quirks are bug reports for the server side.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

// =============================================================================
// Configuration
// =============================================================================

/// ACME server base URL (plaintext HTTP in the E2E environment)
fn acme_url() -> String {
    std::env::var("ACME_URL")
        .unwrap_or_else(|_| "http://localhost:8081".to_string())
        .trim_end_matches('/')
        .to_string()
}

/// Port the server-side HTTP-01 validator fetches challenges from.
/// RFC 8555 §8.3 mandates port 80; the server supports an override for
/// dev/E2E environments (Http01Validator::with_http_port).
fn http01_port() -> u16 {
    std::env::var("ACME_HTTP01_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8099)
}

const POLL_INTERVAL: Duration = Duration::from_millis(500);
const POLL_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_VALIDITY_SECS: i64 = 90 * 24 * 60 * 60; // acme-default profile: <= 90 days

// =============================================================================
// Server response shapes (matched to crates/ostrich-acme serialization)
// =============================================================================

/// RFC 8555 §7.1.1 directory object.
/// Fields optional so the client can fall back to conventional paths.
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Directory {
    new_nonce: Option<String>,
    new_account: Option<String>,
    new_order: Option<String>,
}

/// RFC 8555 §7.1.3 order object (subset the client needs)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrderObject {
    status: String,
    #[serde(default)]
    authorizations: Vec<String>,
    #[serde(default)]
    finalize: Option<String>,
    #[serde(default)]
    certificate: Option<String>,
    #[serde(default)]
    error: Option<serde_json::Value>,
}

/// RFC 8555 §7.1.4 authorization object (subset)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthzObject {
    status: String,
    #[serde(default)]
    challenges: Vec<ChallengeObject>,
}

/// RFC 8555 §8 challenge object (subset)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeObject {
    #[serde(rename = "type")]
    challenge_type: String,
    status: String,
    url: String,
    token: String,
    #[serde(default)]
    error: Option<serde_json::Value>,
}

// =============================================================================
// Minimal ACME client (RFC 8555 §6.2 JWS with RS256 account key)
// =============================================================================

struct AcmeClient {
    http: reqwest::Client,
    base_url: String,
    /// RFC 8555 §6.5: every response carries a fresh Replay-Nonce; the
    /// client uses each nonce exactly once.
    nonce: Option<String>,
    signing_key: SigningKey<Sha256>,
    /// base64url(big-endian modulus) - RFC 7518 §6.3.1.1
    jwk_n: String,
    /// base64url(big-endian exponent) - RFC 7518 §6.3.1.2
    jwk_e: String,
    /// Account URL / kid, captured from the new-account Location header
    kid: Option<String>,
}

impl AcmeClient {
    fn new(base_url: String) -> Self {
        println!("[acme-client] generating RSA-2048 account key...");
        let private_key =
            RsaPrivateKey::new(&mut rand::thread_rng(), 2048).expect("RSA keygen failed");
        let public_key = private_key.to_public_key();
        let jwk_n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let jwk_e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

        Self {
            http: reqwest::Client::new(),
            base_url,
            nonce: None,
            signing_key: SigningKey::<Sha256>::new(private_key),
            jwk_n,
            jwk_e,
            kid: None,
        }
    }

    /// Join a possibly-relative URL onto the ACME base URL.
    ///
    /// SERVER QUIRK: RFC 8555 returns absolute URLs everywhere (§7.1), but
    /// ostrich-acme returns *relative* paths (e.g. "/acme/authz/<id>") in
    /// Location headers and in order/authorization/challenge bodies
    /// (crates/ostrich-acme/src/rest.rs map_db_* helpers). The client must
    /// join them against the base URL itself.
    fn abs_url(&self, url: &str) -> String {
        if url.starts_with("http://") || url.starts_with("https://") {
            url.to_string()
        } else {
            format!("{}{}", self.base_url, url)
        }
    }

    /// JWK for the account key: {"e","kty","n"} per RFC 7518 §6.3
    fn jwk(&self) -> serde_json::Value {
        serde_json::json!({"e": self.jwk_e, "kty": "RSA", "n": self.jwk_n})
    }

    /// RFC 7638 JWK thumbprint: b64url(SHA-256 of the canonical JSON
    /// {"e":"...","kty":"RSA","n":"..."} - required members only, in
    /// lexicographic order, no whitespace). This matches the server's
    /// jws::compute_jwk_thumbprint exactly.
    fn jwk_thumbprint(&self) -> String {
        let canonical = format!(r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#, self.jwk_e, self.jwk_n);
        URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
    }

    /// Harvest the Replay-Nonce header from any server response (RFC 8555 §6.5)
    fn harvest_nonce(&mut self, response: &reqwest::Response) {
        if let Some(nonce) = response
            .headers()
            .get("Replay-Nonce")
            .and_then(|v| v.to_str().ok())
        {
            self.nonce = Some(nonce.to_string());
        }
    }

    /// Get a nonce: use the one from the previous response, or fetch a fresh
    /// one from the new-nonce endpoint (RFC 8555 §7.2).
    async fn take_nonce(&mut self, new_nonce_url: &str) -> String {
        if let Some(nonce) = self.nonce.take() {
            return nonce;
        }
        // RFC 8555 §7.2: HEAD new-nonce returns the Replay-Nonce header
        // (axum's get() route also answers HEAD). Fall back to GET if the
        // HEAD request did not yield a nonce.
        if let Ok(response) = self.http.head(new_nonce_url).send().await {
            self.harvest_nonce(&response);
        }
        if let Some(nonce) = self.nonce.take() {
            return nonce;
        }
        let response = self
            .http
            .get(new_nonce_url)
            .send()
            .await
            .expect("GET new-nonce failed");
        self.harvest_nonce(&response);
        self.nonce.take().expect("server returned no Replay-Nonce")
    }

    /// Sign and POST a JWS request per RFC 8555 §6.2 / RFC 7515.
    ///
    /// Protected header: {"alg":"RS256","nonce":...,"url":...} plus either
    /// the embedded "jwk" (new-account) or "kid" (all later requests).
    /// Body: {"protected","payload","signature"} in flattened JSON
    /// serialization; signature is RSASSA-PKCS1-v1_5/SHA-256 over
    /// ASCII(b64url(header) || "." || b64url(payload)).
    async fn post_jws(
        &mut self,
        new_nonce_url: &str,
        url: &str,
        payload: &str,
    ) -> reqwest::Response {
        let nonce = self.take_nonce(new_nonce_url).await;

        // NOTE: the server verifies header.url against the *absolute* URL it
        // computes from its configured base_url (rest.rs validate_jws_*), so
        // ACME_URL must equal the server's ACME_BASE_URL.
        let mut header = serde_json::json!({
            "alg": "RS256",
            "nonce": nonce,
            "url": url,
        });
        match &self.kid {
            // RFC 8555 §6.2: "jwk" only for new-account / revoke-cert
            None => header["jwk"] = self.jwk(),
            // SERVER QUIRK: RFC 8555 §6.2 requires "kid" to be the full
            // account URL. ostrich-acme instead requires the literal relative
            // path "/acme/account/{account_id}" - validate_jws_with_account
            // does kid.strip_prefix("/acme/account/") (rest.rs ~line 239).
            // We therefore use the (relative) Location header verbatim.
            Some(kid) => header["kid"] = serde_json::json!(kid),
        }

        let protected_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
        // RFC 8555 §6.3: POST-as-GET uses the empty string as payload;
        // b64url("") == "" so this encoding handles both cases.
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let signing_input = format!("{}.{}", protected_b64, payload_b64);
        let signature = self.signing_key.sign(signing_input.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        let body = serde_json::json!({
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": signature_b64,
        });

        let response = self
            .http
            .post(url)
            .header("Content-Type", "application/jose+json")
            .body(body.to_string())
            .send()
            .await
            .unwrap_or_else(|e| panic!("POST {} failed: {}", url, e));

        self.harvest_nonce(&response);
        response
    }

    /// Plain GET against an ACME resource.
    ///
    /// SERVER QUIRK: RFC 8555 §6.3 requires POST-as-GET (signed JWS with
    /// empty payload) for fetching orders, authorizations and certificates.
    /// ostrich-acme instead exposes /acme/authz/{id}, /acme/order/{id} and
    /// /acme/cert/{id} as plain *unauthenticated* GET routes (rest.rs
    /// create_router), so the client uses plain GET here.
    async fn get(&mut self, url: &str) -> reqwest::Response {
        let response = self
            .http
            .get(url)
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET {} failed: {}", url, e));
        self.harvest_nonce(&response);
        response
    }
}

/// Fail with full diagnostics if the response status is not the expected one.
async fn expect_status(
    response: reqwest::Response,
    expected: reqwest::StatusCode,
    step: &str,
) -> (reqwest::header::HeaderMap, String) {
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.text().await.unwrap_or_default();
    assert_eq!(
        status, expected,
        "{}: expected {}, got {} - body: {}",
        step, expected, status, body
    );
    (headers, body)
}

// =============================================================================
// Local HTTP-01 challenge responder (RFC 8555 §8.3)
// =============================================================================

/// Serve GET /.well-known/acme-challenge/<token> -> "<token>.<thumbprint>"
/// on a hand-rolled HTTP/1.1 TCP loop (no extra dependencies).
async fn start_http01_responder(
    port: u16,
    token: String,
    key_authorization: String,
) -> tokio::task::JoinHandle<()> {
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .unwrap_or_else(|e| panic!("failed to bind HTTP-01 responder on port {}: {}", port, e));
    println!(
        "[http-01] responder listening on 0.0.0.0:{} for token {}",
        port, token
    );

    tokio::spawn(async move {
        loop {
            let Ok((mut socket, peer)) = listener.accept().await else {
                break;
            };
            let token = token.clone();
            let key_authorization = key_authorization.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = vec![0u8; 8192];
                let mut read = 0usize;
                // Read until end of request headers (or EOF / buffer full)
                loop {
                    match socket.read(&mut buf[read..]).await {
                        Ok(0) => break,
                        Ok(n) => {
                            read += n;
                            if buf[..read].windows(4).any(|w| w == b"\r\n\r\n")
                                || read == buf.len()
                            {
                                break;
                            }
                        }
                        Err(_) => return,
                    }
                }
                let request = String::from_utf8_lossy(&buf[..read]);
                let path = request.split_whitespace().nth(1).unwrap_or("");
                let expected_path = format!("/.well-known/acme-challenge/{}", token);
                println!("[http-01] request from {} for {}", peer, path);
                let response = if path == expected_path {
                    // RFC 8555 §8.3: body is the key authorization, text/plain
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        key_authorization.len(),
                        key_authorization
                    )
                } else {
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_string()
                };
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    })
}

// =============================================================================
// CSR generation (PKCS#10 via x509-cert builder, RSA-2048 certificate key)
// =============================================================================

/// Build a DER-encoded CSR with CN=localhost and SAN DNS:localhost, signed
/// with a SEPARATE RSA-2048 certificate key (never the account key - RFC 8555
/// §11.1 forbids reusing the account key for certificates).
fn build_csr_der(identifier: &str) -> Vec<u8> {
    use std::str::FromStr;
    use x509_cert::builder::{Builder, RequestBuilder};
    use x509_cert::der::Encode;
    use x509_cert::der::asn1::Ia5String;
    use x509_cert::ext::pkix::SubjectAltName;
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::name::Name;

    println!("[acme-client] generating RSA-2048 certificate key + CSR...");
    let cert_key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048)
        .expect("certificate RSA keygen failed");
    let csr_signer = SigningKey::<Sha256>::new(cert_key);

    let subject = Name::from_str(&format!("CN={}", identifier)).expect("invalid subject DN");
    let mut builder = RequestBuilder::new(subject, &csr_signer).expect("CSR builder");
    // RFC 8555 §7.4: CSR MUST contain the order identifiers as SANs
    // (the acme-default profile requires a SAN).
    builder
        .add_extension(&SubjectAltName(vec![GeneralName::DnsName(
            Ia5String::new(identifier).expect("invalid DNS name"),
        )]))
        .expect("add SAN extension");

    let csr = builder
        .build::<rsa::pkcs1v15::Signature>()
        .expect("CSR signing failed");
    csr.to_der().expect("CSR DER encoding failed")
}

// =============================================================================
// The test
// =============================================================================

/// Full ACME issuance flow: account -> order -> http-01 -> finalize -> cert.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SA-11, CA-2, SC-17
/// - RFC 8555 §7.1-§7.5, §8.3
#[tokio::test]
#[ignore = "requires live acme-server (ACME_URL) with CA backend and http-01 validator"]
async fn test_acme_full_issuance_flow() {
    let base_url = acme_url();
    let identifier = "localhost";
    println!("=== ACME full issuance flow against {} ===", base_url);

    let mut client = AcmeClient::new(base_url.clone());

    // -------------------------------------------------------------------
    // Step 1: Directory discovery (RFC 8555 §7.1.1)
    // -------------------------------------------------------------------
    println!("[step 1] GET {}/acme/directory", base_url);
    let response = client.get(&format!("{}/acme/directory", base_url)).await;
    let (_, dir_body) = expect_status(response, reqwest::StatusCode::OK, "directory").await;
    let directory: Directory = serde_json::from_str(&dir_body).unwrap_or_default();
    // Directory URLs are absolute (built from the server's ACME_BASE_URL);
    // fall back to conventional paths if fields are missing.
    let new_nonce_url = directory
        .new_nonce
        .unwrap_or_else(|| format!("{}/acme/new-nonce", base_url));
    let new_account_url = directory
        .new_account
        .unwrap_or_else(|| format!("{}/acme/new-account", base_url));
    let new_order_url = directory
        .new_order
        .unwrap_or_else(|| format!("{}/acme/new-order", base_url));
    println!("[step 1] newNonce={} newAccount={}", new_nonce_url, new_account_url);

    // -------------------------------------------------------------------
    // Step 2: Initial nonce (RFC 8555 §7.2)
    // -------------------------------------------------------------------
    println!("[step 2] GET new-nonce");
    let response = client.get(&new_nonce_url).await;
    assert!(
        client.nonce.is_some(),
        "new-nonce did not return Replay-Nonce header (status {})",
        response.status()
    );
    println!("[step 2] got initial Replay-Nonce");

    // -------------------------------------------------------------------
    // Step 3/4: Account creation (RFC 8555 §7.3, JWS with embedded JWK)
    // -------------------------------------------------------------------
    println!("[step 3] POST new-account");
    let payload = serde_json::json!({
        "termsOfServiceAgreed": true,
        "contact": ["mailto:e2e@example.com"],
    })
    .to_string();
    let response = client
        .post_jws(&new_nonce_url, &new_account_url, &payload)
        .await;
    let (headers, body) =
        expect_status(response, reqwest::StatusCode::CREATED, "new-account").await;
    // SERVER QUIRK: RFC 8555 §7.3 says the Location header is the (absolute)
    // account URL. ostrich-acme returns the relative path
    // "/acme/account/acct-<uuid>" (rest.rs new_account). We use it verbatim
    // as the kid because that is exactly what validate_jws_with_account
    // matches against.
    let account_location = headers
        .get("Location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_else(|| panic!("new-account response missing Location header; body: {}", body))
        .to_string();
    client.kid = Some(account_location.clone());
    println!("[step 3] account created, kid = {}", account_location);

    // SERVER QUIRK: validate_jws_with_account (rest.rs ~line 263) does
    // Uuid::parse_str(account.account_id), but new_account stores account_id
    // as "acct-<uuid>" (rest.rs ~line 504), which is not a parseable UUID.
    // As written, every kid-authenticated request (new-order, challenge,
    // finalize) fails with 500 "Invalid UUID in database" until the server
    // either stores bare UUIDs or strips the "acct-" prefix before parsing.
    // The client follows the RFC-intended flow and will surface that bug
    // as a new-order failure below.

    // -------------------------------------------------------------------
    // Step 5: New order (RFC 8555 §7.4)
    // -------------------------------------------------------------------
    println!("[step 5] POST new-order for identifier {}", identifier);
    let payload = serde_json::json!({
        "identifiers": [{"type": "dns", "value": identifier}],
    })
    .to_string();
    let response = client
        .post_jws(&new_nonce_url, &new_order_url, &payload)
        .await;
    let (headers, body) = expect_status(response, reqwest::StatusCode::CREATED, "new-order").await;
    let order_location = headers
        .get("Location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_else(|| panic!("new-order response missing Location header; body: {}", body))
        .to_string();
    let order: OrderObject =
        serde_json::from_str(&body).unwrap_or_else(|e| panic!("invalid order JSON: {} - {}", e, body));
    assert!(
        !order.authorizations.is_empty(),
        "order has no authorizations: {}",
        body
    );
    let authz_url = client.abs_url(&order.authorizations[0]);
    let finalize_url = client.abs_url(
        order
            .finalize
            .as_deref()
            .unwrap_or_else(|| panic!("order missing finalize URL: {}", body)),
    );
    let order_url = client.abs_url(&order_location);
    println!(
        "[step 5] order created: {} (status={}, authz={})",
        order_url, order.status, authz_url
    );

    // -------------------------------------------------------------------
    // Step 6: Fetch authorization + http-01 challenge (RFC 8555 §7.5)
    // (plain GET - see SERVER QUIRK on AcmeClient::get)
    // -------------------------------------------------------------------
    println!("[step 6] GET authorization {}", authz_url);
    let response = client.get(&authz_url).await;
    let (_, body) = expect_status(response, reqwest::StatusCode::OK, "get-authorization").await;
    let authz: AuthzObject =
        serde_json::from_str(&body).unwrap_or_else(|e| panic!("invalid authz JSON: {} - {}", e, body));
    let challenge = authz
        .challenges
        .iter()
        .find(|c| c.challenge_type == "http-01")
        .unwrap_or_else(|| panic!("no http-01 challenge offered: {}", body));
    let challenge_url = client.abs_url(&challenge.url);
    let token = challenge.token.clone();
    println!(
        "[step 6] http-01 challenge: url={} token={}",
        challenge_url, token
    );

    // -------------------------------------------------------------------
    // Step 7: Serve the key authorization (RFC 8555 §8.1/§8.3)
    // -------------------------------------------------------------------
    let key_authorization = format!("{}.{}", token, client.jwk_thumbprint());
    let responder = start_http01_responder(http01_port(), token.clone(), key_authorization).await;

    // -------------------------------------------------------------------
    // Step 8: Trigger challenge validation and poll (RFC 8555 §7.5.1)
    // -------------------------------------------------------------------
    println!("[step 8] POST {{}} to challenge {}", challenge_url);
    let response = client
        .post_jws(&new_nonce_url, &challenge_url, "{}")
        .await;
    let (_, body) = expect_status(response, reqwest::StatusCode::OK, "respond-to-challenge").await;
    println!("[step 8] challenge response accepted: {}", body);

    // SERVER QUIRK: respond_to_challenge only flips the challenge to
    // "processing" (rest.rs, "TODO: Trigger actual validation (Phase 11)")
    // and services/acme-server/src/main.rs wires no background validation
    // worker, so nothing ever marks the challenge/authorization "valid"
    // unless the E2E environment adds one (Http01Validator exists in
    // crates/ostrich-acme/src/validation.rs with .with_http_port() and
    // .insecure_allow_private_domains() for exactly this setup). This poll
    // times out against a stock server until that is wired up.
    println!("[step 8] polling authorization until valid (timeout {:?})", POLL_TIMEOUT);
    let deadline = Instant::now() + POLL_TIMEOUT;
    loop {
        let response = client.get(&authz_url).await;
        let (_, body) =
            expect_status(response, reqwest::StatusCode::OK, "poll-authorization").await;
        let authz: AuthzObject = serde_json::from_str(&body)
            .unwrap_or_else(|e| panic!("invalid authz JSON: {} - {}", e, body));
        let challenge_error = authz.challenges.iter().find_map(|c| c.error.clone());
        match authz.status.as_str() {
            "valid" => {
                println!("[step 8] authorization valid");
                break;
            }
            "invalid" => panic!(
                "authorization went invalid; challenge error: {:?}",
                challenge_error
            ),
            status => {
                let http01_status = authz
                    .challenges
                    .iter()
                    .find(|c| c.challenge_type == "http-01")
                    .map(|c| c.status.as_str())
                    .unwrap_or("<missing>");
                assert!(
                    Instant::now() < deadline,
                    "timed out waiting for authorization to become valid; \
                     authz status: {}, http-01 status: {}, challenge error: {:?}",
                    status,
                    http01_status,
                    challenge_error
                );
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        }
    }

    // -------------------------------------------------------------------
    // Step 9: Finalize with CSR (RFC 8555 §7.4)
    // -------------------------------------------------------------------
    let csr_der = build_csr_der(identifier);
    let csr_b64 = URL_SAFE_NO_PAD.encode(&csr_der);
    println!("[step 9] POST finalize {} ({} byte CSR)", finalize_url, csr_der.len());
    let payload = serde_json::json!({ "csr": csr_b64 }).to_string();
    let response = client
        .post_jws(&new_nonce_url, &finalize_url, &payload)
        .await;
    let (_, body) = expect_status(response, reqwest::StatusCode::OK, "finalize-order").await;
    println!("[step 9] finalize accepted: {}", body);

    // -------------------------------------------------------------------
    // Step 10: Poll order until valid, then download the certificate
    // -------------------------------------------------------------------
    println!("[step 10] polling order {} until valid", order_url);
    let deadline = Instant::now() + POLL_TIMEOUT;
    let final_order: OrderObject = loop {
        let response = client.get(&order_url).await;
        let (_, body) = expect_status(response, reqwest::StatusCode::OK, "poll-order").await;
        let order: OrderObject = serde_json::from_str(&body)
            .unwrap_or_else(|e| panic!("invalid order JSON: {} - {}", e, body));
        match order.status.as_str() {
            "valid" => break order,
            "invalid" => panic!("order went invalid; error: {:?}", order.error),
            other => {
                assert!(
                    Instant::now() < deadline,
                    "timed out waiting for order to become valid; last status: {}",
                    other
                );
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        }
    };

    // SERVER QUIRK: the order's "certificate" field is
    // "/acme/cert/{certificate_id}" (map_db_order_to_service), but the
    // /acme/cert/{id} handler (get_certificate) treats the path id as the
    // ACME *order* id - it calls find_order_by_id(id) and then resolves the
    // order's certificate. Following the certificate field as returned would
    // 404; the working URL is /acme/cert/{order_id}. We derive it from the
    // order URL instead of trusting the certificate field.
    let order_id = order_url
        .rsplit('/')
        .next()
        .expect("order URL has no path segments");
    let cert_url = format!("{}/acme/cert/{}", base_url, order_id);
    println!(
        "[step 10] order valid (certificate field = {:?}); downloading {}",
        final_order.certificate, cert_url
    );
    // Plain GET - see SERVER QUIRK on AcmeClient::get (RFC 8555 §7.4.2
    // requires POST-as-GET with Accept: application/pem-certificate-chain).
    let response = client.get(&cert_url).await;
    let (_, pem_chain) =
        expect_status(response, reqwest::StatusCode::OK, "download-certificate").await;

    // -------------------------------------------------------------------
    // Step 11: Assertions on the issued certificate (RFC 5280)
    // -------------------------------------------------------------------
    println!("[step 11] validating issued certificate ({} bytes PEM)", pem_chain.len());
    assert!(
        pem_chain.contains("-----BEGIN CERTIFICATE-----"),
        "response is not a PEM certificate chain: {}",
        &pem_chain[..pem_chain.len().min(200)]
    );

    let pem = x509_parser::pem::Pem::iter_from_buffer(pem_chain.as_bytes())
        .next()
        .expect("no PEM block in certificate chain")
        .expect("invalid PEM block");
    let cert = pem.parse_x509().expect("failed to parse issued certificate");

    // SAN contains DNS:localhost (RFC 5280 §4.2.1.6; acme-default profile)
    let san = cert
        .subject_alternative_name()
        .expect("malformed SAN extension")
        .expect("certificate missing SAN extension");
    let has_dns_localhost = san.value.general_names.iter().any(
        |gn| matches!(gn, x509_parser::extensions::GeneralName::DNSName(d) if *d == identifier),
    );
    assert!(
        has_dns_localhost,
        "SAN does not contain DNS:{} - SAN: {:?}",
        identifier, san.value.general_names
    );
    println!("[step 11] SAN contains DNS:{}", identifier);

    // Issuer CN
    let issuer_cn = cert
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .expect("issuer has no CN");
    assert_eq!(
        issuer_cn, "OstrichPKI Root CA",
        "unexpected issuer CN: {}",
        issuer_cn
    );
    println!("[step 11] issuer CN = {}", issuer_cn);

    // Validity <= 90 days (acme-default profile). Allow 5 minutes of slack
    // for inclusive notBefore/notAfter boundary handling.
    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();
    let validity_secs = not_after - not_before;
    assert!(
        validity_secs <= MAX_VALIDITY_SECS + 300,
        "certificate validity {} seconds exceeds 90 days",
        validity_secs
    );
    println!(
        "[step 11] validity = {} days (<= 90)",
        validity_secs / 86400
    );

    responder.abort();
    println!("=== ACME full issuance flow PASSED ===");
}
