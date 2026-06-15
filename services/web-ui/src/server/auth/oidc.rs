//! OpenID Connect Client
//!
//! Provides OIDC client functionality for Keycloak integration.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: IA-2 (Identification and Authentication)
//! - NIST 800-53: IA-8 (External Identity Provider)
//! - NIST 800-53: SC-8 (Transmission Confidentiality)

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ostrich_common::util::random::secure_random_bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::RwLock;
use url::Url;
use url::form_urlencoded;

use super::super::config::OidcConfig;

/// OpenID Connect client wrapper
pub struct OidcClient {
    config: OidcConfig,
    http_client: reqwest::Client,
    auth_url: Url,
    token_url: Url,
    // In-memory PKCE state storage (use Redis in production)
    pkce_states: Arc<RwLock<std::collections::HashMap<String, PkceStateData>>>,
}

/// PKCE state stored during authorization flow
#[derive(Debug)]
struct PkceStateData {
    verifier: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

/// User information extracted from ID token / userinfo endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcUserInfo {
    pub subject: String,
    pub username: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    pub roles: Vec<String>,
}

/// Token response from the token endpoint
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[allow(dead_code)]
    token_type: String,
    #[allow(dead_code)]
    expires_in: Option<u64>,
    #[allow(dead_code)]
    refresh_token: Option<String>,
    #[allow(dead_code)]
    id_token: Option<String>,
}

impl OidcClient {
    /// Create a new OIDC client with the given configuration
    pub async fn new(config: &OidcConfig) -> Result<Self> {
        // For Keycloak, construct the URLs from issuer
        let auth_url = Url::parse(&format!(
            "{}/protocol/openid-connect/auth",
            config.issuer_url
        ))
        .context("Invalid auth URL")?;

        let token_url = Url::parse(&format!(
            "{}/protocol/openid-connect/token",
            config.issuer_url
        ))
        .context("Invalid token URL")?;

        // Create HTTP client for token exchange
        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("Failed to create HTTP client")?;

        tracing::info!(
            issuer = %config.issuer_url,
            client_id = %config.client_id,
            "OIDC client initialized"
        );

        Ok(Self {
            config: config.clone(),
            http_client,
            auth_url,
            token_url,
            pkce_states: Arc::new(RwLock::new(std::collections::HashMap::new())),
        })
    }

    /// Check if the OIDC provider is reachable
    pub async fn is_ready(&self) -> bool {
        // Try to reach the well-known endpoint
        let well_known_url = format!(
            "{}/.well-known/openid-configuration",
            self.config.issuer_url
        );

        match self.http_client.get(&well_known_url).send().await {
            Ok(response) => response.status().is_success(),
            Err(_) => false,
        }
    }

    /// Generate an authorization URL for the OAuth flow
    ///
    /// Uses PKCE (Proof Key for Code Exchange) for enhanced security.
    /// Returns the authorization URL and the state parameter.
    pub async fn authorize_url(&self) -> Result<(Url, String)> {
        // Generate PKCE challenge
        // NIST 800-53: SC-13 - Cryptographic Protection
        let verifier = generate_pkce_verifier();
        let challenge = generate_pkce_challenge(&verifier);

        // Generate CSRF state token
        let state = generate_state_token();

        // Store PKCE verifier
        {
            let mut states = self.pkce_states.write().await;
            states.insert(
                state.clone(),
                PkceStateData {
                    verifier,
                    created_at: chrono::Utc::now(),
                },
            );

            // Clean up old states (older than 10 minutes)
            let cutoff = chrono::Utc::now() - chrono::Duration::minutes(10);
            states.retain(|_, v| v.created_at > cutoff);
        }

        // Build authorization URL
        let mut auth_url = self.auth_url.clone();
        auth_url
            .query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &self.config.redirect_uri)
            .append_pair("scope", &self.config.scopes.join(" "))
            .append_pair("state", &state)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");

        Ok((auth_url, state))
    }

    /// Exchange authorization code for tokens
    ///
    /// Validates the CSRF state and exchanges the code using the stored PKCE verifier.
    pub async fn exchange_code(&self, code: &str, state: &str) -> Result<OidcUserInfo> {
        // Retrieve and remove PKCE state
        let pkce_data = {
            let mut states = self.pkce_states.write().await;
            states
                .remove(state)
                .context("Invalid or expired OAuth state")?
        };

        // Build token request body (URL-encoded form)
        // Note: We construct the body in a separate block to ensure the encoder
        // is dropped before any await points, as the Serializer is not Send.
        let body = {
            let mut encoder = form_urlencoded::Serializer::new(String::new());
            encoder.append_pair("grant_type", "authorization_code");
            encoder.append_pair("code", code);
            encoder.append_pair("redirect_uri", &self.config.redirect_uri);
            encoder.append_pair("client_id", &self.config.client_id);
            encoder.append_pair("code_verifier", &pkce_data.verifier);

            // Add client secret if configured
            if let Some(ref secret) = self.config.client_secret {
                encoder.append_pair("client_secret", secret);
            }

            encoder.finish()
        };

        // Exchange code for tokens
        let token_response = self
            .http_client
            .post(self.token_url.as_str())
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .context("Failed to send token request")?;

        if !token_response.status().is_success() {
            let status = token_response.status();
            let error_body = token_response.text().await.unwrap_or_default();
            anyhow::bail!("Token exchange failed: {} - {}", status, error_body);
        }

        let tokens: TokenResponse = token_response
            .json()
            .await
            .context("Failed to parse token response")?;

        // Fetch user info from userinfo endpoint
        let userinfo_url = format!(
            "{}/protocol/openid-connect/userinfo",
            self.config.issuer_url
        );

        let userinfo_response = self
            .http_client
            .get(&userinfo_url)
            .bearer_auth(&tokens.access_token)
            .send()
            .await
            .context("Failed to fetch userinfo")?;

        if !userinfo_response.status().is_success() {
            anyhow::bail!("Userinfo request failed: {}", userinfo_response.status());
        }

        let userinfo: serde_json::Value = userinfo_response
            .json()
            .await
            .context("Failed to parse userinfo response")?;

        // Extract user info from response
        let user_info = self.parse_userinfo(&userinfo);

        tracing::info!(
            subject = %user_info.subject,
            username = ?user_info.username,
            roles = ?user_info.roles,
            "User authenticated via OIDC"
        );

        Ok(user_info)
    }

    /// Parse userinfo response into OidcUserInfo
    fn parse_userinfo(&self, userinfo: &serde_json::Value) -> OidcUserInfo {
        let subject = userinfo["sub"].as_str().unwrap_or("unknown").to_string();

        let username = userinfo["preferred_username"]
            .as_str()
            .map(|s| s.to_string());

        let email = userinfo["email"].as_str().map(|s| s.to_string());

        let email_verified = userinfo["email_verified"].as_bool();

        let name = userinfo["name"].as_str().map(|s| s.to_string());

        // Extract roles from Keycloak-specific claims
        let roles = self.extract_roles(userinfo);

        OidcUserInfo {
            subject,
            username,
            email,
            email_verified,
            name,
            roles,
        }
    }

    /// Extract roles from Keycloak-specific claims
    fn extract_roles(&self, userinfo: &serde_json::Value) -> Vec<String> {
        // Try realm_access.roles first (Keycloak default)
        if let Some(realm_access) = userinfo.get("realm_access") {
            if let Some(roles) = realm_access.get("roles") {
                if let Some(roles_array) = roles.as_array() {
                    return roles_array
                        .iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect();
                }
            }
        }

        // Try resource_access.<client_id>.roles
        if let Some(resource_access) = userinfo.get("resource_access") {
            if let Some(client_roles) = resource_access.get(&self.config.client_id) {
                if let Some(roles) = client_roles.get("roles") {
                    if let Some(roles_array) = roles.as_array() {
                        return roles_array
                            .iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect();
                    }
                }
            }
        }

        // Try groups claim
        if let Some(groups) = userinfo.get("groups") {
            if let Some(groups_array) = groups.as_array() {
                return groups_array
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
            }
        }

        Vec::new()
    }
}

/// Generate a PKCE code verifier (43-128 characters, URL-safe)
fn generate_pkce_verifier() -> String {
    let bytes = secure_random_bytes(32);
    URL_SAFE_NO_PAD.encode(&bytes)
}

/// Generate PKCE code challenge (S256 method)
fn generate_pkce_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();
    URL_SAFE_NO_PAD.encode(&hash)
}

/// Generate a random state token
fn generate_state_token() -> String {
    let bytes = secure_random_bytes(32);
    URL_SAFE_NO_PAD.encode(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkce_challenge() {
        let verifier = generate_pkce_verifier();
        let challenge = generate_pkce_challenge(&verifier);

        // Verifier should be URL-safe base64
        assert!(!verifier.contains('+'));
        assert!(!verifier.contains('/'));

        // Challenge should be URL-safe base64
        assert!(!challenge.contains('+'));
        assert!(!challenge.contains('/'));

        // Challenge should be different from verifier
        assert_ne!(verifier, challenge);
    }

    #[test]
    fn test_role_extraction() {
        let userinfo = serde_json::json!({
            "sub": "user-123",
            "preferred_username": "testuser",
            "realm_access": {
                "roles": ["admin", "user", "auditor"]
            }
        });

        let config = OidcConfig {
            issuer_url: "https://example.com".to_string(),
            client_id: "test-client".to_string(),
            client_secret: None,
            redirect_uri: "https://app.example.com/callback".to_string(),
            scopes: vec!["openid".to_string()],
            roles_claim: "realm_access.roles".to_string(),
        };

        let http_client = reqwest::Client::new();

        let oidc_client = OidcClient {
            config,
            http_client,
            auth_url: Url::parse("https://example.com/auth").unwrap(),
            token_url: Url::parse("https://example.com/token").unwrap(),
            pkce_states: Arc::new(RwLock::new(std::collections::HashMap::new())),
        };

        let roles = oidc_client.extract_roles(&userinfo);
        assert_eq!(roles, vec!["admin", "user", "auditor"]);
    }
}
