//! Content Security Policy (CSP) Middleware
//!
//! This middleware generates cryptographic nonces for inline scripts and styles,
//! and sets appropriate CSP headers on responses.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-8 (Transmission Confidentiality and Integrity)
//! - NIST 800-53: SC-18 (Mobile Code) - Restricts executable content
//! - NIST 800-53: SI-10 (Information Input Validation) - Prevents XSS
//! - NIAP PP-CA: FPT_TRP_EXT.1 (Trusted Path) - Secure communication

use axum::{
    body::Body,
    extract::Request,
    http::{HeaderValue, header},
    middleware::Next,
    response::Response,
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use ostrich_common::util::random::secure_random_bytes;

/// Default nonce length in bytes (128 bits)
const DEFAULT_NONCE_LENGTH: usize = 16;

/// CSP Nonce wrapper for extension injection
/// This is stored in request extensions and used by template rendering
#[derive(Clone, Debug)]
pub struct CspNonce(pub String);

impl CspNonce {
    /// Generate a new cryptographic nonce
    ///
    /// Uses the secure random generator from ostrich-common which
    /// leverages a cryptographically secure RNG.
    pub fn generate(length: usize) -> Self {
        // NIST 800-53: SC-13 - Cryptographic Protection
        // Use cryptographically secure random bytes
        let nonce_bytes = secure_random_bytes(length);
        let nonce_b64 = BASE64.encode(&nonce_bytes);
        Self(nonce_b64)
    }

    /// Get the nonce value for use in HTML attributes
    pub fn value(&self) -> &str {
        &self.0
    }
}

impl Default for CspNonce {
    fn default() -> Self {
        Self::generate(DEFAULT_NONCE_LENGTH)
    }
}

/// CSP middleware that generates nonces and sets security headers
///
/// This middleware:
/// 1. Generates a unique cryptographic nonce for each request
/// 2. Stores the nonce in request extensions for template injection
/// 3. Sets the Content-Security-Policy header on the response
/// 4. Adds additional security headers (X-Frame-Options, etc.)
pub async fn csp_middleware(mut request: Request, next: Next) -> Response {
    // Generate a fresh nonce for this request
    // NIST 800-53: SC-13 - Each request gets a unique nonce
    let nonce = CspNonce::generate(DEFAULT_NONCE_LENGTH);

    tracing::trace!(nonce_preview = %&nonce.0[..8], "Generated CSP nonce");

    // Store nonce in request extensions for template injection
    request.extensions_mut().insert(nonce.clone());

    // Process the request
    let mut response = next.run(request).await;

    // Build the CSP header value
    // NIST 800-53: SC-18 - Restrict mobile code execution
    let csp_value = build_csp_header(&nonce.0);

    // Set CSP header
    if let Ok(header_value) = HeaderValue::from_str(&csp_value) {
        response
            .headers_mut()
            .insert(header::CONTENT_SECURITY_POLICY, header_value);
    }

    // Add additional security headers
    add_security_headers(&mut response);

    response
}

/// Build the Content-Security-Policy header value
///
/// This creates a restrictive CSP that:
/// - Only allows scripts with the specific nonce
/// - Only allows styles with the specific nonce
/// - Allows WASM execution (required for Yew)
/// - Restricts other resource loading to same-origin
fn build_csp_header(nonce: &str) -> String {
    // style-src allows 'unsafe-inline': the React/Cloudscape UI (and Radix
    // before it) sets inline style="" attributes for dynamic layout, which a
    // nonce cannot cover — and a nonce in style-src would itself *disable*
    // 'unsafe-inline' per CSP. The XSS-critical script-src stays nonce-strict,
    // so this only relaxes style injection (a much lower-risk vector).
    // NIST 800-53: SC-18 - script execution remains nonce-gated.
    format!(
        "default-src 'self'; \
         script-src 'self' 'nonce-{nonce}' 'wasm-unsafe-eval'; \
         style-src 'self' 'unsafe-inline'; \
         img-src 'self' data:; \
         font-src 'self' data:; \
         connect-src 'self'; \
         frame-ancestors 'none'; \
         base-uri 'self'; \
         form-action 'self'; \
         upgrade-insecure-requests"
    )
}

/// Add additional security headers to the response
fn add_security_headers(response: &mut Response<Body>) {
    let headers = response.headers_mut();

    // Prevent clickjacking
    // NIST 800-53: SC-18 - Mobile code restrictions
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));

    // Prevent MIME type sniffing
    headers.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );

    // Enable XSS filter (legacy, but still useful for older browsers)
    headers.insert(
        "X-XSS-Protection",
        HeaderValue::from_static("1; mode=block"),
    );

    // Referrer policy - don't leak URLs
    headers.insert(
        "Referrer-Policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );

    // Permissions policy - restrict powerful features
    headers.insert(
        "Permissions-Policy",
        HeaderValue::from_static("accelerometer=(), camera=(), geolocation=(), microphone=()"),
    );
}

/// Configuration-aware CSP middleware builder
/// This struct allows customization of CSP directives for different deployment scenarios.
#[allow(dead_code)]
pub struct CspMiddlewareConfig {
    pub nonce_length: usize,
    pub additional_script_src: Vec<String>,
    pub additional_style_src: Vec<String>,
    pub additional_connect_src: Vec<String>,
}

impl Default for CspMiddlewareConfig {
    fn default() -> Self {
        Self {
            nonce_length: DEFAULT_NONCE_LENGTH,
            additional_script_src: Vec::new(),
            additional_style_src: Vec::new(),
            additional_connect_src: Vec::new(),
        }
    }
}

impl CspMiddlewareConfig {
    /// Build a CSP header with custom configuration
    #[allow(dead_code)]
    pub fn build_header(&self, nonce: &str) -> String {
        let script_src = if self.additional_script_src.is_empty() {
            format!("'self' 'nonce-{nonce}' 'wasm-unsafe-eval'")
        } else {
            format!(
                "'self' 'nonce-{nonce}' 'wasm-unsafe-eval' {}",
                self.additional_script_src.join(" ")
            )
        };

        let style_src = if self.additional_style_src.is_empty() {
            format!("'self' 'nonce-{nonce}'")
        } else {
            format!(
                "'self' 'nonce-{nonce}' {}",
                self.additional_style_src.join(" ")
            )
        };

        let connect_src = if self.additional_connect_src.is_empty() {
            "'self'".to_string()
        } else {
            format!("'self' {}", self.additional_connect_src.join(" "))
        };

        format!(
            "default-src 'self'; \
             script-src {script_src}; \
             style-src {style_src}; \
             img-src 'self' data:; \
             font-src 'self'; \
             connect-src {connect_src}; \
             frame-ancestors 'none'; \
             base-uri 'self'; \
             form-action 'self'; \
             upgrade-insecure-requests"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_generation() {
        let nonce1 = CspNonce::generate(16);
        let nonce2 = CspNonce::generate(16);

        // Nonces should be different
        assert_ne!(nonce1.0, nonce2.0);

        // Should be valid base64
        assert!(BASE64.decode(&nonce1.0).is_ok());
        assert!(BASE64.decode(&nonce2.0).is_ok());

        // Should decode to correct length
        let decoded = BASE64.decode(&nonce1.0).unwrap();
        assert_eq!(decoded.len(), 16);
    }

    #[test]
    fn test_csp_header_contains_nonce() {
        let nonce = "test-nonce-value";
        let csp = build_csp_header(nonce);

        assert!(csp.contains(&format!("'nonce-{nonce}'")));
        assert!(csp.contains("'wasm-unsafe-eval'"));
        assert!(csp.contains("frame-ancestors 'none'"));
    }

    #[test]
    fn test_config_builder() {
        let config = CspMiddlewareConfig {
            nonce_length: 32,
            additional_script_src: vec!["https://cdn.example.com".to_string()],
            additional_style_src: vec![],
            additional_connect_src: vec!["https://api.example.com".to_string()],
        };

        let header = config.build_header("test-nonce");

        assert!(header.contains("https://cdn.example.com"));
        assert!(header.contains("https://api.example.com"));
    }
}
