//! HTTP client utilities for integration tests

use reqwest::{Client, Response};
use std::time::Duration;

/// Create a test HTTP client with reasonable defaults
pub fn create_test_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .danger_accept_invalid_certs(true) // For testing with self-signed certs
        .build()
        .expect("Failed to create HTTP client")
}

/// Create a test HTTPS client with mTLS support
pub fn create_mtls_client(
    client_cert_pem: &str,
    client_key_pem: &str,
) -> Result<Client, Box<dyn std::error::Error>> {
    let client_cert =
        reqwest::Identity::from_pem(format!("{}{}", client_cert_pem, client_key_pem).as_bytes())?;

    Ok(Client::builder()
        .timeout(Duration::from_secs(30))
        .danger_accept_invalid_certs(true)
        .identity(client_cert)
        .build()?)
}

/// Assert HTTP response status code
pub async fn assert_status(response: Response, expected_status: reqwest::StatusCode) -> Response {
    let actual_status = response.status();
    if actual_status != expected_status {
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| String::from("<no body>"));
        panic!(
            "Expected status {}, got {}. Body: {}",
            expected_status, actual_status, body
        );
    }
    response
}

/// Assert HTTP response contains JSON
pub async fn assert_json<T: serde::de::DeserializeOwned>(response: Response) -> T {
    response
        .json::<T>()
        .await
        .expect("Failed to parse JSON response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_test_client() {
        let client = create_test_client();
        // Just verify we can create a client
        assert!(true);
    }
}
