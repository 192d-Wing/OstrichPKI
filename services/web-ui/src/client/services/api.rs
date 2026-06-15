//! API Client Service
//!
//! Provides HTTP client utilities for calling backend APIs.

use gloo_net::http::Request;
use serde::de::DeserializeOwned;

/// API error type
#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: u16,
    pub message: String,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "API Error {}: {}", self.status, self.message)
    }
}

/// API client for making requests to backend services
pub struct ApiClient {
    base_url: String,
}

impl Default for ApiClient {
    fn default() -> Self {
        Self {
            base_url: "/api".to_string(),
        }
    }
}

impl ApiClient {
    /// Create a new API client with custom base URL
    pub fn new(base_url: String) -> Self {
        Self { base_url }
    }

    /// Make a GET request
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        let url = format!("{}{}", self.base_url, path);

        let response = Request::get(&url).send().await.map_err(|e| ApiError {
            status: 0,
            message: e.to_string(),
        })?;

        if !response.ok() {
            return Err(ApiError {
                status: response.status(),
                message: response.status_text(),
            });
        }

        response.json().await.map_err(|e| ApiError {
            status: 0,
            message: format!("Failed to parse response: {}", e),
        })
    }

    /// Make a POST request
    pub async fn post<T: DeserializeOwned, B: serde::Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, ApiError> {
        let url = format!("{}{}", self.base_url, path);

        let response = Request::post(&url)
            .json(body)
            .map_err(|e| ApiError {
                status: 0,
                message: e.to_string(),
            })?
            .send()
            .await
            .map_err(|e| ApiError {
                status: 0,
                message: e.to_string(),
            })?;

        if !response.ok() {
            return Err(ApiError {
                status: response.status(),
                message: response.status_text(),
            });
        }

        response.json().await.map_err(|e| ApiError {
            status: 0,
            message: format!("Failed to parse response: {}", e),
        })
    }

    /// Make a DELETE request
    pub async fn delete(&self, path: &str) -> Result<(), ApiError> {
        let url = format!("{}{}", self.base_url, path);

        let response = Request::delete(&url).send().await.map_err(|e| ApiError {
            status: 0,
            message: e.to_string(),
        })?;

        if !response.ok() {
            return Err(ApiError {
                status: response.status(),
                message: response.status_text(),
            });
        }

        Ok(())
    }
}

/// Global API client instance
pub fn api() -> ApiClient {
    ApiClient::default()
}
