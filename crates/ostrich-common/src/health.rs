//! Health check utilities for all services
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SI-17 (Fail-safe response)
//!
//! Provides standardized health and readiness check responses for Kubernetes
//! liveness and readiness probes.

use axum::{Json, http::StatusCode, response::IntoResponse};
use serde_json::json;
use sqlx::PgPool;

/// Standard health check response (liveness probe)
///
/// Returns 200 OK if the service process is running.
/// This is the simplest check - if the process can respond, it's alive.
pub fn health_response(service_name: &str) -> impl IntoResponse {
    Json(json!({
        "status": "healthy",
        "service": service_name,
        "version": env!("CARGO_PKG_VERSION")
    }))
}

/// Database readiness check
///
/// Returns true if database is accessible, false otherwise.
pub async fn check_database(pool: &PgPool) -> bool {
    match sqlx::query("SELECT 1").fetch_one(pool).await {
        Ok(_) => true,
        Err(e) => {
            tracing::warn!("Database readiness check failed: {}", e);
            false
        }
    }
}

/// Standard readiness response with database check
///
/// Returns 200 OK if all dependencies are accessible.
/// Returns 503 SERVICE_UNAVAILABLE if any dependency is not ready.
pub async fn readiness_response_with_db(
    service_name: &str,
    pool: &PgPool,
) -> (StatusCode, Json<serde_json::Value>) {
    let db_ok = check_database(pool).await;

    if !db_ok {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "not_ready",
                "service": service_name,
                "checks": {
                    "database": false
                }
            })),
        );
    }

    (
        StatusCode::OK,
        Json(json!({
            "status": "ready",
            "service": service_name,
            "version": env!("CARGO_PKG_VERSION"),
            "checks": {
                "database": true
            }
        })),
    )
}

/// Standard readiness response without database
///
/// For services that don't have database dependencies.
pub fn readiness_response_simple(service_name: &str) -> impl IntoResponse {
    Json(json!({
        "status": "ready",
        "service": service_name,
        "version": env!("CARGO_PKG_VERSION")
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_response() {
        let response = health_response("test-service");
        // Response should be serializable
        let json = serde_json::to_string(&response.0).unwrap();
        assert!(json.contains("healthy"));
        assert!(json.contains("test-service"));
    }

    #[test]
    fn test_readiness_response_simple() {
        let response = readiness_response_simple("test-service");
        let json = serde_json::to_string(&response.0).unwrap();
        assert!(json.contains("ready"));
        assert!(json.contains("test-service"));
    }
}
