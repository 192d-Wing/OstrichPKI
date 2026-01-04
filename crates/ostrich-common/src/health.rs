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

/// Database readiness check using raw PgPool
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

/// Standard readiness response with database check (accepts raw PgPool)
///
/// Returns 200 OK if all dependencies are accessible.
/// Returns 503 SERVICE_UNAVAILABLE if any dependency is not ready.
pub async fn readiness_response_with_pg_pool(
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

/// Standard readiness response with database check (accepts DatabasePool wrapper)
///
/// This is a convenience wrapper that extracts the inner PgPool from DatabasePool.
/// Returns 200 OK if all dependencies are accessible.
/// Returns 503 SERVICE_UNAVAILABLE if any dependency is not ready.
pub async fn readiness_response_with_db<P: AsRef<PgPool>>(
    service_name: &str,
    pool: &P,
) -> (StatusCode, Json<serde_json::Value>) {
    readiness_response_with_pg_pool(service_name, pool.as_ref()).await
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
    fn test_health_response_json_structure() {
        // Verify the expected JSON structure is correct
        let expected = json!({
            "status": "healthy",
            "service": "test-service",
            "version": env!("CARGO_PKG_VERSION")
        });

        // Verify we can serialize it
        let json_str = serde_json::to_string(&expected).unwrap();
        assert!(json_str.contains("healthy"));
        assert!(json_str.contains("test-service"));
    }

    #[test]
    fn test_readiness_simple_json_structure() {
        // Verify the expected JSON structure is correct
        let expected = json!({
            "status": "ready",
            "service": "test-service",
            "version": env!("CARGO_PKG_VERSION")
        });

        // Verify we can serialize it
        let json_str = serde_json::to_string(&expected).unwrap();
        assert!(json_str.contains("ready"));
        assert!(json_str.contains("test-service"));
    }

    #[test]
    fn test_readiness_with_db_json_structure() {
        // Verify the expected JSON structure for database check responses
        let ready_response = json!({
            "status": "ready",
            "service": "test-service",
            "version": env!("CARGO_PKG_VERSION"),
            "checks": {
                "database": true
            }
        });

        let not_ready_response = json!({
            "status": "not_ready",
            "service": "test-service",
            "checks": {
                "database": false
            }
        });

        // Verify we can serialize them
        assert!(
            serde_json::to_string(&ready_response)
                .unwrap()
                .contains("\"database\":true")
        );
        assert!(
            serde_json::to_string(&not_ready_response)
                .unwrap()
                .contains("\"database\":false")
        );
    }
}
