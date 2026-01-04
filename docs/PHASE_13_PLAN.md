# Phase 13: Advanced Features - Comprehensive Implementation Plan

> **Status**: Planned (Deferred Post-v1.0)
> **Priority**: ⚪ LOW (Optional Enhancements)
> **Effort**: 3-4 weeks
> **Dependencies**: Phases 1-15 complete

---

## Executive Summary

Phase 13 encompasses **123 TODO items** identified across the codebase, plus additional enhancements for production readiness. This phase is **optional** and deferred post-v1.0 launch, as all critical functionality is complete.

**Scope Categories**:

1. **JSON Configuration with Schema Validation** (14 TODOs) - Priority: HIGH
2. **IP Literal Remediation** (5 files) - Priority: HIGH
3. **IPv6 Native Support** (NEW) - Priority: HIGH
4. **SCMS PKCS#11 Token Operations** (29 TODOs) - Priority: MEDIUM
5. **Audit Logging Hookups** (21 TODOs) - Priority: MEDIUM
6. **Service Integration Enhancements** (15 TODOs) - Priority: LOW
7. **Advanced Protocol Features** (8 TODOs) - Priority: LOW
8. **Database Schema Extensions** (11 TODOs) - Priority: LOW
9. **Minor Enhancements** (25 TODOs) - Priority: LOW

---

## Table of Contents

- [Track 1: High Priority (Production Readiness)](#track-1-high-priority-production-readiness)
  - [1.1 Configuration Management](#11-configuration-management)
  - [1.2 IPv6 Native Support](#12-ipv6-native-support)
- [Track 2: Medium Priority (Operational Improvements)](#track-2-medium-priority-operational-improvements)
  - [2.1 SCMS PKCS#11 Token Operations](#21-scms-pkcs11-token-operations)
  - [2.2 Audit Logging Hookups](#22-audit-logging-hookups)
- [Track 3: Low Priority (Advanced Features)](#track-3-low-priority-advanced-features)
  - [3.1 Enhanced CSR Processing](#31-enhanced-csr-processing)
  - [3.2 OCSP Response Caching](#32-ocsp-response-caching)
  - [3.3 EST Server-Side Key Generation](#33-est-server-side-key-generation)
  - [3.4 Database Schema Extensions](#34-database-schema-extensions)
  - [3.5 Service Integration Enhancements](#35-service-integration-enhancements)
- [Implementation Timeline](#implementation-timeline)
- [Testing Strategy](#testing-strategy)
- [Success Criteria](#success-criteria)

---

## Track 1: High Priority (Production Readiness)

### 1.1 Configuration Management

**Effort**: 4 days | **Priority**: 🔴 HIGH | **Blocks**: Production deployment

#### Overview

Replace hardcoded URLs and configuration values with externalized JSON-based configuration system with JSON Schema validation.

#### Current Issues

**URL Hardcoding** (14 TODOs):

- `crates/ostrich-acme/src/rest.rs`: 6 instances of `"https://example.com/acme/..."`
- All ACME endpoints use placeholder URLs
- No base URL configuration

**IP Literal Hardcoding** (Found in codebase):

- `crates/ostrich-audit/src/event.rs`: Test IP literals (`192.168.1.1`, `10.0.0.1`)
- `crates/ostrich-common/src/auth/lockout.rs`: Test IP literals (`192.168.1.1`)
- `crates/ostrich-common/src/auth/session.rs`: Test IP literals (`192.168.1.1`)
- `crates/ostrich-db/src/models/audit.rs`: Test IP literals (`192.168.1.100`, `10.0.0.1`)
- `crates/ostrich-acme/src/validation.rs`: Test IP literals for SSRF testing

**Configuration Gaps**:

- No centralized config file support
- Environment variables scattered across services
- No configuration validation on startup
- No schema-based validation

#### Implementation Tasks

##### 1.1.1 Create JSON Schema for Configuration Validation

**File**: `config/schema/ostrich-config.schema.json` (new)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://ostrichpki.example.com/schemas/config.schema.json",
  "title": "OstrichPKI Configuration",
  "description": "Configuration schema for OstrichPKI services - NIAP PP-CA: FMT_MSA.1, FMT_SMF.1",
  "type": "object",
  "required": ["service", "database", "logging"],
  "properties": {
    "$schema": {
      "type": "string",
      "description": "JSON Schema reference for validation"
    },
    "service": {
      "$ref": "#/$defs/serviceConfig"
    },
    "database": {
      "$ref": "#/$defs/databaseConfig"
    },
    "tls": {
      "$ref": "#/$defs/tlsConfig"
    },
    "acme": {
      "$ref": "#/$defs/acmeConfig"
    },
    "est": {
      "$ref": "#/$defs/estConfig"
    },
    "ca": {
      "$ref": "#/$defs/caConfig"
    },
    "ocsp": {
      "$ref": "#/$defs/ocspConfig"
    },
    "kra": {
      "$ref": "#/$defs/kraConfig"
    },
    "scms": {
      "$ref": "#/$defs/scmsConfig"
    },
    "logging": {
      "$ref": "#/$defs/loggingConfig"
    }
  },
  "$defs": {
    "serviceConfig": {
      "type": "object",
      "description": "Core service configuration",
      "required": ["name", "listen", "baseUrl"],
      "properties": {
        "name": {
          "type": "string",
          "description": "Service name for identification",
          "pattern": "^[a-z][a-z0-9-]*$",
          "minLength": 1,
          "maxLength": 64
        },
        "listen": {
          "$ref": "#/$defs/listenConfig"
        },
        "baseUrl": {
          "type": "string",
          "description": "Public base URL (must use hostname, not IP literal)",
          "format": "uri",
          "pattern": "^https?://[a-zA-Z][a-zA-Z0-9.-]*"
        },
        "maxBodySize": {
          "type": "integer",
          "description": "Maximum request body size in bytes",
          "minimum": 1024,
          "maximum": 104857600,
          "default": 1048576
        },
        "requestTimeoutSeconds": {
          "type": "integer",
          "description": "Request timeout in seconds",
          "minimum": 1,
          "maximum": 300,
          "default": 30
        }
      },
      "additionalProperties": false
    },
    "listenConfig": {
      "type": "object",
      "description": "Network listen configuration - NO IP LITERALS ALLOWED",
      "required": ["host", "port"],
      "properties": {
        "host": {
          "type": "string",
          "description": "Listen hostname (use '::' for dual-stack, hostname for specific interface)",
          "oneOf": [
            { "const": "::", "description": "Dual-stack (IPv4+IPv6)" },
            { "const": "0.0.0.0", "description": "All IPv4 interfaces (deprecated, use '::')" },
            { "pattern": "^[a-zA-Z][a-zA-Z0-9.-]*$", "description": "Hostname" }
          ]
        },
        "port": {
          "type": "integer",
          "description": "Listen port",
          "minimum": 1,
          "maximum": 65535
        }
      },
      "additionalProperties": false
    },
    "databaseConfig": {
      "type": "object",
      "description": "Database connection configuration",
      "required": ["host", "port", "database", "username"],
      "properties": {
        "host": {
          "type": "string",
          "description": "Database hostname (NO IP LITERALS)",
          "pattern": "^[a-zA-Z][a-zA-Z0-9.-]*$"
        },
        "port": {
          "type": "integer",
          "minimum": 1,
          "maximum": 65535,
          "default": 5432
        },
        "database": {
          "type": "string",
          "pattern": "^[a-zA-Z][a-zA-Z0-9_]*$"
        },
        "username": {
          "type": "string"
        },
        "password": {
          "type": "string",
          "description": "Database password (use $ENV{VAR} for environment variable reference)"
        },
        "poolSize": {
          "type": "integer",
          "minimum": 1,
          "maximum": 100,
          "default": 10
        },
        "sslMode": {
          "type": "string",
          "enum": ["disable", "prefer", "require", "verify-ca", "verify-full"],
          "default": "require"
        }
      },
      "additionalProperties": false
    },
    "tlsConfig": {
      "type": "object",
      "description": "TLS configuration - NIAP PP-CA: FTP_ITC.1",
      "required": ["certFile", "keyFile"],
      "properties": {
        "certFile": {
          "type": "string",
          "description": "Path to TLS certificate file"
        },
        "keyFile": {
          "type": "string",
          "description": "Path to TLS private key file"
        },
        "caFile": {
          "type": "string",
          "description": "Path to CA certificate for client verification"
        },
        "minVersion": {
          "type": "string",
          "enum": ["1.2", "1.3"],
          "default": "1.3",
          "description": "Minimum TLS version (1.3 required for NIAP compliance)"
        },
        "clientAuth": {
          "type": "string",
          "enum": ["none", "request", "require"],
          "default": "none"
        }
      },
      "additionalProperties": false
    },
    "acmeConfig": {
      "type": "object",
      "description": "ACME service configuration - RFC 8555",
      "properties": {
        "directoryUrl": {
          "type": "string",
          "format": "uri",
          "description": "ACME directory URL (NO IP LITERALS)",
          "pattern": "^https://[a-zA-Z][a-zA-Z0-9.-]*"
        },
        "termsOfServiceUrl": {
          "type": "string",
          "format": "uri"
        },
        "nonceExpirationSeconds": {
          "type": "integer",
          "minimum": 60,
          "maximum": 3600,
          "default": 900
        },
        "orderExpirationSeconds": {
          "type": "integer",
          "minimum": 3600,
          "maximum": 604800,
          "default": 86400
        },
        "maxIdentifiersPerOrder": {
          "type": "integer",
          "minimum": 1,
          "maximum": 100,
          "default": 10
        },
        "challengeTypes": {
          "type": "array",
          "items": {
            "type": "string",
            "enum": ["http-01", "dns-01", "tls-alpn-01"]
          },
          "default": ["http-01", "dns-01"]
        }
      },
      "additionalProperties": false
    },
    "estConfig": {
      "type": "object",
      "description": "EST service configuration - RFC 7030",
      "properties": {
        "requireClientCert": {
          "type": "boolean",
          "default": true,
          "description": "Require mTLS client certificate"
        },
        "allowServerKeygen": {
          "type": "boolean",
          "default": false,
          "description": "Allow server-side key generation (security risk)"
        },
        "escrowServerKeys": {
          "type": "boolean",
          "default": true,
          "description": "Escrow server-generated keys via KRA"
        }
      },
      "additionalProperties": false
    },
    "caConfig": {
      "type": "object",
      "description": "Certificate Authority configuration",
      "properties": {
        "grpcEndpoint": {
          "type": "string",
          "format": "uri",
          "description": "CA gRPC endpoint (NO IP LITERALS)",
          "pattern": "^https://[a-zA-Z][a-zA-Z0-9.-]*"
        },
        "defaultProfile": {
          "type": "string",
          "default": "end-entity"
        },
        "maxValidityDays": {
          "type": "integer",
          "minimum": 1,
          "maximum": 3650,
          "default": 825
        }
      },
      "additionalProperties": false
    },
    "ocspConfig": {
      "type": "object",
      "description": "OCSP responder configuration - RFC 6960",
      "properties": {
        "cacheEnabled": {
          "type": "boolean",
          "default": true
        },
        "cacheSize": {
          "type": "integer",
          "minimum": 100,
          "maximum": 1000000,
          "default": 10000
        },
        "cacheTtlSeconds": {
          "type": "integer",
          "minimum": 60,
          "maximum": 86400,
          "default": 3600
        }
      },
      "additionalProperties": false
    },
    "kraConfig": {
      "type": "object",
      "description": "Key Recovery Authority configuration",
      "properties": {
        "shamirThreshold": {
          "type": "integer",
          "minimum": 2,
          "maximum": 10,
          "default": 3
        },
        "shamirShares": {
          "type": "integer",
          "minimum": 3,
          "maximum": 20,
          "default": 5
        }
      },
      "additionalProperties": false
    },
    "scmsConfig": {
      "type": "object",
      "description": "Smartcard Management System configuration",
      "properties": {
        "pkcs11ModulePath": {
          "type": "string",
          "description": "Path to PKCS#11 module library"
        },
        "maxPinRetries": {
          "type": "integer",
          "minimum": 1,
          "maximum": 10,
          "default": 3
        },
        "pinLockoutMinutes": {
          "type": "integer",
          "minimum": 1,
          "maximum": 60,
          "default": 15
        }
      },
      "additionalProperties": false
    },
    "loggingConfig": {
      "type": "object",
      "description": "Logging configuration - NIAP PP-CA: FAU_GEN.1",
      "required": ["level"],
      "properties": {
        "level": {
          "type": "string",
          "enum": ["trace", "debug", "info", "warn", "error"],
          "default": "info"
        },
        "format": {
          "type": "string",
          "enum": ["json", "pretty", "compact"],
          "default": "json"
        },
        "output": {
          "type": "string",
          "enum": ["stdout", "stderr", "file"],
          "default": "stdout"
        },
        "file": {
          "type": "string",
          "description": "Log file path (required if output is 'file')"
        }
      },
      "additionalProperties": false
    }
  },
  "additionalProperties": false
}
```

##### 1.1.2 Create Centralized Configuration System

**File**: `crates/ostrich-common/src/config.rs` (new)

```rust
//! # Centralized JSON Configuration System
//!
//! ## NIAP PP-CA Compliance
//! - FMT_MSA.1: Secure configuration defaults
//! - FMT_SMF.1: Configuration management function
//!
//! ## Security Requirements
//! - NO HARDCODED IP LITERALS (use hostnames or '::' for dual-stack)
//! - JSON Schema validation on load
//! - Environment variable expansion for secrets

use serde::{Deserialize, Serialize};
use jsonschema::{JSONSchema, ValidationError};
use std::path::Path;

/// JSON Schema for configuration validation
const CONFIG_SCHEMA: &str = include_str!("../../../config/schema/ostrich-config.schema.json");

/// Global configuration for all OstrichPKI services
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OstrichConfig {
    /// JSON Schema reference (optional, for IDE support)
    #[serde(rename = "$schema", skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,

    /// Service configuration
    pub service: ServiceConfig,

    /// Database configuration
    pub database: DatabaseConfig,

    /// TLS configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,

    /// ACME-specific configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acme: Option<AcmeConfig>,

    /// EST-specific configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub est: Option<EstConfig>,

    /// CA-specific configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca: Option<CaConfig>,

    /// OCSP-specific configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ocsp: Option<OcspConfig>,

    /// KRA-specific configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kra: Option<KraConfig>,

    /// SCMS-specific configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scms: Option<ScmsConfig>,

    /// Logging configuration
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceConfig {
    /// Service name
    pub name: String,

    /// Listen configuration
    pub listen: ListenConfig,

    /// Public base URL for this service (NO IP LITERALS)
    pub base_url: String,

    /// Maximum request body size (bytes)
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,

    /// Request timeout (seconds)
    #[serde(default = "default_request_timeout")]
    pub request_timeout_seconds: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListenConfig {
    /// Listen host (use "::" for dual-stack, hostname for specific interface)
    /// NO IP LITERALS except "::" and "0.0.0.0"
    pub host: String,

    /// Listen port
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AcmeConfig {
    /// ACME directory URL base
    pub directory_url: String,

    /// Terms of Service URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_of_service_url: Option<String>,

    /// Nonce expiration time (seconds)
    #[serde(default = "default_nonce_expiration")]
    pub nonce_expiration_seconds: u64,

    /// Order expiration time (seconds)
    #[serde(default = "default_order_expiration")]
    pub order_expiration_seconds: u64,

    /// Maximum identifiers per order
    #[serde(default = "default_max_identifiers")]
    pub max_identifiers_per_order: usize,

    /// Enabled challenge types
    #[serde(default = "default_challenge_types")]
    pub challenge_types: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseConfig {
    /// Database hostname (NO IP LITERALS)
    pub host: String,

    /// Database port
    #[serde(default = "default_db_port")]
    pub port: u16,

    /// Database name
    pub database: String,

    /// Username
    pub username: String,

    /// Password (supports $ENV{VAR} syntax)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// Connection pool size
    #[serde(default = "default_pool_size")]
    pub pool_size: u32,

    /// SSL mode
    #[serde(default = "default_ssl_mode")]
    pub ssl_mode: String,
}

// ... (TlsConfig, EstConfig, CaConfig, OcspConfig, KraConfig, ScmsConfig, LoggingConfig)

impl OstrichConfig {
    /// Load and validate configuration from JSON file
    ///
    /// # NIAP PP-CA Compliance
    /// - FMT_MSA.1: Validates against secure defaults schema
    pub fn load() -> Result<Self, ConfigError> {
        let config_paths = vec![
            std::env::var("OSTRICH_CONFIG").ok(),
            Some("/etc/ostrich/config.json".to_string()),
            Some("./config.json".to_string()),
        ];

        for path in config_paths.into_iter().flatten() {
            if Path::new(&path).exists() {
                return Self::from_file(&path);
            }
        }

        Err(ConfigError::NoConfigFile)
    }

    /// Load from JSON file with schema validation
    pub fn from_file(path: &str) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_json(&contents)
    }

    /// Parse JSON with schema validation
    pub fn from_json(json: &str) -> Result<Self, ConfigError> {
        // Parse JSON
        let json_value: serde_json::Value = serde_json::from_str(json)
            .map_err(|e| ConfigError::JsonParse(e.to_string()))?;

        // Validate against schema
        Self::validate_schema(&json_value)?;

        // Deserialize to config struct
        let mut config: OstrichConfig = serde_json::from_value(json_value)
            .map_err(|e| ConfigError::JsonParse(e.to_string()))?;

        // Expand environment variables
        config.expand_env_vars()?;

        // Validate no IP literals in hostnames
        config.validate_no_ip_literals()?;

        Ok(config)
    }

    /// Validate JSON against schema
    fn validate_schema(json: &serde_json::Value) -> Result<(), ConfigError> {
        let schema: serde_json::Value = serde_json::from_str(CONFIG_SCHEMA)
            .map_err(|e| ConfigError::SchemaError(e.to_string()))?;

        let compiled = JSONSchema::compile(&schema)
            .map_err(|e| ConfigError::SchemaError(e.to_string()))?;

        let result = compiled.validate(json);
        if let Err(errors) = result {
            let error_messages: Vec<String> = errors
                .map(|e| format!("{}: {}", e.instance_path, e))
                .collect();
            return Err(ConfigError::ValidationFailed(error_messages));
        }

        Ok(())
    }

    /// Expand $ENV{VAR} patterns in configuration values
    fn expand_env_vars(&mut self) -> Result<(), ConfigError> {
        // Expand database password
        if let Some(ref password) = self.database.password {
            if let Some(expanded) = Self::expand_env_var(password)? {
                self.database.password = Some(expanded);
            }
        }

        Ok(())
    }

    /// Expand single $ENV{VAR} pattern
    fn expand_env_var(value: &str) -> Result<Option<String>, ConfigError> {
        let re = regex::Regex::new(r"\$ENV\{([^}]+)\}").unwrap();

        if let Some(caps) = re.captures(value) {
            let var_name = &caps[1];
            let env_value = std::env::var(var_name)
                .map_err(|_| ConfigError::MissingEnvVar(var_name.to_string()))?;
            Ok(Some(re.replace_all(value, env_value.as_str()).to_string()))
        } else {
            Ok(None)
        }
    }

    /// Validate that no IP literals are used in hostnames
    ///
    /// # Security
    /// IP literals bypass DNS and can cause security issues.
    /// Only "::" (dual-stack) and "0.0.0.0" (all IPv4) are allowed for listen addresses.
    fn validate_no_ip_literals(&self) -> Result<(), ConfigError> {
        // Check service base URL
        if Self::contains_ip_literal(&self.service.base_url) {
            return Err(ConfigError::IpLiteralNotAllowed(
                "service.baseUrl".to_string(),
                self.service.base_url.clone(),
            ));
        }

        // Check listen host (allow :: and 0.0.0.0)
        let listen_host = &self.service.listen.host;
        if listen_host != "::" && listen_host != "0.0.0.0" {
            if Self::contains_ip_literal(listen_host) {
                return Err(ConfigError::IpLiteralNotAllowed(
                    "service.listen.host".to_string(),
                    listen_host.clone(),
                ));
            }
        }

        // Check database host
        if Self::contains_ip_literal(&self.database.host) {
            return Err(ConfigError::IpLiteralNotAllowed(
                "database.host".to_string(),
                self.database.host.clone(),
            ));
        }

        // Check ACME directory URL
        if let Some(ref acme) = self.acme {
            if Self::contains_ip_literal(&acme.directory_url) {
                return Err(ConfigError::IpLiteralNotAllowed(
                    "acme.directoryUrl".to_string(),
                    acme.directory_url.clone(),
                ));
            }
        }

        // Check CA gRPC endpoint
        if let Some(ref ca) = self.ca {
            if let Some(ref endpoint) = ca.grpc_endpoint {
                if Self::contains_ip_literal(endpoint) {
                    return Err(ConfigError::IpLiteralNotAllowed(
                        "ca.grpcEndpoint".to_string(),
                        endpoint.clone(),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Check if a string contains an IP literal (IPv4 or IPv6)
    fn contains_ip_literal(s: &str) -> bool {
        use std::net::IpAddr;

        // Extract host from URL if present
        let host = if s.starts_with("http://") || s.starts_with("https://") {
            url::Url::parse(s)
                .ok()
                .and_then(|u| u.host_str().map(|h| h.to_string()))
                .unwrap_or_else(|| s.to_string())
        } else {
            s.to_string()
        };

        // Remove port if present
        let host = host.split(':').next().unwrap_or(&host);

        // Try to parse as IP address
        host.parse::<IpAddr>().is_ok()
    }
}

fn default_max_body_size() -> usize { 1_048_576 } // 1 MB
fn default_request_timeout() -> u64 { 30 }
fn default_nonce_expiration() -> u64 { 900 } // 15 minutes
fn default_order_expiration() -> u64 { 86400 } // 24 hours
fn default_max_identifiers() -> usize { 10 }
fn default_pool_size() -> u32 { 10 }
fn default_db_port() -> u16 { 5432 }
fn default_ssl_mode() -> String { "require".to_string() }
fn default_challenge_types() -> Vec<String> {
    vec!["http-01".to_string(), "dns-01".to_string()]
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON parse error: {0}")]
    JsonParse(String),

    #[error("Schema error: {0}")]
    SchemaError(String),

    #[error("Schema validation failed: {0:?}")]
    ValidationFailed(Vec<String>),

    #[error("Missing environment variable: {0}")]
    MissingEnvVar(String),

    #[error("IP literal not allowed in {0}: {1} (use hostname instead)")]
    IpLiteralNotAllowed(String, String),

    #[error("No configuration file found")]
    NoConfigFile,

    #[error("Invalid base URL")]
    InvalidBaseUrl,

    #[error("Invalid port")]
    InvalidPort,
}
```

**NIAP Compliance**: FMT_MSA.1 (Secure defaults via JSON Schema), FMT_SMF.1 (Configuration management)

##### 1.1.2 Update ACME Service to Use Configuration

**File**: `crates/ostrich-acme/src/rest.rs`

Replace all 6 hardcoded URL instances:

```rust
// BEFORE (Line 431):
"https://example.com/acme/new-account", // TODO: Get actual URL from request

// AFTER:
&format!("{}/acme/new-account", config.acme.directory_url)
```

**Changes Required**:

- Line 431: `new_account` endpoint URL
- Line 518: `new_order` endpoint URL
- Line 620: `account/{id}` URL
- Line 700: `challenge/{id}` URL
- Line 779: `order/{id}/finalize` URL
- Line 875: Certificate download URL

**Implementation**:

```rust
pub struct AcmeService {
    db: Arc<Repository>,
    config: Arc<OstrichConfig>,
}

impl AcmeService {
    fn account_url(&self, account_id: &Uuid) -> String {
        format!("{}/acme/account/{}", self.config.acme.directory_url, account_id)
    }

    fn order_url(&self, order_id: &Uuid) -> String {
        format!("{}/acme/order/{}", self.config.acme.directory_url, order_id)
    }

    fn challenge_url(&self, challenge_id: &Uuid) -> String {
        format!("{}/acme/challenge/{}", self.config.acme.directory_url, challenge_id)
    }
}
```

##### 1.1.4 Example Configuration Files

**File**: `config/production.json`

```json
{
  "$schema": "./schema/ostrich-config.schema.json",
  "service": {
    "name": "ostrich-acme",
    "listen": {
      "host": "::",
      "port": 8443
    },
    "baseUrl": "https://acme.ostrichpki.example.com",
    "maxBodySize": 1048576,
    "requestTimeoutSeconds": 30
  },
  "database": {
    "host": "db.ostrichpki.internal",
    "port": 5432,
    "database": "ostrichpki",
    "username": "acme_service",
    "password": "$ENV{DB_PASSWORD}",
    "poolSize": 20,
    "sslMode": "verify-full"
  },
  "tls": {
    "certFile": "/etc/ostrich/tls/acme.crt",
    "keyFile": "/etc/ostrich/tls/acme.key",
    "caFile": "/etc/ostrich/tls/ca.crt",
    "minVersion": "1.3",
    "clientAuth": "none"
  },
  "acme": {
    "directoryUrl": "https://acme.ostrichpki.example.com",
    "termsOfServiceUrl": "https://ostrichpki.example.com/tos",
    "nonceExpirationSeconds": 900,
    "orderExpirationSeconds": 86400,
    "maxIdentifiersPerOrder": 10,
    "challengeTypes": ["http-01", "dns-01", "tls-alpn-01"]
  },
  "logging": {
    "level": "info",
    "format": "json",
    "output": "stdout"
  }
}
```

**File**: `config/development.json`

```json
{
  "$schema": "./schema/ostrich-config.schema.json",
  "service": {
    "name": "ostrich-acme",
    "listen": {
      "host": "::",
      "port": 8080
    },
    "baseUrl": "http://localhost:8080"
  },
  "database": {
    "host": "localhost",
    "port": 5432,
    "database": "ostrichpki_dev",
    "username": "postgres",
    "password": "postgres",
    "poolSize": 5,
    "sslMode": "disable"
  },
  "acme": {
    "directoryUrl": "http://localhost:8080",
    "termsOfServiceUrl": "http://localhost:8080/tos",
    "nonceExpirationSeconds": 900,
    "challengeTypes": ["http-01"]
  },
  "logging": {
    "level": "debug",
    "format": "pretty",
    "output": "stdout"
  }
}
```

**Note on `localhost`**: The hostname `localhost` is allowed (not an IP literal) as it resolves via DNS/hosts file. Direct IP literals like `127.0.0.1` are prohibited in configuration.

##### 1.1.5 IP Literal Remediation in Test Code

The following test files contain IP literals that should be replaced with test constants:

**File**: `crates/ostrich-common/src/test_constants.rs` (new)

```rust
//! Test constants for IP addresses and network values
//!
//! Using constants instead of inline literals allows for:
//! 1. Easy identification of test-only values
//! 2. Consistent test data across all tests
//! 3. Clear separation from production code

/// Test IPv4 addresses (RFC 5737 - TEST-NET-1)
pub mod test_ipv4 {
    /// Documentation/example IPv4: 192.0.2.0/24
    pub const TEST_NET_1: &str = "192.0.2.1";
    /// Documentation/example IPv4: 198.51.100.0/24
    pub const TEST_NET_2: &str = "198.51.100.1";
    /// Documentation/example IPv4: 203.0.113.0/24
    pub const TEST_NET_3: &str = "203.0.113.1";
}

/// Test IPv6 addresses (RFC 3849 - 2001:db8::/32)
pub mod test_ipv6 {
    /// Documentation IPv6 prefix
    pub const DOCUMENTATION: &str = "2001:db8::1";
    /// Documentation IPv6 with subnet
    pub const DOCUMENTATION_SUBNET: &str = "2001:db8:1::1";
}
```

**Files to Update**:

1. `crates/ostrich-audit/src/event.rs:450, 506, 517` → Use `test_ipv4::TEST_NET_1`
2. `crates/ostrich-common/src/auth/lockout.rs:544, 550, 556` → Use `test_ipv4::TEST_NET_1`
3. `crates/ostrich-common/src/auth/session.rs:670` → Use `test_ipv4::TEST_NET_1`
4. `crates/ostrich-db/src/models/audit.rs:184, 227, 232` → Use `test_ipv4::TEST_NET_1`
5. `crates/ostrich-acme/src/validation.rs:572-580` → Use RFC 5737 TEST-NET addresses

##### 1.1.4 Documentation

**File**: `docs/CONFIGURATION.md` (new)

Create comprehensive configuration documentation covering:

- All configuration parameters
- Environment variable overrides
- Example configurations for different deployment scenarios
- Security best practices (secrets management)

#### Success Criteria

- [ ] All 14 hardcoded URL TODOs resolved
- [ ] JSON Schema created and validates configuration
- [ ] Configuration loads from JSON files with schema validation
- [ ] Environment variable expansion ($ENV{VAR}) functional
- [ ] IP literal detection and rejection in hostnames
- [ ] Test code IP literals replaced with RFC 5737/3849 constants
- [ ] Configuration validation on startup
- [ ] IDE autocompletion via $schema reference
- [ ] Documentation complete
- [ ] Example configs for dev/staging/production

---

### 1.2 IPv6 Native Support

**Effort**: 4 days | **Priority**: 🔴 HIGH | **Compliance**: NIST 800-53 SC-8

#### Overview

Implement full IPv6 support across all services, including dual-stack operation, IPv6 address validation, and IPv6-specific security considerations.

#### Current State

- Services bind to `0.0.0.0` (IPv4 only)
- No IPv6 address parsing/validation
- ACME HTTP-01 challenge validation doesn't support IPv6
- OCSP/CRL distribution points don't include IPv6 addresses

#### Implementation Tasks

##### 1.2.1 Core IPv6 Support

**File**: `crates/ostrich-common/src/network.rs` (new)

```rust
//! # Network Utilities
//!
//! ## NIAP PP-CA Compliance
//! - FTP_ITC.1: Trusted channel (IPv4/IPv6)
//! - SC-8: Transmission confidentiality (both protocols)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

/// IP address type with dual-stack support
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpAddressType {
    IPv4(Ipv4Addr),
    IPv6(Ipv6Addr),
    DualStack,
}

/// Parse IP address from string, supporting both IPv4 and IPv6
pub fn parse_ip_address(addr: &str) -> Result<IpAddr, ParseError> {
    // Handle IPv6 with zone identifier (e.g., "fe80::1%eth0")
    if addr.contains('%') {
        let parts: Vec<&str> = addr.split('%').collect();
        if parts.len() == 2 {
            return Ipv6Addr::from_str(parts[0])
                .map(IpAddr::V6)
                .map_err(|_| ParseError::InvalidIpv6);
        }
    }

    IpAddr::from_str(addr).map_err(|_| ParseError::InvalidIpAddress)
}

/// Create dual-stack socket address (IPv6 with IPv4-mapped support)
pub fn dual_stack_bind_addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
}

/// Check if IP address is in private range
pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_private()
            || ipv4.is_loopback()
            || ipv4.is_link_local()
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback()
            || is_ipv6_unique_local(ipv6)
            || ipv6.is_multicast()
            || is_ipv6_link_local(ipv6)
        }
    }
}

/// Check if IPv6 address is in Unique Local Address (ULA) range (fc00::/7)
fn is_ipv6_unique_local(ip: &Ipv6Addr) -> bool {
    ip.segments()[0] & 0xfe00 == 0xfc00
}

/// Check if IPv6 address is link-local (fe80::/10)
fn is_ipv6_link_local(ip: &Ipv6Addr) -> bool {
    ip.segments()[0] & 0xffc0 == 0xfe80
}

/// Normalize IP address for database storage
pub fn normalize_ip(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(ipv4) => ipv4.to_string(),
        IpAddr::V6(ipv6) => {
            // Use compressed notation
            ipv6.to_string()
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("Invalid IP address")]
    InvalidIpAddress,

    #[error("Invalid IPv6 address")]
    InvalidIpv6,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4() {
        let ip = parse_ip_address("192.0.2.1").unwrap();
        assert!(matches!(ip, IpAddr::V4(_)));
    }

    #[test]
    fn test_parse_ipv6() {
        let ip = parse_ip_address("2001:db8::1").unwrap();
        assert!(matches!(ip, IpAddr::V6(_)));
    }

    #[test]
    fn test_parse_ipv6_with_zone() {
        let ip = parse_ip_address("fe80::1%eth0").unwrap();
        assert!(matches!(ip, IpAddr::V6(_)));
    }

    #[test]
    fn test_is_private_ipv4() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn test_is_private_ipv6_ula() {
        let ip = IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1));
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn test_is_private_ipv6_link_local() {
        let ip = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        assert!(is_private_ip(&ip));
    }
}
```

##### 1.2.2 Update Service Bindings for Dual-Stack

**File**: `crates/ostrich-acme/src/main.rs` (and all other services)

```rust
use ostrich_common::network::dual_stack_bind_addr;

#[tokio::main]
async fn main() -> Result<()> {
    let config = OstrichConfig::load()?;

    // Bind to dual-stack address (IPv6 with IPv4-mapped support)
    let bind_addr = match config.service.listen_address {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED) => {
            // "::" - dual-stack mode
            dual_stack_bind_addr(config.service.port)
        }
        ip => {
            SocketAddr::new(ip, config.service.port)
        }
    };

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;

    // Enable dual-stack mode on the socket
    if bind_addr.is_ipv6() {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = listener.as_raw_fd();
            // Set IPV6_V6ONLY to 0 to accept both IPv4 and IPv6
            unsafe {
                let optval: libc::c_int = 0;
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_V6ONLY,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }
    }

    tracing::info!("Listening on {} (dual-stack: {})",
        bind_addr, bind_addr.is_ipv6());

    // ... rest of server setup
}
```

##### 1.2.3 ACME HTTP-01 Challenge IPv6 Support

**File**: `crates/ostrich-acme/src/validation.rs`

Update SSRF prevention to handle IPv6:

```rust
// NIST 800-53: SI-10 - Input validation (IPv4/IPv6)
// NIAP PP-CA: FDP_IFC.1 - Information flow control

async fn validate_domain_not_private(domain: &str) -> Result<(), ValidationError> {
    use trust_dns_resolver::TokioAsyncResolver;
    use ostrich_common::network::is_private_ip;

    let resolver = TokioAsyncResolver::tokio_from_system_conf()
        .map_err(|_| ValidationError::DnsResolutionFailed)?;

    // Resolve both A (IPv4) and AAAA (IPv6) records
    let ipv4_lookup = resolver.ipv4_lookup(domain).await;
    let ipv6_lookup = resolver.ipv6_lookup(domain).await;

    // Check IPv4 addresses
    if let Ok(ipv4_records) = ipv4_lookup {
        for ip in ipv4_records.iter() {
            let addr = IpAddr::V4(*ip);
            if is_private_ip(&addr) {
                tracing::warn!(domain = %domain, ip = %addr,
                    "SSRF attempt: domain resolves to private IPv4");
                return Err(ValidationError::PrivateIpNotAllowed);
            }
        }
    }

    // Check IPv6 addresses
    if let Ok(ipv6_records) = ipv6_lookup {
        for ip in ipv6_records.iter() {
            let addr = IpAddr::V6(*ip);
            if is_private_ip(&addr) {
                tracing::warn!(domain = %domain, ip = %addr,
                    "SSRF attempt: domain resolves to private IPv6");
                return Err(ValidationError::PrivateIpNotAllowed);
            }
        }
    }

    Ok(())
}
```

##### 1.2.4 X.509 Certificate IPv6 Support

**File**: `crates/ostrich-x509/src/builder/certificate.rs`

Add IPv6 address parsing for Subject Alternative Name (SAN):

```rust
// RFC 5280 §4.2.1.6 - Subject Alternative Name (IPv4/IPv6)

fn parse_san_ip_address(ip_str: &str) -> Result<Vec<u8>, BuilderError> {
    use std::net::IpAddr;

    let ip = IpAddr::from_str(ip_str)
        .map_err(|_| BuilderError::InvalidSanIpAddress)?;

    match ip {
        IpAddr::V4(ipv4) => Ok(ipv4.octets().to_vec()),
        IpAddr::V6(ipv6) => Ok(ipv6.octets().to_vec()),
    }
}
```

##### 1.2.5 Database Schema Updates

**File**: `migrations/00006_add_ipv6_support.sql` (new)

```sql
-- Add IPv6 support to database schema

-- Update audit events to support IPv6 source addresses
ALTER TABLE audit_events
    ALTER COLUMN source_ip TYPE INET;  -- PostgreSQL INET type supports both IPv4 and IPv6

COMMENT ON COLUMN audit_events.source_ip IS
    'Source IP address (IPv4 or IPv6) - NIST 800-53: AU-3(b)';

-- Update ACME challenge validation to support IPv6
ALTER TABLE acme_challenges
    ADD COLUMN validated_from_ipv6 INET;

COMMENT ON COLUMN acme_challenges.validated_from_ipv6 IS
    'IPv6 address from which validation was performed';

-- Create index for IPv6 lookups
CREATE INDEX idx_audit_events_source_ipv6 ON audit_events(source_ip)
    WHERE family(source_ip) = 6;  -- IPv6 only index
```

##### 1.2.6 Testing

**File**: `crates/ostrich-common/tests/ipv6_test.rs` (new)

```rust
use ostrich_common::network::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn test_dual_stack_binding() {
    let addr = dual_stack_bind_addr(8443);
    assert!(addr.is_ipv6());
    assert_eq!(addr.port(), 8443);
}

#[test]
fn test_ipv6_ula_detection() {
    let ula = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
    assert!(is_private_ip(&ula));
}

#[test]
fn test_ipv6_global_unicast() {
    let global = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    assert!(!is_private_ip(&global));  // 2001:db8::/32 is documentation, treated as non-private
}

#[tokio::test]
async fn test_http_challenge_ipv6() {
    // Test HTTP-01 challenge validation over IPv6
    // Requires IPv6-enabled test infrastructure
}
```

#### Documentation Updates

**File**: `docs/IPv6_SUPPORT.md` (new)

Create comprehensive IPv6 documentation:

- Dual-stack deployment guide
- IPv6-only deployment considerations
- Firewall rules for IPv6
- Security considerations (NDP, ICMPv6)
- Troubleshooting IPv6 connectivity

#### Success Criteria

- [ ] All services support dual-stack (IPv4/IPv6) binding
- [ ] IPv6 address parsing and validation functional
- [ ] ACME HTTP-01 challenge works over IPv6
- [ ] X.509 SAN supports IPv6 addresses
- [ ] Database schema supports IPv6 storage
- [ ] SSRF protection works for IPv6
- [ ] Comprehensive IPv6 tests passing
- [ ] Documentation complete

---

## Track 2: Medium Priority (Operational Improvements)

### 2.1 SCMS PKCS#11 Token Operations

**Effort**: 2 weeks | **Priority**: 🟡 MEDIUM

#### Overview

Implement full PKCS#11 integration for smartcard/token lifecycle management (29 TODOs in `crates/ostrich-scms/src/rest.rs`).

**Current State**: All SCMS endpoints exist with database-only operation. PKCS#11 operations are stubbed with `TODO` markers.

#### Implementation Tasks

##### 2.1.1 Token Initialization via PKCS#11

**File**: `crates/ostrich-scms/src/rest.rs:338`

```rust
// BEFORE:
// TODO: Initialize via PKCS#11 (Phase 10)

// AFTER:
async fn initialize_token_impl(
    &self,
    token_id: Uuid,
    so_pin: &str,
) -> Result<(), ScmsError> {
    // NIAP PP-CA: FCS_CKM.1 - Token initialization

    // Initialize token via PKCS#11
    let ctx = self.pkcs11_ctx.lock().await;
    let slot_id = self.get_token_slot(token_id).await?;

    ctx.init_token(slot_id, so_pin, "OstrichPKI Token")
        .map_err(|e| ScmsError::Pkcs11Error(e))?;

    // Update database
    self.db.scms().update_token_initialized(token_id).await?;

    Ok(())
}
```

##### 2.1.2 PIN Operations via PKCS#11

**Files**: Lines 384-385, 537, 591-592

Implement:

- `set_pin_via_pkcs11()` - Set initial PIN
- `verify_pin_via_pkcs11()` - Verify PIN with retry tracking
- `change_pin_via_pkcs11()` - Change PIN

```rust
// NIAP PP-CA: FIA_UAU.1 - PIN-based authentication

async fn verify_pin_via_pkcs11(
    &self,
    token_id: Uuid,
    pin: &str,
) -> Result<bool, ScmsError> {
    let ctx = self.pkcs11_ctx.lock().await;
    let slot_id = self.get_token_slot(token_id).await?;

    // Open session
    let session = ctx.open_session(slot_id,
        CKF_SERIAL_SESSION | CKF_RW_SESSION)?;

    // Attempt login
    match ctx.login(session, CKU_USER, pin) {
        Ok(_) => {
            ctx.logout(session)?;
            ctx.close_session(session)?;
            Ok(true)
        }
        Err(CKR_PIN_INCORRECT) => {
            ctx.close_session(session)?;

            // Increment failed attempt counter in database
            self.db.scms().increment_pin_retry_count(token_id).await?;

            // Check if should lock
            let token = self.db.scms().get_token(token_id).await?;
            if token.pin_retry_count >= token.max_pin_retries {
                self.db.scms().lock_token(token_id).await?;
                return Err(ScmsError::TokenLocked);
            }

            Ok(false)
        }
        Err(e) => Err(ScmsError::Pkcs11Error(e)),
    }
}
```

##### 2.1.3 Key Generation via PKCS#11

**File**: Line 665

```rust
// NIAP PP-CA: FCS_CKM.1 - Key generation on token

async fn generate_key_via_pkcs11(
    &self,
    token_id: Uuid,
    pin: &str,
    algorithm: &str,
) -> Result<TokenKey, ScmsError> {
    let ctx = self.pkcs11_ctx.lock().await;
    let slot_id = self.get_token_slot(token_id).await?;

    let session = ctx.open_session(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION)?;
    ctx.login(session, CKU_USER, pin)?;

    // Parse algorithm
    let (key_type, key_size) = parse_algorithm(algorithm)?;

    // Generate key pair on token
    let (pub_handle, priv_handle) = match key_type {
        KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => {
            ctx.generate_rsa_keypair(session, key_size, true)?
        }
        KeyType::EcdsaP256 | KeyType::EcdsaP384 | KeyType::EcdsaP521 => {
            ctx.generate_ec_keypair(session, ec_params(key_type), true)?
        }
        _ => return Err(ScmsError::UnsupportedAlgorithm),
    };

    // Export public key for storage
    let public_key_spki = ctx.export_public_key(session, pub_handle)?;

    ctx.logout(session)?;
    ctx.close_session(session)?;

    // Store in database
    let key_id = Uuid::new_v4();
    self.db.scms().create_key(TokenKey {
        id: key_id,
        token_id,
        key_handle: priv_handle.to_string(),
        algorithm: algorithm.to_string(),
        public_key: public_key_spki,
        created_at: Utc::now(),
    }).await?;

    Ok(self.db.scms().get_key(key_id).await?)
}
```

**Implementation Checklist** (29 TODOs):

- [ ] Line 49: Add PKCS#11 provider initialization
- [ ] Line 338: Initialize token via PKCS#11
- [ ] Lines 384-385: Set PIN and generate keys on personalization
- [ ] Line 491: Verify SO-PIN via PKCS#11
- [ ] Lines 537, 548: PIN verification with retry tracking
- [ ] Lines 591-592: PIN change operations
- [ ] Line 620: Query keys from token
- [ ] Line 665: Generate key on token
- [ ] Line 714: Delete key from token
- [ ] Lines 823, 827-829, 831, 833: Database schema additions for token metadata
- [ ] All PKCS#11 operations integrated with audit logging

**Testing**:

- [ ] Integration tests with SoftHSM2
- [ ] PIN lockout testing
- [ ] Key generation for all algorithms
- [ ] Token lifecycle (init → personalize → use → revoke)

---

### 2.2 Audit Logging Hookups

**Effort**: 3 days | **Priority**: 🟡 MEDIUM

#### Overview

Connect 21 TODO audit logging placeholders to the `AuditLog::emit()` infrastructure.

**Current State**: Audit infrastructure complete (`ostrich-audit`), but many service operations don't emit events.

#### Implementation Tasks

##### 2.2.1 SCMS Audit Events (16 TODOs)

**File**: `crates/ostrich-scms/src/rest.rs`

All audit TODOs at lines: 230, 272, 302, 345, 393, 427, 459, 498, 557, 599, 677, 721, 776

```rust
use ostrich_audit::{AuditLog, AuditEvent, EventOutcome};

// Example: Token creation audit (line 230)
// BEFORE:
// TODO: Audit log (Phase 11)

// AFTER:
audit_log.emit(AuditEvent {
    timestamp: Utc::now(),
    actor: ActorId::Service("scms".to_string()),
    event_type: EventType::TokenCreated,
    outcome: EventOutcome::Success,
    resource: ResourceId::Token(token.id),
    details: serde_json::json!({
        "token_id": token.id,
        "serial_number": token.serial_number,
        "model": token.model,
    }),
}).await?;

// Example: PIN verification audit (lines 548, 557)
// Failed attempt:
audit_log.emit(AuditEvent {
    timestamp: Utc::now(),
    actor: ActorId::Token(token_id),
    event_type: EventType::AuthenticationFailed,
    outcome: EventOutcome::Failure,
    resource: ResourceId::Token(token_id),
    details: serde_json::json!({
        "reason": "invalid_pin",
        "retry_count": token.pin_retry_count,
    }),
}).await?;

// Successful verification:
audit_log.emit(AuditEvent {
    timestamp: Utc::now(),
    actor: ActorId::Token(token_id),
    event_type: EventType::AuthenticationSuccess,
    outcome: EventOutcome::Success,
    resource: ResourceId::Token(token_id),
    details: serde_json::json!({
        "token_id": token_id,
    }),
}).await?;
```

##### 2.2.2 ACME Audit Event (1 TODO)

**File**: `crates/ostrich-acme/src/rest.rs:485`

```rust
// Account creation audit
audit_log.emit(AuditEvent {
    timestamp: Utc::now(),
    actor: ActorId::AcmeAccount(account.id),
    event_type: EventType::AcmeAccountCreated,
    outcome: EventOutcome::Success,
    resource: ResourceId::AcmeAccount(account.id),
    details: serde_json::json!({
        "account_id": account.id,
        "public_key_jwk": account.public_key,
        "contact": account.contact,
    }),
}).await?;
```

##### 2.2.3 EST Audit Events (3 TODOs)

**Files**: Lines 290, 387

```rust
// Enrollment audit (line 290)
audit_log.emit(AuditEvent {
    timestamp: Utc::now(),
    actor: ActorId::from_client_cert(&client_cert),
    event_type: EventType::EstEnrollmentRequested,
    outcome: EventOutcome::Success,
    resource: ResourceId::Certificate(cert_serial),
    details: serde_json::json!({
        "csr_subject": csr.subject_dn,
        "client_cert_subject": client_cert.subject_dn,
    }),
}).await?;

// Re-enrollment audit (line 387)
audit_log.emit(AuditEvent {
    timestamp: Utc::now(),
    actor: ActorId::from_client_cert(&client_cert),
    event_type: EventType::EstReenrollmentRequested,
    outcome: EventOutcome::Success,
    resource: ResourceId::Certificate(new_cert_serial),
    details: serde_json::json!({
        "old_cert_serial": old_cert_serial,
        "new_cert_serial": new_cert_serial,
        "csr_subject": csr.subject_dn,
    }),
}).await?;
```

##### 2.2.4 Audit Event Type Additions

**File**: `crates/ostrich-audit/src/event.rs`

Add missing event types:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventType {
    // ... existing events ...

    // SCMS events
    TokenCreated,
    TokenInitialized,
    TokenPersonalized,
    TokenSuspended,
    TokenResumed,
    TokenRevoked,
    TokenPinVerified,
    TokenPinChanged,
    TokenKeyGenerated,
    TokenKeyDeleted,

    // ACME events
    AcmeAccountCreated,
    AcmeAccountDeactivated,

    // EST events
    EstEnrollmentRequested,
    EstReenrollmentRequested,
}
```

#### Success Criteria

- [ ] All 21 audit TODO items resolved
- [ ] SCMS operations emit comprehensive audit events
- [ ] ACME account lifecycle fully audited
- [ ] EST enrollment operations audited
- [ ] All audit events include required NIAP PP-CA fields (AU-3)
- [ ] Audit log tests verify event emission

---

## Track 3: Low Priority (Advanced Features)

### 3.1 Enhanced CSR Processing

**Effort**: 1 week | **Priority**: ⚪ LOW

#### 3.1.1 CSR Signature Verification

**Files**:

- `crates/ostrich-acme/src/ca_integration.rs:113`
- `crates/ostrich-est/src/ca_integration.rs:113`

```rust
// NIAP PP-CA: FCS_COP.1 - Signature verification

async fn verify_csr_signature(csr: &CertificationRequest) -> Result<(), ValidationError> {
    use x509_cert::request::CertReq;

    // Parse CSR
    let cert_req = CertReq::try_from(csr.der_bytes.as_slice())
        .map_err(|_| ValidationError::InvalidCsr)?;

    // Extract public key
    let public_key = cert_req.info.subject_pki;

    // Verify signature on CSR
    cert_req.verify_signature(&public_key)
        .map_err(|_| ValidationError::InvalidCsrSignature)?;

    Ok(())
}
```

#### 3.1.2 SAN Extraction from CSR

**Files**:

- `crates/ostrich-acme/src/ca_integration.rs:77`
- `crates/ostrich-est/src/ca_integration.rs:120`
- `crates/ostrich-x509/src/parser.rs:77`

```rust
// RFC 2986 §4.1 - Extension Request Attribute

fn extract_san_from_csr(csr: &CertificationRequest) -> Result<Vec<String>, ParseError> {
    use x509_cert::attr::Attribute;
    use x509_cert::ext::pkix::SubjectAltName;

    // Look for extensionRequest attribute (OID 1.2.840.113549.1.9.14)
    const EXTENSION_REQUEST_OID: &str = "1.2.840.113549.1.9.14";

    for attr in &csr.attributes {
        if attr.oid.to_string() == EXTENSION_REQUEST_OID {
            // Parse extensions from attribute
            let extensions = parse_extensions(&attr.values)?;

            for ext in extensions {
                if ext.extn_id.to_string() == "2.5.29.17" {  // id-ce-subjectAltName
                    let san = SubjectAltName::from_der(&ext.extn_value)?;
                    return Ok(extract_dns_names(san));
                }
            }
        }
    }

    Ok(vec![])
}

fn extract_dns_names(san: SubjectAltName) -> Vec<String> {
    san.0.iter()
        .filter_map(|name| match name {
            GeneralName::DnsName(dns) => Some(dns.to_string()),
            _ => None,
        })
        .collect()
}
```

#### 3.1.3 ASN.1 RDN Parsing

**Files**:

- `crates/ostrich-acme/src/ca_integration.rs:142`
- `crates/ostrich-est/src/ca_integration.rs:188`

```rust
// RFC 5280 §4.1.2.4 - Issuer/Subject Distinguished Name

fn parse_distinguished_name(dn_der: &[u8]) -> Result<DistinguishedName, ParseError> {
    use x509_cert::name::{Name, RdnSequence};

    let name = Name::from_der(dn_der)
        .map_err(|_| ParseError::InvalidDistinguishedName)?;

    let mut dn = DistinguishedName::default();

    for rdn in name.0.iter() {
        for attr_tv in rdn.0.iter() {
            let oid = attr_tv.oid.to_string();
            let value = attr_tv.value.to_string()?;

            match oid.as_str() {
                "2.5.4.3" => dn.common_name = Some(value),
                "2.5.4.6" => dn.country = Some(value),
                "2.5.4.7" => dn.locality = Some(value),
                "2.5.4.8" => dn.state_or_province = Some(value),
                "2.5.4.10" => dn.organization = Some(value),
                "2.5.4.11" => dn.organizational_unit = Some(value),
                _ => {}  // Ignore unknown attributes
            }
        }
    }

    Ok(dn)
}
```

### 3.2 OCSP Response Caching

**Effort**: 2 days | **Priority**: ⚪ LOW

**Files**:

- `crates/ostrich-ocsp/src/responder.rs:47-49, 86, 88`

```rust
use lru::LruCache;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct OcspCache {
    cache: Arc<RwLock<LruCache<String, CachedResponse>>>,
}

struct CachedResponse {
    response: Vec<u8>,  // DER-encoded OCSP response
    expires_at: Instant,
}

impl OcspCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            cache: Arc::new(RwLock::new(LruCache::new(capacity))),
        }
    }

    pub async fn get(&self, serial: &str) -> Option<Vec<u8>> {
        let mut cache = self.cache.write().await;

        if let Some(cached) = cache.get(serial) {
            if Instant::now() < cached.expires_at {
                return Some(cached.response.clone());
            } else {
                // Expired, remove from cache
                cache.pop(serial);
            }
        }

        None
    }

    pub async fn put(&self, serial: String, response: Vec<u8>, ttl: Duration) {
        let mut cache = self.cache.write().await;

        cache.put(serial, CachedResponse {
            response,
            expires_at: Instant::now() + ttl,
        });
    }

    pub async fn invalidate(&self, serial: &str) {
        let mut cache = self.cache.write().await;
        cache.pop(serial);
    }
}

// Usage in responder:
impl OcspResponder {
    pub async fn generate_response(&self, request: &OcspRequest) -> Result<Vec<u8>> {
        let cache_key = format!("{}-{}", request.serial_number, request.hash_algorithm);

        // Check cache
        if let Some(cached) = self.cache.get(&cache_key).await {
            return Ok(cached);
        }

        // Generate new response
        let response = self.generate_response_uncached(request).await?;

        // Cache for nextUpdate - now
        let ttl = Duration::from_secs(3600);  // 1 hour
        self.cache.put(cache_key, response.clone(), ttl).await;

        Ok(response)
    }
}
```

**Performance Target**: <5ms p99 latency for cached responses

### 3.3 EST Server-Side Key Generation

**Effort**: 3 days | **Priority**: ⚪ LOW

**File**: `crates/ostrich-est/src/rest.rs:443-448`

```rust
// RFC 7030 §4.4 - Server-Side Key Generation
// SECURITY WARNING: Key generation on server - use only when absolutely required

async fn server_keygen(
    client_cert: Certificate,
    body: Bytes,
) -> Result<impl IntoResponse> {
    // TODO: Validate client certificate
    // TODO: Parse CSR (without private key, just subject info)

    // Generate key pair on server
    let keypair = crypto_provider.generate_keypair(SignatureAlgorithm::EcdsaP256Sha256).await?;

    // TODO: Issue certificate with generated public key
    let cert = ca_client.issue_certificate(IssueCertificateRequest {
        public_key: keypair.public_key,
        subject_dn: csr.subject_dn,
        profile_name: "est-serverkeygen".to_string(),
    }).await?;

    // Encrypt private key for client
    // Use client's transport key from TLS session
    let encrypted_key = encrypt_for_client(&keypair.private_key, &client_cert)?;

    // Zeroize private key from memory
    use zeroize::Zeroize;
    keypair.private_key.zeroize();

    // Optionally escrow key via KRA
    if config.est.escrow_server_generated_keys {
        kra_client.escrow_key(EscrowKeyRequest {
            key_type: "ecdsa-p256".to_string(),
            wrapped_key: encrypted_key.clone(),
            certificate_serial: cert.serial.clone(),
        }).await?;
    }

    // TODO: Return PKCS#7 with cert + encrypted private key
    let pkcs7 = build_pkcs7_with_encrypted_key(&cert, &encrypted_key)?;

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/pkcs7-mime")],
        pkcs7,
    ))
}
```

**Security Note**: Document that this is discouraged in high-security deployments.

### 3.4 Database Schema Extensions

**Effort**: 2 days | **Priority**: ⚪ LOW

**File**: `migrations/00007_scms_schema_extensions.sql` (new)

```sql
-- Add missing SCMS token metadata fields

ALTER TABLE scms_tokens
    ADD COLUMN label VARCHAR(255),
    ADD COLUMN initialized_at TIMESTAMPTZ,
    ADD COLUMN expires_at TIMESTAMPTZ,
    ADD COLUMN firmware_version VARCHAR(50),
    ADD COLUMN key_capacity INTEGER DEFAULT 10,
    ADD COLUMN cert_capacity INTEGER DEFAULT 10,
    ADD COLUMN pkcs11_support BOOLEAN DEFAULT true;

-- Add KRA recovery agent roles
ALTER TABLE kra_recovery_requests
    ADD COLUMN approved_by_role VARCHAR(100);

COMMENT ON COLUMN kra_recovery_requests.approved_by_role IS
    'Role of the recovery agent (e.g., "Recovery Agent", "Security Officer") - NIAP PP-CA: FMT_SMF.1';

-- Create recovery agents table
CREATE TABLE kra_recovery_agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    role VARCHAR(100) NOT NULL,
    public_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    CONSTRAINT unique_agent_name UNIQUE (name)
);

COMMENT ON TABLE kra_recovery_agents IS
    'Recovery agents authorized to reconstruct escrowed keys - NIAP PP-CA: FMT_SMF.1';
```

### 3.5 Service Integration Enhancements

**Effort**: 2 days | **Priority**: ⚪ LOW

#### 3.5.1 PKCS#7/CMS Wrapping for EST

**Files**:

- `crates/ostrich-est/src/ca_integration.rs:226`
- `crates/ostrich-acme/src/ca_integration.rs` (similar)

```rust
// RFC 7030 §4.1.3 - PKCS#7 Certificate Chain Response

use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;

fn wrap_certificate_in_pkcs7(cert_chain: Vec<Certificate>) -> Result<Vec<u8>, EstError> {
    // Create SignedData structure
    let mut certs = vec![];
    for cert in cert_chain {
        certs.push(x509_cert::Certificate::from_der(&cert.der_bytes)?);
    }

    let signed_data = SignedData {
        version: cms::signed_data::Version::V1,
        digest_algorithms: Default::default(),
        encap_content_info: ContentInfo {
            content_type: ID_DATA,  // OID 1.2.840.113549.1.7.1
            content: None,
        },
        certificates: Some(certs),
        crls: None,
        signer_infos: Default::default(),
    };

    let content_info = ContentInfo {
        content_type: ID_SIGNED_DATA,  // OID 1.2.840.113549.1.7.2
        content: Some(signed_data.to_der()?),
    };

    Ok(content_info.to_der()?)
}
```

---

## Implementation Timeline

### Sprint 1: High Priority (Week 1-2)

- **Days 1-3**: Configuration Management (Track 1.1)
  - Create config system
  - Update all 14 URL TODOs
  - Create example configs
- **Days 4-7**: IPv6 Support (Track 1.2)
  - Network utilities
  - Dual-stack binding
  - ACME IPv6 validation
  - X.509 IPv6 SAN
- **Days 8-10**: Testing & Documentation
  - IPv6 integration tests
  - Configuration documentation
  - IPv6 deployment guide

### Sprint 2: Medium Priority (Week 3-4)

- **Days 11-20**: SCMS PKCS#11 Token Operations (Track 2.1)
  - Token initialization (Days 11-12)
  - PIN operations (Days 13-14)
  - Key generation (Days 15-17)
  - Testing with SoftHSM (Days 18-20)
- **Days 21-23**: Audit Logging Hookups (Track 2.2)
  - SCMS audit events (16 TODOs)
  - ACME/EST audit events (4 TODOs)
  - Event type additions

### Sprint 3: Low Priority (Week 5, Optional)

- **Days 24-28**: Advanced Features (Track 3)
  - Enhanced CSR processing (Days 24-25)
  - OCSP caching (Day 26)
  - Database extensions (Day 27)
  - PKCS#7 wrapping (Day 28)

---

## Testing Strategy

### Unit Tests

- [ ] Configuration loading and validation
- [ ] IPv6 address parsing and validation
- [ ] PKCS#11 mock operations
- [ ] Audit event emission
- [ ] CSR signature verification
- [ ] OCSP cache expiration

### Integration Tests

- [ ] Dual-stack server binding
- [ ] ACME HTTP-01 over IPv6
- [ ] SCMS token lifecycle with SoftHSM
- [ ] Audit log persistence
- [ ] EST enrollment with PKCS#7 response

### Performance Tests

- [ ] OCSP cache hit rate >80%
- [ ] OCSP cached response latency <5ms (p99)
- [ ] Configuration load time <100ms
- [ ] PKCS#11 operations <100ms (p99)

### Security Tests

- [ ] IPv6 SSRF prevention
- [ ] Configuration secrets not logged
- [ ] PIN retry lockout enforced
- [ ] Private key zeroization after use

---

## Success Criteria

### Track 1 (High Priority) - Required for v1.0

- [ ] All configuration externalized
- [ ] All 14 URL TODOs resolved
- [ ] Full IPv6 dual-stack support
- [ ] IPv6 ACME validation functional
- [ ] Configuration validation on startup
- [ ] Documentation complete

### Track 2 (Medium Priority) - Required for v1.1

- [ ] All 29 SCMS PKCS#11 TODOs resolved
- [ ] Token lifecycle via PKCS#11 functional
- [ ] All 21 audit logging TODOs resolved
- [ ] Comprehensive audit coverage

### Track 3 (Low Priority) - Optional Enhancements

- [ ] CSR signature verification
- [ ] SAN extraction from CSR
- [ ] OCSP response caching (>80% hit rate)
- [ ] EST server-side keygen (with warnings)
- [ ] Database schema extensions

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| **IPv6 Infrastructure Unavailable** | Medium | Medium | Support IPv4-only mode, document dual-stack benefits |
| **PKCS#11 Token Compatibility** | High | Medium | Extensive testing with SoftHSM and multiple vendor tokens |
| **Configuration Migration Breaking Changes** | Low | High | Provide migration tool, backward compatibility for 1 release |
| **OCSP Cache Invalidation Issues** | Medium | Low | Conservative TTL, explicit invalidation on revocation |
| **EST Server Keygen Security Concerns** | Low | High | Document risks, make opt-in, require explicit config flag |

---

## Dependencies

**Required Crates (New)**:

- `jsonschema` - JSON Schema validation (Draft 2020-12)
- `serde_json` - JSON parsing (already present, ensure latest)
- `url` - URL parsing for IP literal detection
- `regex` - Environment variable pattern matching
- `trust-dns-resolver` - IPv6 DNS resolution
- `cms` - PKCS#7/CMS message syntax
- `lru` - LRU cache for OCSP

**Updated Crates**:

- `cryptoki` - PKCS#11 operations (already present)
- `axum-server` - Dual-stack server support

---

## Deferred Items (Post-v1.1)

**Items NOT in Phase 13**:

- Post-quantum OID updates (waiting for NIST finalization)
- Audit hash chain verification (enhancement beyond FAU_STG.1)
- OpenSSL compatibility tests (Phase 14 item)
- Fuzzing (Phase 14 item)
- Performance benchmarking (Phase 14 item)

---

## Documentation Deliverables

1. **Configuration Guide** (`docs/CONFIGURATION.md`)
   - All config parameters
   - Environment variable overrides
   - Migration from hardcoded values

2. **IPv6 Deployment Guide** (`docs/IPv6_SUPPORT.md`)
   - Dual-stack setup
   - IPv6-only deployment
   - Firewall configuration
   - Troubleshooting

3. **SCMS Token Operations** (`docs/SCMS_PKCS11.md`)
   - Token initialization procedures
   - PIN management
   - Key generation workflows
   - Supported token vendors

4. **Phase 13 Summary** (`docs/PHASE_13_SUMMARY.md`)
   - Implementation summary
   - Test results
   - Known limitations
   - Future enhancements

---

## Conclusion

Phase 13 addresses **123 TODO items** plus critical IPv6 support, organized into 3 priority tracks:

- **Track 1 (HIGH)**: Configuration management and IPv6 support - **required for v1.0 production**
- **Track 2 (MEDIUM)**: SCMS PKCS#11 operations and audit logging - **recommended for v1.1**
- **Track 3 (LOW)**: Advanced features - **optional enhancements for v1.2+**

The phase is **optional** as the system is already production-ready, but Track 1 items significantly improve operational readiness and modern networking support.

**Recommended Approach**: Complete Track 1 before v1.0 launch, defer Tracks 2-3 to post-launch based on operational requirements.

---

**Document Version**: 1.0
**Last Updated**: January 2026
**Status**: Planning Complete, Implementation Pending User Approval
