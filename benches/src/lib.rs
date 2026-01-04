//! OstrichPKI Performance Benchmarks
//!
//! This crate contains Criterion benchmarks for critical PKI operations.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Security Testing)
//! - NIST 800-53: CP-2 (Contingency Plan) - Capacity planning
//!
//! ## Running Benchmarks
//!
//! Run all benchmarks:
//! ```bash
//! cargo bench
//! ```
//!
//! Run specific benchmark:
//! ```bash
//! cargo bench --bench crypto_benchmarks
//! cargo bench --bench x509_benchmarks
//! cargo bench --bench encoding_benchmarks
//! ```
//!
//! Generate HTML reports:
//! ```bash
//! cargo bench -- --save-baseline main
//! ```
//!
//! Compare with baseline:
//! ```bash
//! cargo bench -- --baseline main
//! ```
//!
//! ## Benchmark Categories
//!
//! - **crypto_benchmarks**: RSA key generation, signing, verification, SHA-256
//! - **x509_benchmarks**: Certificate parsing, encoding, DN parsing
//! - **encoding_benchmarks**: Base64, hex, DER, JSON serialization

pub mod utils;
