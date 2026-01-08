//! OstrichPKI Web UI Client (Yew WASM Application)
//!
//! This is the client-side Yew application that runs in the browser.
//! It provides the admin dashboard interface for OstrichPKI.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-3 (Access Enforcement) - Client-side permission checks
//! - NIST 800-53: AU-12 (Audit Record Generation) - Client-side event logging

#![cfg(target_arch = "wasm32")]

mod app;
mod components;
mod pages;
mod router;
mod services;
mod types;

use wasm_bindgen::prelude::*;

/// Entry point for the WASM application
#[wasm_bindgen(start)]
pub fn main() {
    // Set up panic hook for better error messages
    console_error_panic_hook::set_once();

    // Initialize WASM tracing
    tracing_wasm::set_as_global_default();

    tracing::info!("OstrichPKI Web UI starting...");

    // Mount the Yew application
    yew::Renderer::<app::App>::new().render();

    tracing::info!("OstrichPKI Web UI mounted");
}
