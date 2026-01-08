//! OAuth Callback Utilities
//!
//! Additional utilities for handling OAuth callbacks.
//! This module is a placeholder for future callback-related utilities such as:
//! - Custom claim processing
//! - Role mapping configuration
//! - User provisioning hooks

#![allow(dead_code)] // Module prepared for future integration

use super::handlers::CallbackParams;

/// Re-export the callback params type for external use
pub type OAuthCallbackParams = CallbackParams;
