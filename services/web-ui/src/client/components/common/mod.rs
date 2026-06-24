//! Common UI Components
//!
//! Reusable components for the OstrichPKI Web UI.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SI-10 (Information Input Validation) - Form validation
//! - NIAP PP-CA: FIA_UID.1 (User Identification) - User feedback components

mod alert;
mod badge;
mod copy_button;
mod data_table;
mod loading;
mod modal;
mod pagination;

pub use alert::{Alert, AlertType};
pub use badge::{Badge, BadgeSize, BadgeVariant};
pub use copy_button::CopyButton;
pub use data_table::{Column, DataTable, KeyFn, RenderFn};
pub use loading::Loading;
pub use modal::{Modal, ModalSize};
pub use pagination::Pagination;
