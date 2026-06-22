//! Client-side Router
//!
//! Defines all routes for the Yew SPA.

use yew_router::prelude::*;

/// Application routes
#[derive(Clone, Routable, PartialEq)]
pub enum Route {
    /// Dashboard home page
    #[at("/")]
    Dashboard,

    /// Certificate list
    #[at("/certificates")]
    Certificates,

    /// Certificate issuance form
    #[at("/certificates/issue")]
    CertificateIssue,

    /// Certificate detail view
    #[at("/certificates/:id")]
    CertificateDetail { id: String },

    /// Certificate Revocation Lists (CRL management)
    #[at("/crl")]
    Crl,

    /// Certificate profile catalog
    #[at("/profiles")]
    Profiles,

    /// EST enrollment (RFC 7030)
    #[at("/est")]
    Est,

    /// Approval queue
    #[at("/approvals")]
    Approvals,

    /// Audit log viewer
    #[at("/audit")]
    AuditLogs,

    /// SCMS token management
    #[at("/scms")]
    Scms,

    /// User management
    #[at("/users")]
    Users,

    /// Settings
    #[at("/settings")]
    Settings,

    /// Login page
    #[at("/login")]
    Login,

    /// 404 Not Found
    #[not_found]
    #[at("/404")]
    NotFound,
}

impl Route {
    /// Get the display name for this route
    pub fn name(&self) -> &'static str {
        match self {
            Route::Dashboard => "Dashboard",
            Route::Certificates => "Certificates",
            Route::CertificateIssue => "Issue Certificate",
            Route::CertificateDetail { .. } => "Certificate Details",
            Route::Crl => "Revocation Lists",
            Route::Profiles => "Certificate Profiles",
            Route::Est => "EST Enrollment",
            Route::Approvals => "Approvals",
            Route::AuditLogs => "Audit Logs",
            Route::Scms => "Token Management",
            Route::Users => "Users",
            Route::Settings => "Settings",
            Route::Login => "Login",
            Route::NotFound => "Not Found",
        }
    }

    /// Get the icon class for this route (using Heroicons class names)
    pub fn icon(&self) -> &'static str {
        match self {
            Route::Dashboard => "home",
            Route::Certificates => "document-check",
            Route::CertificateIssue => "document-plus",
            Route::CertificateDetail { .. } => "document",
            Route::Crl => "ban",
            Route::Profiles => "template",
            Route::Est => "device",
            Route::Approvals => "clipboard-check",
            Route::AuditLogs => "document-text",
            Route::Scms => "credit-card",
            Route::Users => "users",
            Route::Settings => "cog",
            Route::Login => "login",
            Route::NotFound => "exclamation",
        }
    }

    /// Check if this route requires authentication
    pub fn requires_auth(&self) -> bool {
        match self {
            Route::Login => false,
            Route::NotFound => false,
            _ => true,
        }
    }

    /// Get the required permission for this route (if any)
    pub fn required_permission(&self) -> Option<&'static str> {
        match self {
            Route::Certificates | Route::CertificateDetail { .. } => Some("view_certificates"),
            Route::CertificateIssue => Some("issue_certificates"),
            Route::Crl => Some("view_crl"),
            Route::Profiles => Some("view_config"),
            Route::Est => Some("generate_est_token"),
            Route::Approvals => Some("view_approvals"),
            Route::AuditLogs => Some("read_audit_log"),
            Route::Scms => Some("view_tokens"),
            Route::Users => Some("manage_users"),
            Route::Settings => Some("admin"),
            _ => None,
        }
    }
}
