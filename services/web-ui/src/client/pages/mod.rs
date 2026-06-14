//! Page Components
//!
//! Main page components for each route.

mod dashboard;
mod certificates;
mod certificate_issue;
mod approvals;
mod audit;
mod scms;
mod users;
mod settings;
mod login;
mod not_found;

pub use dashboard::Dashboard;
pub use certificates::{Certificates, CertificateDetail};
pub use certificate_issue::CertificateIssue;
pub use approvals::Approvals;
pub use audit::AuditLogs;
pub use scms::Scms;
pub use users::Users;
pub use settings::Settings;
pub use login::Login;
pub use not_found::NotFound;
