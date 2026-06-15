//! Page Components
//!
//! Main page components for each route.

mod approvals;
mod audit;
mod certificate_issue;
mod certificates;
mod crl;
mod dashboard;
mod est;
mod login;
mod not_found;
mod profiles;
mod scms;
mod settings;
mod users;

pub use approvals::Approvals;
pub use audit::AuditLogs;
pub use certificate_issue::CertificateIssue;
pub use certificates::{CertificateDetail, Certificates};
pub use crl::Crl;
pub use dashboard::Dashboard;
pub use est::Est;
pub use login::Login;
pub use not_found::NotFound;
pub use profiles::Profiles;
pub use scms::Scms;
pub use settings::Settings;
pub use users::Users;
