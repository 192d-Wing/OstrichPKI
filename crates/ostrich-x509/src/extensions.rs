//! X.509 certificate extensions
//!
//! RFC 5280 §4.2 - Standard extensions

/// Subject Alternative Name types
///
/// RFC 5280 §4.2.1.6 - Subject alternative name
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SubjectAltName {
    /// DNS name
    DnsName(String),
    /// RFC 822 email address
    Rfc822Name(String),
    /// URI
    UniformResourceIdentifier(String),
    /// IP address (v4 or v6)
    IpAddress(std::net::IpAddr),
    /// Directory name (DN)
    DirectoryName(String),
}

impl SubjectAltName {
    /// Create a DNS name SAN entry
    pub fn dns(name: impl Into<String>) -> Self {
        SubjectAltName::DnsName(name.into())
    }

    /// Create an email SAN entry
    pub fn email(email: impl Into<String>) -> Self {
        SubjectAltName::Rfc822Name(email.into())
    }

    /// Create a URI SAN entry
    pub fn uri(uri: impl Into<String>) -> Self {
        SubjectAltName::UniformResourceIdentifier(uri.into())
    }

    /// Create an IP address SAN entry
    pub fn ip(ip: std::net::IpAddr) -> Self {
        SubjectAltName::IpAddress(ip)
    }
}

/// Authority Information Access types
///
/// RFC 5280 §4.2.2.1 - Authority information access
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AuthorityInfoAccess {
    /// OCSP responder location
    Ocsp(String),
    /// CA issuers location
    CaIssuers(String),
}

/// CRL Distribution Points
///
/// RFC 5280 §4.2.1.13 - CRL distribution points
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CrlDistributionPoint {
    /// Distribution point URI
    pub uri: String,
}

impl CrlDistributionPoint {
    /// Create a new CRL distribution point
    pub fn new(uri: impl Into<String>) -> Self {
        Self { uri: uri.into() }
    }
}

/// Certificate Policies
///
/// RFC 5280 §4.2.1.4 - Certificate policies
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificatePolicy {
    /// Policy OID
    pub oid: String,
    /// CPS URI (optional)
    pub cps_uri: Option<String>,
    /// User notice (optional)
    pub user_notice: Option<String>,
}

impl CertificatePolicy {
    /// Create a new certificate policy
    pub fn new(oid: impl Into<String>) -> Self {
        Self {
            oid: oid.into(),
            cps_uri: None,
            user_notice: None,
        }
    }

    /// Add CPS URI
    pub fn with_cps_uri(mut self, uri: impl Into<String>) -> Self {
        self.cps_uri = Some(uri.into());
        self
    }

    /// Add user notice
    pub fn with_user_notice(mut self, notice: impl Into<String>) -> Self {
        self.user_notice = Some(notice.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subject_alt_name() {
        let san_dns = SubjectAltName::dns("example.com");
        assert!(matches!(san_dns, SubjectAltName::DnsName(_)));

        let san_email = SubjectAltName::email("user@example.com");
        assert!(matches!(san_email, SubjectAltName::Rfc822Name(_)));
    }

    #[test]
    fn test_crl_distribution_point() {
        let cdp = CrlDistributionPoint::new("http://crl.example.com/ca.crl");
        assert_eq!(cdp.uri, "http://crl.example.com/ca.crl");
    }

    #[test]
    fn test_certificate_policy() {
        let policy = CertificatePolicy::new("2.16.840.1.114412.1.1")
            .with_cps_uri("https://example.com/cps")
            .with_user_notice("This is a test policy");

        assert_eq!(policy.oid, "2.16.840.1.114412.1.1");
        assert!(policy.cps_uri.is_some());
        assert!(policy.user_notice.is_some());
    }
}
