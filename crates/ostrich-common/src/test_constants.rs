//! # Test Constants for OstrichPKI
//!
//! This module provides RFC-compliant constants for use in test code.
//! Using these constants ensures that tests do not accidentally connect
//! to real network resources.
//!
//! ## NIAP PP-CA Compliance
//! - FMT_MSA.1: Secure configuration defaults
//!
//! ## RFC Compliance
//! - RFC 5737: IPv4 Address Blocks Reserved for Documentation
//! - RFC 3849: IPv6 Address Prefix Reserved for Documentation

/// IPv4 test addresses from RFC 5737.
///
/// These addresses are reserved for documentation and examples,
/// and will never be assigned to real hosts on the Internet.
///
/// # Usage
/// ```rust
/// use ostrich_common::test_constants::test_ipv4;
///
/// let test_addr = test_ipv4::TEST_NET_1;
/// assert!(test_addr.starts_with("192.0.2."));
/// ```
pub mod test_ipv4 {
    /// TEST-NET-1: 192.0.2.0/24 (RFC 5737)
    /// First host in the range.
    pub const TEST_NET_1: &str = "192.0.2.1";

    /// TEST-NET-1: 192.0.2.0/24 (RFC 5737)
    /// Second host in the range.
    pub const TEST_NET_1_HOST_2: &str = "192.0.2.2";

    /// TEST-NET-1: 192.0.2.0/24 (RFC 5737)
    /// Third host in the range.
    pub const TEST_NET_1_HOST_3: &str = "192.0.2.3";

    /// TEST-NET-1: 192.0.2.0/24 (RFC 5737)
    /// High-numbered host in the range.
    pub const TEST_NET_1_HOST_100: &str = "192.0.2.100";

    /// TEST-NET-2: 198.51.100.0/24 (RFC 5737)
    /// First host in the range.
    pub const TEST_NET_2: &str = "198.51.100.1";

    /// TEST-NET-2: 198.51.100.0/24 (RFC 5737)
    /// Second host in the range.
    pub const TEST_NET_2_HOST_2: &str = "198.51.100.2";

    /// TEST-NET-2: 198.51.100.0/24 (RFC 5737)
    /// High-numbered host in the range.
    pub const TEST_NET_2_HOST_100: &str = "198.51.100.100";

    /// TEST-NET-3: 203.0.113.0/24 (RFC 5737)
    /// First host in the range.
    pub const TEST_NET_3: &str = "203.0.113.1";

    /// TEST-NET-3: 203.0.113.0/24 (RFC 5737)
    /// Second host in the range.
    pub const TEST_NET_3_HOST_2: &str = "203.0.113.2";

    /// TEST-NET-3: 203.0.113.0/24 (RFC 5737)
    /// High-numbered host in the range.
    pub const TEST_NET_3_HOST_100: &str = "203.0.113.100";

    /// Network address for TEST-NET-1 (for CIDR testing).
    pub const TEST_NET_1_NETWORK: &str = "192.0.2.0";

    /// Broadcast address for TEST-NET-1 (for CIDR testing).
    pub const TEST_NET_1_BROADCAST: &str = "192.0.2.255";
}

/// IPv6 test addresses from RFC 3849.
///
/// These addresses use the 2001:db8::/32 prefix, which is reserved
/// for documentation and examples.
///
/// # Usage
/// ```rust
/// use ostrich_common::test_constants::test_ipv6;
///
/// let test_addr = test_ipv6::DOCUMENTATION;
/// assert!(test_addr.starts_with("2001:db8::"));
/// ```
pub mod test_ipv6 {
    /// Documentation prefix: 2001:db8::/32 (RFC 3849)
    /// Simple host address.
    pub const DOCUMENTATION: &str = "2001:db8::1";

    /// Documentation prefix (RFC 3849)
    /// Second host address.
    pub const DOCUMENTATION_HOST_2: &str = "2001:db8::2";

    /// Documentation prefix (RFC 3849)
    /// Third host address.
    pub const DOCUMENTATION_HOST_3: &str = "2001:db8::3";

    /// Documentation prefix (RFC 3849)
    /// Full expanded format.
    pub const DOCUMENTATION_FULL: &str = "2001:0db8:0000:0000:0000:0000:0000:0001";

    /// Documentation prefix (RFC 3849)
    /// With subnet identifier.
    pub const DOCUMENTATION_SUBNET_1: &str = "2001:db8:1::1";

    /// Documentation prefix (RFC 3849)
    /// With second subnet identifier.
    pub const DOCUMENTATION_SUBNET_2: &str = "2001:db8:2::1";

    /// Documentation prefix (RFC 3849)
    /// With EUI-64 style suffix.
    pub const DOCUMENTATION_EUI64: &str = "2001:db8::aabb:ccff:fedd:eeff";

    /// Documentation network prefix (for CIDR testing).
    pub const DOCUMENTATION_NETWORK: &str = "2001:db8::";

    /// Loopback address for local testing.
    pub const LOOPBACK: &str = "::1";
}

/// Test hostnames for use in test URLs and configurations.
///
/// These use `.example`, `.test`, `.invalid`, and `.localhost` TLDs
/// which are reserved by IANA and will never be registered.
///
/// # RFC Compliance
/// - RFC 2606: Reserved Top Level DNS Names
/// - RFC 6761: Special-Use Domain Names
pub mod test_hostnames {
    /// Example domain (RFC 2606).
    pub const EXAMPLE_COM: &str = "example.com";

    /// Example domain for ACME (RFC 2606).
    pub const ACME_EXAMPLE_COM: &str = "acme.example.com";

    /// Example domain for CA (RFC 2606).
    pub const CA_EXAMPLE_COM: &str = "ca.example.com";

    /// Example domain for OCSP (RFC 2606).
    pub const OCSP_EXAMPLE_COM: &str = "ocsp.example.com";

    /// Example domain for EST (RFC 2606).
    pub const EST_EXAMPLE_COM: &str = "est.example.com";

    /// Example domain for KRA (RFC 2606).
    pub const KRA_EXAMPLE_COM: &str = "kra.example.com";

    /// Example domain for SCMS (RFC 2606).
    pub const SCMS_EXAMPLE_COM: &str = "scms.example.com";

    /// Invalid TLD (RFC 2606) - for negative testing.
    pub const INVALID_HOST: &str = "invalid.invalid";

    /// Test TLD (RFC 2606).
    pub const TEST_HOST: &str = "test.test";

    /// Localhost for local testing.
    pub const LOCALHOST: &str = "localhost";

    /// Subdomain of example.org (RFC 2606).
    pub const EXAMPLE_ORG: &str = "example.org";

    /// Subdomain of example.net (RFC 2606).
    pub const EXAMPLE_NET: &str = "example.net";
}

/// Test URLs combining hostnames with standard ports and paths.
pub mod test_urls {
    #![allow(unused_imports)]
    use super::test_hostnames;

    /// Base URL for ACME service testing.
    pub const ACME_BASE_URL: &str = "https://acme.example.com";

    /// ACME directory URL.
    pub const ACME_DIRECTORY_URL: &str = "https://acme.example.com/directory";

    /// ACME new-account URL.
    pub const ACME_NEW_ACCOUNT_URL: &str = "https://acme.example.com/acme/new-account";

    /// ACME new-order URL.
    pub const ACME_NEW_ORDER_URL: &str = "https://acme.example.com/acme/new-order";

    /// ACME new-nonce URL.
    pub const ACME_NEW_NONCE_URL: &str = "https://acme.example.com/acme/new-nonce";

    /// Base URL for CA service testing.
    pub const CA_BASE_URL: &str = "https://ca.example.com";

    /// CA gRPC endpoint.
    pub const CA_GRPC_URL: &str = "https://ca.example.com:8443";

    /// Base URL for OCSP service testing.
    pub const OCSP_BASE_URL: &str = "https://ocsp.example.com";

    /// Base URL for EST service testing.
    pub const EST_BASE_URL: &str = "https://est.example.com";

    /// EST cacerts URL.
    pub const EST_CACERTS_URL: &str = "https://est.example.com/.well-known/est/cacerts";

    /// EST simpleenroll URL.
    pub const EST_SIMPLEENROLL_URL: &str = "https://est.example.com/.well-known/est/simpleenroll";

    /// Base URL for KRA service testing.
    pub const KRA_BASE_URL: &str = "https://kra.example.com";

    /// Base URL for SCMS service testing.
    pub const SCMS_BASE_URL: &str = "https://scms.example.com";

    /// Returns the base URL for a given hostname.
    pub fn https_url(hostname: &str) -> String {
        format!("https://{}", hostname)
    }

    /// Returns a URL with a specific port.
    pub fn https_url_with_port(hostname: &str, port: u16) -> String {
        format!("https://{}:{}", hostname, port)
    }
}

/// Test ports for use in configurations.
///
/// These are well-known ports and ephemeral ports for testing.
pub mod test_ports {
    /// Standard HTTPS port.
    pub const HTTPS: u16 = 443;

    /// Alternative HTTPS port (commonly used for admin interfaces).
    pub const HTTPS_ALT: u16 = 8443;

    /// gRPC default port.
    pub const GRPC: u16 = 50051;

    /// PostgreSQL default port.
    pub const POSTGRES: u16 = 5432;

    /// Ephemeral port range start (for dynamic port allocation in tests).
    pub const EPHEMERAL_START: u16 = 49152;

    /// OCSP common port.
    pub const OCSP: u16 = 80;

    /// ACME common port.
    pub const ACME: u16 = 443;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_ipv4_addresses_are_valid() {
        // Verify all IPv4 test addresses are parseable
        assert!(test_ipv4::TEST_NET_1.parse::<Ipv4Addr>().is_ok());
        assert!(test_ipv4::TEST_NET_1_HOST_2.parse::<Ipv4Addr>().is_ok());
        assert!(test_ipv4::TEST_NET_1_HOST_3.parse::<Ipv4Addr>().is_ok());
        assert!(test_ipv4::TEST_NET_1_HOST_100.parse::<Ipv4Addr>().is_ok());
        assert!(test_ipv4::TEST_NET_2.parse::<Ipv4Addr>().is_ok());
        assert!(test_ipv4::TEST_NET_2_HOST_2.parse::<Ipv4Addr>().is_ok());
        assert!(test_ipv4::TEST_NET_2_HOST_100.parse::<Ipv4Addr>().is_ok());
        assert!(test_ipv4::TEST_NET_3.parse::<Ipv4Addr>().is_ok());
        assert!(test_ipv4::TEST_NET_3_HOST_2.parse::<Ipv4Addr>().is_ok());
        assert!(test_ipv4::TEST_NET_3_HOST_100.parse::<Ipv4Addr>().is_ok());
    }

    #[test]
    fn test_ipv4_addresses_in_rfc5737_ranges() {
        // TEST-NET-1: 192.0.2.0/24
        let addr: Ipv4Addr = test_ipv4::TEST_NET_1.parse().unwrap();
        assert!(addr.octets()[0] == 192 && addr.octets()[1] == 0 && addr.octets()[2] == 2);

        // TEST-NET-2: 198.51.100.0/24
        let addr: Ipv4Addr = test_ipv4::TEST_NET_2.parse().unwrap();
        assert!(addr.octets()[0] == 198 && addr.octets()[1] == 51 && addr.octets()[2] == 100);

        // TEST-NET-3: 203.0.113.0/24
        let addr: Ipv4Addr = test_ipv4::TEST_NET_3.parse().unwrap();
        assert!(addr.octets()[0] == 203 && addr.octets()[1] == 0 && addr.octets()[2] == 113);
    }

    #[test]
    fn test_ipv6_addresses_are_valid() {
        // Verify all IPv6 test addresses are parseable
        assert!(test_ipv6::DOCUMENTATION.parse::<Ipv6Addr>().is_ok());
        assert!(test_ipv6::DOCUMENTATION_HOST_2.parse::<Ipv6Addr>().is_ok());
        assert!(test_ipv6::DOCUMENTATION_HOST_3.parse::<Ipv6Addr>().is_ok());
        assert!(test_ipv6::DOCUMENTATION_FULL.parse::<Ipv6Addr>().is_ok());
        assert!(
            test_ipv6::DOCUMENTATION_SUBNET_1
                .parse::<Ipv6Addr>()
                .is_ok()
        );
        assert!(
            test_ipv6::DOCUMENTATION_SUBNET_2
                .parse::<Ipv6Addr>()
                .is_ok()
        );
        assert!(test_ipv6::DOCUMENTATION_EUI64.parse::<Ipv6Addr>().is_ok());
        assert!(test_ipv6::LOOPBACK.parse::<Ipv6Addr>().is_ok());
    }

    #[test]
    fn test_ipv6_addresses_in_rfc3849_range() {
        // Documentation prefix: 2001:db8::/32
        let addr: Ipv6Addr = test_ipv6::DOCUMENTATION.parse().unwrap();
        let segments = addr.segments();
        assert_eq!(segments[0], 0x2001);
        assert_eq!(segments[1], 0x0db8);
    }

    #[test]
    fn test_hostnames_are_valid() {
        // All hostnames should be valid DNS names
        assert!(!test_hostnames::EXAMPLE_COM.is_empty());
        assert!(test_hostnames::EXAMPLE_COM.contains('.'));
        assert!(!test_hostnames::LOCALHOST.contains('.'));
    }

    #[test]
    fn test_urls_are_valid() {
        // All URLs should start with https://
        assert!(test_urls::ACME_BASE_URL.starts_with("https://"));
        assert!(test_urls::CA_BASE_URL.starts_with("https://"));
        assert!(test_urls::OCSP_BASE_URL.starts_with("https://"));
        assert!(test_urls::EST_BASE_URL.starts_with("https://"));
    }

    #[test]
    fn test_url_builders() {
        assert_eq!(test_urls::https_url("example.com"), "https://example.com");
        assert_eq!(
            test_urls::https_url_with_port("example.com", 8443),
            "https://example.com:8443"
        );
    }
}
