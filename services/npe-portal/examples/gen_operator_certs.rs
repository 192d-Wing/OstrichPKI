//! Generate an NPE operator client CA + one client cert per portal role.
//!
//! The NPE portal authenticates operators by mTLS and derives the role from the
//! client certificate's **Certificate Policies** extension (RFC 5280 §4.2.1.4),
//! matched against `oidMapping` in the portal config. This tool mints a
//! self-contained operator trust domain for testing/bootstrapping that posture:
//!
//!   - `ca.pem`                  -> the `npe-operator-client-ca` secret (ca.pem)
//!   - `<role>.crt` / `<role>.key` -> hand to each operator
//!
//! It also prints the CA subject DN exactly as `x509-parser` renders it, for the
//! portal's `oidMapping.allowedIssuers` (issuer scoping).
//!
//! Run (in WSL):
//!   cargo run -p ostrich-npe-portal --example gen_operator_certs -- <out_dir>
//!
//! Role -> policy OID(s) mirror deploy/kubernetes/npe-portal-acme configmap:
//!   sponsor 2.16.840.1.101.2.1.11.42
//!   admin   sponsor + 2.16.840.1.101.2.1.11.43  (elevation OID)
//!   ra      2.16.840.1.101.2.1.11.44
//!   caa     2.16.840.1.101.2.1.11.45

use std::collections::HashSet;
use std::path::PathBuf;

use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};

const SPONSOR_OID: &str = "2.16.840.1.101.2.1.11.42";
const ADMIN_OID: &str = "2.16.840.1.101.2.1.11.43";
const RA_OID: &str = "2.16.840.1.101.2.1.11.44";
const CAA_OID: &str = "2.16.840.1.101.2.1.11.45";

/// id-ce-certificatePolicies = 2.5.29.32
const CERT_POLICIES_OID: &[u64] = &[2, 5, 29, 32];

struct RoleSpec {
    name: &'static str,
    common_name: &'static str,
    policy_oids: &'static [&'static str],
}

fn roles() -> Vec<RoleSpec> {
    vec![
        RoleSpec {
            name: "sponsor",
            common_name: "SPONSOR.TEST.NPE.1",
            policy_oids: &[SPONSOR_OID],
        },
        RoleSpec {
            name: "admin",
            common_name: "ADMIN.TEST.NPE.2",
            policy_oids: &[SPONSOR_OID, ADMIN_OID],
        },
        RoleSpec {
            name: "ra",
            common_name: "RA.TEST.NPE.3",
            policy_oids: &[RA_OID],
        },
        RoleSpec {
            name: "caa",
            common_name: "CAA.TEST.NPE.4",
            policy_oids: &[CAA_OID],
        },
    ]
}

/// DER tag+length prefix for a value < 128 bytes (always true for our OIDs).
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    assert!(content.len() < 128, "DER long-form length not needed here");
    let mut v = Vec::with_capacity(content.len() + 2);
    v.push(tag);
    v.push(content.len() as u8);
    v.extend_from_slice(content);
    v
}

/// Encode the certificatePolicies extension value:
///   SEQUENCE OF PolicyInformation { policyIdentifier OBJECT IDENTIFIER }
fn cert_policies_value(oids: &[&str]) -> Vec<u8> {
    let mut policy_infos = Vec::new();
    for o in oids {
        let oid = const_oid::ObjectIdentifier::new_unwrap(o);
        let oid_tlv = tlv(0x06, oid.as_bytes()); // OBJECT IDENTIFIER
        let policy_info = tlv(0x30, &oid_tlv); // PolicyInformation SEQUENCE
        policy_infos.extend_from_slice(&policy_info);
    }
    tlv(0x30, &policy_infos) // certificatePolicies SEQUENCE
}

fn dn(common_name: &str) -> DistinguishedName {
    let mut d = DistinguishedName::new();
    d.push(DnType::CommonName, common_name);
    d.push(DnType::OrganizationName, "U.S. Government");
    d.push(DnType::OrganizationalUnitName, "NPE");
    d.push(DnType::CountryName, "US");
    d
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(
        std::env::args()
            .nth(1)
            .unwrap_or_else(|| "operator-certs".into()),
    );
    std::fs::create_dir_all(&out_dir)?;

    // --- Operator client CA (self-signed) ---
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.distinguished_name = dn("OstrichPKI NPE Operator CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_cert = ca_params.self_signed(&ca_key)?;
    std::fs::write(out_dir.join("ca.pem"), ca_cert.pem())?;
    std::fs::write(out_dir.join("ca.key"), ca_key.serialize_pem())?;

    // Issuer used to sign each leaf (same construction self_signed uses).
    let ca_issuer = Issuer::from_params(&ca_params, &ca_key);

    // --- One client cert per role ---
    let mut printed_issuer = String::new();
    for role in roles() {
        let leaf_key = KeyPair::generate()?;
        let mut p = CertificateParams::new(Vec::<String>::new())?;
        p.distinguished_name = dn(role.common_name);
        p.is_ca = IsCa::NoCa;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        p.use_authority_key_identifier_extension = true;
        p.custom_extensions.push(CustomExtension::from_oid_content(
            CERT_POLICIES_OID,
            cert_policies_value(role.policy_oids),
        ));

        let leaf = p.signed_by(&leaf_key, &ca_issuer)?;
        let leaf_pem = leaf.pem();
        std::fs::write(out_dir.join(format!("{}.crt", role.name)), &leaf_pem)?;
        std::fs::write(
            out_dir.join(format!("{}.key", role.name)),
            leaf_key.serialize_pem(),
        )?;

        // Self-check: re-parse exactly as the portal does (x509-parser) and
        // confirm the policy OIDs + capture the issuer DN string.
        let (got_policies, issuer) = parse_back(&leaf_pem)?;
        let want: HashSet<String> = role.policy_oids.iter().map(|s| s.to_string()).collect();
        assert!(
            want.is_subset(&got_policies),
            "role {}: expected policy OIDs {:?} but cert carries {:?}",
            role.name,
            want,
            got_policies
        );
        printed_issuer = issuer;
        println!(
            "  {:7} CN={:<20} policies={:?}",
            role.name, role.common_name, role.policy_oids
        );
    }

    println!(
        "\nWrote operator CA + 4 role certs to {}",
        out_dir.display()
    );
    println!("\nallowedIssuers (paste into the portal oidMapping):");
    println!("  \"{printed_issuer}\"");
    Ok(())
}

/// Parse a leaf PEM the way the portal does and return (policy OIDs, issuer DN).
fn parse_back(pem: &str) -> Result<(HashSet<String>, String), Box<dyn std::error::Error>> {
    use x509_parser::extensions::ParsedExtension;

    let (_, pem_block) = x509_parser::pem::parse_x509_pem(pem.as_bytes())?;
    let cert = pem_block.parse_x509()?;
    let issuer = cert.issuer().to_string();
    let mut policies = HashSet::new();
    for ext in cert.extensions() {
        if let ParsedExtension::CertificatePolicies(ps) = ext.parsed_extension() {
            for p in ps.iter() {
                policies.insert(p.policy_id.to_id_string());
            }
        }
    }
    Ok((policies, issuer))
}
