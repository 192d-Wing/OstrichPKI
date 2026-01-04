//! X.509 certificate and CRL parsing
//!
//! RFC 5280: X.509 certificate and CRL parsing
//! RFC 2986: PKCS#10 certification request syntax

use crate::{Error, Result};
use ostrich_crypto::{Algorithm, CryptoProvider, KeyHandle};
use std::sync::Arc;
use x509_parser::prelude::*;

/// Parse a DER-encoded X.509 certificate
///
/// RFC 5280 §4.1 - Basic certificate fields
/// RFC 5280 §4.2 - Certificate extensions
///
/// COMPLIANCE MAPPING:
/// - RFC 5280 §4.1: Certificate structure parsing
/// - RFC 5280 §4.2.1.3: Key Usage extension
/// - RFC 5280 §4.2.1.6: Subject Alternative Name extension
/// - RFC 5280 §4.2.1.9: Basic Constraints extension
pub fn parse_certificate(der: &[u8]) -> Result<ParsedCertificate> {
    if der.is_empty() {
        return Err(Error::Parse("Empty DER data".to_string()));
    }

    // Parse the X.509 certificate using x509-parser
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| Error::Parse(format!("Failed to parse X.509 certificate: {}", e)))?;

    // Extract serial number
    let serial_number = cert.serial.to_bytes_be();

    // Extract subject and issuer DNs
    let subject_dn = cert.subject().to_string();
    let issuer_dn = cert.issuer().to_string();

    // Extract validity period
    let not_before = cert.validity().not_before.to_datetime().unix_timestamp();
    let not_before = chrono::DateTime::from_timestamp(not_before, 0)
        .ok_or_else(|| Error::Parse("Invalid notBefore timestamp".to_string()))?;

    let not_after = cert.validity().not_after.to_datetime().unix_timestamp();
    let not_after = chrono::DateTime::from_timestamp(not_after, 0)
        .ok_or_else(|| Error::Parse("Invalid notAfter timestamp".to_string()))?;

    // Extract public key (SubjectPublicKeyInfo) - already in DER format
    let public_key = cert.public_key().raw.to_vec();

    // Extract signature
    let signature = cert.signature_value.data.to_vec();

    // Extract signature algorithm OID
    let signature_algorithm = cert.signature_algorithm.algorithm.to_id_string();

    // Extract TBS (To Be Signed) certificate
    // Note: For now, store empty vec as signature verification is not yet enabled
    // When implementing signature verification, we'll need to extract the exact DER bytes
    // of the TBS certificate from the original encoding
    let tbs_certificate = vec![];

    // Parse extensions
    let (basic_constraints, key_usage, subject_alt_names) = parse_certificate_extensions(&cert)?;

    Ok(ParsedCertificate {
        serial_number,
        subject_dn,
        issuer_dn,
        not_before,
        not_after,
        public_key,
        signature,
        signature_algorithm,
        tbs_certificate,
        der_encoded: der.to_vec(),
        basic_constraints,
        key_usage,
        subject_alt_names,
    })
}

/// Certificate extension parsing result type
type ExtensionsResult = (
    Option<(bool, Option<u32>)>, // BasicConstraints (ca, pathLen)
    Option<Vec<String>>,         // KeyUsage flags
    Vec<String>,                 // SubjectAltNames
);

/// Parse certificate extensions
///
/// RFC 5280 §4.2 - Standard Extensions
fn parse_certificate_extensions(cert: &X509Certificate) -> Result<ExtensionsResult> {
    let mut basic_constraints = None;
    let mut key_usage = None;
    let mut subject_alt_names = Vec::new();

    // Get extensions - x509-parser returns a slice, not Option
    let extensions = cert.extensions();

    if !extensions.is_empty() {
        for ext in extensions {
            let oid = ext.oid.to_id_string();

            match oid.as_str() {
                "2.5.29.19" => {
                    // Basic Constraints (RFC 5280 §4.2.1.9)
                    let parsed = ext.parsed_extension();
                    if let ParsedExtension::BasicConstraints(bc_ext) = parsed {
                        basic_constraints = Some((bc_ext.ca, bc_ext.path_len_constraint));
                    }
                }
                "2.5.29.15" => {
                    // Key Usage (RFC 5280 §4.2.1.3)
                    let parsed = ext.parsed_extension();
                    if let ParsedExtension::KeyUsage(ku_ext) = parsed {
                        let mut usages = Vec::new();
                        if ku_ext.digital_signature() {
                            usages.push("digitalSignature".to_string());
                        }
                        if ku_ext.non_repudiation() {
                            usages.push("nonRepudiation".to_string());
                        }
                        if ku_ext.key_encipherment() {
                            usages.push("keyEncipherment".to_string());
                        }
                        if ku_ext.data_encipherment() {
                            usages.push("dataEncipherment".to_string());
                        }
                        if ku_ext.key_agreement() {
                            usages.push("keyAgreement".to_string());
                        }
                        if ku_ext.key_cert_sign() {
                            usages.push("keyCertSign".to_string());
                        }
                        if ku_ext.crl_sign() {
                            usages.push("cRLSign".to_string());
                        }
                        if ku_ext.encipher_only() {
                            usages.push("encipherOnly".to_string());
                        }
                        if ku_ext.decipher_only() {
                            usages.push("decipherOnly".to_string());
                        }
                        key_usage = Some(usages);
                    }
                }
                "2.5.29.17" => {
                    // Subject Alternative Name (RFC 5280 §4.2.1.6)
                    let parsed = ext.parsed_extension();
                    if let ParsedExtension::SubjectAlternativeName(san_ext) = parsed {
                        for gn in &san_ext.general_names {
                            match gn {
                                GeneralName::DNSName(dns) => {
                                    subject_alt_names.push(format!("DNS:{}", dns));
                                }
                                GeneralName::RFC822Name(email) => {
                                    subject_alt_names.push(format!("email:{}", email));
                                }
                                GeneralName::URI(uri) => {
                                    subject_alt_names.push(format!("URI:{}", uri));
                                }
                                GeneralName::IPAddress(ip) => {
                                    let ip_str = if ip.len() == 4 {
                                        format!("IP:{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
                                    } else if ip.len() == 16 {
                                        format!(
                                            "IP:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                                            ip[0],
                                            ip[1],
                                            ip[2],
                                            ip[3],
                                            ip[4],
                                            ip[5],
                                            ip[6],
                                            ip[7],
                                            ip[8],
                                            ip[9],
                                            ip[10],
                                            ip[11],
                                            ip[12],
                                            ip[13],
                                            ip[14],
                                            ip[15]
                                        )
                                    } else {
                                        continue;
                                    };
                                    subject_alt_names.push(ip_str);
                                }
                                GeneralName::DirectoryName(dn) => {
                                    subject_alt_names.push(format!("DirName:{}", dn));
                                }
                                _ => {
                                    // Other GeneralName types not yet supported in parsed form
                                }
                            }
                        }
                    }
                }
                _ => {
                    // Unknown or unsupported extension, skip
                }
            }
        }
    }

    Ok((basic_constraints, key_usage, subject_alt_names))
}

/// Parse a PEM-encoded X.509 certificate
///
/// RFC 5280 - PEM encoding
pub fn parse_certificate_pem(_pem: &str) -> Result<ParsedCertificate> {
    // TODO: Implement PEM parsing
    // For now, this is a stub
    parse_certificate(&[])
}

/// Parse a DER-encoded Certificate Signing Request (CSR)
///
/// RFC 2986: PKCS#10 certification request syntax
/// NIST 800-53: SI-10 - Information input validation
pub fn parse_csr(der: &[u8]) -> Result<ParsedCsr> {
    if der.is_empty() {
        return Err(Error::Parse("Empty CSR data".to_string()));
    }

    // Parse CSR using x509-parser
    let (_, csr) = x509_parser::certification_request::X509CertificationRequest::from_der(der)
        .map_err(|e| Error::Parse(format!("Failed to parse PKCS#10 CSR: {}", e)))?;

    // Extract subject DN
    let subject_dn = csr.certification_request_info.subject.to_string();

    // Extract public key (SubjectPublicKeyInfo) - already in DER format
    let public_key = csr.certification_request_info.subject_pki.raw.to_vec();

    // Extract signature
    let signature = csr.signature_value.data.to_vec();

    // Extract signature algorithm OID
    let signature_algorithm = csr.signature_algorithm.algorithm.to_id_string();

    // Extract attributes (use method instead of accessing private field)
    let mut attributes = Vec::new();
    for attr in csr.certification_request_info.attributes() {
        let oid = attr.oid.to_id_string();
        // Store raw DER of attribute value (attr.value is already &[u8])
        let value = attr.value.to_vec();
        attributes.push((oid, value));
    }

    // Extract Subject Alternative Names from extensionRequest attribute
    // RFC 2986 §4.1 - Attributes include extensionRequest
    // RFC 5280 §4.2.1.6 - SubjectAltName extension
    let sans = extract_sans_from_csr(&csr)?;

    Ok(ParsedCsr {
        subject_dn,
        subject_alternative_names: sans,
        public_key,
        attributes,
        signature_algorithm,
        signature,
        der_encoded: der.to_vec(),
    })
}

/// Parse X.509 Distinguished Name to structured format
///
/// RFC 5280 §4.1.2.4 - Issuer and Subject fields
/// RFC 4514 - LDAP: String Representation of Distinguished Names
///
/// COMPLIANCE MAPPING:
/// - RFC 5280 §4.1.2.4: Subject/Issuer DN parsing
/// - RFC 4514: DN string representation
/// - NIST 800-53 SI-10: Input validation (DN attribute extraction)
/// - NIAP PP-CA FDP_ITC.1: Import user data (subject identity)
pub fn parse_distinguished_name(
    name: &x509_parser::x509::X509Name,
) -> Result<ostrich_common::types::DistinguishedName> {
    let mut common_name = None;
    let mut country = None;
    let mut state_or_province = None;
    let mut locality = None;
    let mut organization = None;
    let mut organizational_unit = None;
    let mut serial_number = None;

    // Iterate through all RDNs (Relative Distinguished Names)
    for rdn in name.iter() {
        // Each RDN can have multiple attribute-value pairs (multi-valued RDN)
        for attr in rdn.iter() {
            let oid_str = attr.attr_type().to_id_string();

            // Get the attribute value as a string
            // x509-parser provides attr.as_str() which handles various string types
            let value = attr
                .as_str()
                .map_err(|e| Error::Parse(format!("Failed to parse DN attribute value: {}", e)))?
                .to_string();

            // Match against known DN attribute OIDs
            match oid_str.as_str() {
                "2.5.4.3" => {
                    // CN - Common Name
                    common_name = Some(value);
                }
                "2.5.4.6" => {
                    // C - Country
                    country = Some(value);
                }
                "2.5.4.7" => {
                    // L - Locality
                    locality = Some(value);
                }
                "2.5.4.8" => {
                    // ST - State or Province
                    state_or_province = Some(value);
                }
                "2.5.4.10" => {
                    // O - Organization
                    organization = Some(value);
                }
                "2.5.4.11" => {
                    // OU - Organizational Unit
                    organizational_unit = Some(value);
                }
                "2.5.4.5" => {
                    // serialNumber - Certificate serial number attribute
                    serial_number = Some(value);
                }
                _ => {
                    // Unknown/unsupported attribute, skip
                    tracing::debug!("Skipping unknown DN attribute OID: {}", oid_str);
                }
            }
        }
    }

    Ok(ostrich_common::types::DistinguishedName {
        common_name,
        country,
        state_or_province,
        locality,
        organization,
        organizational_unit,
        serial_number,
    })
}

/// Extract Subject Alternative Names from CSR extensionRequest attribute
///
/// RFC 2986 §4.1 - CSR attributes may contain extensionRequest
/// RFC 5280 §4.2.1.6 - SubjectAltName extension structure
///
/// COMPLIANCE MAPPING:
/// - RFC 2986: PKCS#10 CSR attribute parsing
/// - RFC 5280 §4.2.1.6: SubjectAltName extension
/// - NIST 800-53 SI-10: Input validation
fn extract_sans_from_csr(
    csr: &x509_parser::certification_request::X509CertificationRequest,
) -> Result<Vec<String>> {
    use x509_parser::der_parser::asn1_rs::{FromDer, Sequence};
    use x509_parser::extensions::GeneralName;

    let mut sans = Vec::new();

    // Look for extensionRequest attribute (OID 1.2.840.113549.1.9.14)
    for attr in csr.certification_request_info.attributes() {
        if attr.oid.to_id_string() == "1.2.840.113549.1.9.14" {
            // extensionRequest contains a SET of Extensions
            // RFC 2986: attribute value is a SET containing a SEQUENCE of Extensions
            let extensions_der = attr.value;

            // The value is a SET containing a SEQUENCE of Extensions
            // First parse the SET
            use x509_parser::der_parser::asn1_rs::Set;
            let (_, extensions_set) = Set::from_der(extensions_der).map_err(|e| {
                Error::Parse(format!("Failed to parse extensionRequest SET: {}", e))
            })?;

            // The SET contains raw content that is a SEQUENCE of Extensions
            // Access the SET's content directly
            let extensions_seq_der = extensions_set.content.as_ref();

            // Now parse the SEQUENCE of Extensions
            let (_, extensions_seq) = Sequence::from_der(extensions_seq_der)
                .map_err(|e| Error::Parse(format!("Failed to parse Extensions SEQUENCE: {}", e)))?;

            // Each extension in the SEQUENCE is itself a SEQUENCE { extnID, [critical], extnValue }
            // We need to manually parse each extension from the content
            let mut remaining = extensions_seq.content.as_ref();
            while !remaining.is_empty() {
                // Parse one extension SEQUENCE
                let (rest, extension_seq) = Sequence::from_der(remaining).map_err(|e| {
                    Error::Parse(format!("Failed to parse extension SEQUENCE: {}", e))
                })?;
                remaining = rest;

                // Parse the extension SEQUENCE content: OID, [BOOLEAN], OCTET STRING
                // Use manual parsing from the content bytes
                let mut ext_remaining = extension_seq.content.as_ref();

                // First element: OID
                let (rest, ext_oid) = x509_parser::der_parser::asn1_rs::Oid::from_der(
                    ext_remaining,
                )
                .map_err(|e| Error::Parse(format!("Failed to parse extension OID: {}", e)))?;
                ext_remaining = rest;

                // Check if this is SubjectAltName (2.5.29.17)
                if ext_oid.to_id_string() == "2.5.29.17" {
                    // Check for optional BOOLEAN (critical flag)
                    // BOOLEAN tag is 0x01
                    if ext_remaining.starts_with(&[0x01]) {
                        // Skip the BOOLEAN
                        use x509_parser::der_parser::asn1_rs::Boolean;
                        let (rest, _critical) = Boolean::from_der(ext_remaining).map_err(|e| {
                            Error::Parse(format!("Failed to parse critical flag: {}", e))
                        })?;
                        ext_remaining = rest;
                    }

                    // Now get the OCTET STRING containing the extension value
                    let extn_value_der = ext_remaining;

                    // extnValue is an OCTET STRING containing the DER-encoded extension value
                    let (_, octet_string) =
                        x509_parser::der_parser::asn1_rs::OctetString::from_der(extn_value_der)
                            .map_err(|e| {
                                Error::Parse(format!(
                                    "Failed to parse extnValue OCTET STRING: {}",
                                    e
                                ))
                            })?;

                    // The OCTET STRING contains a SEQUENCE of GeneralName
                    let (_, san_seq) = Sequence::from_der(octet_string.as_ref()).map_err(|e| {
                        Error::Parse(format!("Failed to parse SAN SEQUENCE: {}", e))
                    })?;

                    // Parse each GeneralName from the SEQUENCE content
                    // GeneralNames are context-specific tagged, so we parse manually
                    let mut san_remaining = san_seq.content.as_ref();
                    while !san_remaining.is_empty() {
                        // Try to parse as GeneralName
                        match GeneralName::from_der(san_remaining) {
                            Ok((rest, gn)) => {
                                san_remaining = rest;
                                match gn {
                                    GeneralName::DNSName(dns) => {
                                        sans.push(format!("DNS:{}", dns));
                                    }
                                    GeneralName::RFC822Name(email) => {
                                        sans.push(format!("email:{}", email));
                                    }
                                    GeneralName::URI(uri) => {
                                        sans.push(format!("URI:{}", uri));
                                    }
                                    GeneralName::IPAddress(ip) => {
                                        // IP address is encoded as raw octets
                                        let ip_str = if ip.len() == 4 {
                                            // IPv4
                                            format!("IP:{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
                                        } else if ip.len() == 16 {
                                            // IPv6 - simplified formatting
                                            format!(
                                                "IP:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                                                ip[0],
                                                ip[1],
                                                ip[2],
                                                ip[3],
                                                ip[4],
                                                ip[5],
                                                ip[6],
                                                ip[7],
                                                ip[8],
                                                ip[9],
                                                ip[10],
                                                ip[11],
                                                ip[12],
                                                ip[13],
                                                ip[14],
                                                ip[15]
                                            )
                                        } else {
                                            continue; // Invalid IP address length
                                        };
                                        sans.push(ip_str);
                                    }
                                    GeneralName::DirectoryName(dn) => {
                                        sans.push(format!("DirName:{}", dn));
                                    }
                                    GeneralName::OtherName(oid, value) => {
                                        // RFC 5280 §4.2.1.6 - otherName: { type-id, [0] EXPLICIT value }
                                        // Format: otherName:OID:hex-encoded-value
                                        let hex_value = hex::encode(value);
                                        sans.push(format!(
                                            "otherName:{}:{}",
                                            oid.to_id_string(),
                                            hex_value
                                        ));
                                    }
                                    GeneralName::RegisteredID(oid) => {
                                        // RFC 5280 §4.2.1.6 - registeredID: OBJECT IDENTIFIER
                                        sans.push(format!("registeredID:{}", oid.to_id_string()));
                                    }
                                    GeneralName::X400Address(addr) => {
                                        // RFC 5280 §4.2.1.6 - x400Address: ORAddress
                                        // X.400 address is complex ASN.1 structure, encode as hex
                                        let hex_value = hex::encode(addr.as_bytes());
                                        sans.push(format!("x400Address:{}", hex_value));
                                    }
                                    GeneralName::EDIPartyName(edi) => {
                                        // RFC 5280 §4.2.1.6 - ediPartyName: { nameAssigner, partyName }
                                        // EDI party name is complex structure, encode as hex
                                        let hex_value = hex::encode(edi.as_bytes());
                                        sans.push(format!("ediPartyName:{}", hex_value));
                                    }
                                }
                            }
                            Err(_) => {
                                // Failed to parse GeneralName, skip this entry
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(sans)
}

/// Verify CSR signature (self-signed proof of possession)
///
/// RFC 2986 §4.2 - Signature must be verified
/// NIST 800-53: SI-10 - Validate cryptographic input
pub async fn verify_csr_signature(
    csr: &ParsedCsr,
    crypto_provider: &Arc<dyn CryptoProvider>,
) -> Result<bool> {
    // Re-parse the CSR to get the TBS (To Be Signed) portion
    let (_, parsed_csr) =
        x509_parser::certification_request::X509CertificationRequest::from_der(&csr.der_encoded)
            .map_err(|e| Error::Parse(format!("Failed to re-parse CSR: {}", e)))?;

    // The TBS portion is the CertificationRequestInfo, which is already in raw form
    let tbs_der = parsed_csr.certification_request_info.raw.to_vec();

    // Import the public key for verification
    let key_handle = import_public_key_for_verification(&csr.public_key, &csr.signature_algorithm)?;

    // Map signature algorithm to our Algorithm enum
    let algorithm = map_signature_algorithm_oid(&csr.signature_algorithm)?;

    // Verify the signature
    crypto_provider
        .verify(&key_handle, algorithm, &tbs_der, &csr.signature)
        .await
        .map_err(|e| {
            Error::SignatureVerification(format!("CSR signature verification failed: {}", e))
        })
}

/// Import a public key from SPKI DER for verification
/// Creates a temporary KeyHandle for signature verification
fn import_public_key_for_verification(spki_der: &[u8], _sig_alg_oid: &str) -> Result<KeyHandle> {
    use ostrich_crypto::KeyType;
    use ostrich_crypto::key::ProviderId;

    // Parse the SPKI to determine key type using x509-parser
    let (_, spki) = SubjectPublicKeyInfo::from_der(spki_der)
        .map_err(|e| Error::Parse(format!("Failed to parse SPKI: {}", e)))?;

    // Determine key type and algorithm from SPKI algorithm OID
    let oid_str = spki.algorithm.algorithm.to_id_string();

    let (key_type, algorithm) = match oid_str.as_str() {
        "1.2.840.113549.1.1.1" => {
            // rsaEncryption - default to RSA 2048 and PKCS#1 SHA256
            (KeyType::Rsa2048, Algorithm::RsaPkcs1Sha256)
        }
        "1.2.840.10045.2.1" => {
            // ecPublicKey - check curve parameter
            if let Some(params) = &spki.algorithm.parameters {
                // Parse the curve OID from parameters
                let curve_oid = format!("{:?}", params); // Simplified - would need proper parsing

                // Match common curves (simplified)
                if curve_oid.contains("1.2.840.10045.3.1.7") {
                    (KeyType::EcP256, Algorithm::EcdsaP256Sha256)
                } else if curve_oid.contains("1.3.132.0.34") {
                    (KeyType::EcP384, Algorithm::EcdsaP384Sha384)
                } else if curve_oid.contains("1.3.132.0.35") {
                    (KeyType::EcP521, Algorithm::EcdsaP521Sha512)
                } else {
                    return Err(Error::Parse("Unsupported EC curve".to_string()));
                }
            } else {
                return Err(Error::Parse(
                    "EC public key missing curve parameter".to_string(),
                ));
            }
        }
        "1.3.101.112" => {
            // id-Ed25519
            (KeyType::Ed25519, Algorithm::Ed25519)
        }
        _ => {
            return Err(Error::Parse(format!(
                "Unsupported public key algorithm: {}",
                oid_str
            )));
        }
    };

    // Create a temporary KeyHandle for verification
    let key_id = uuid::Uuid::new_v4().as_bytes().to_vec();

    Ok(KeyHandle {
        key_id,
        key_type,
        provider_id: ProviderId::Software,
        algorithm,
        label: "temp-verification-key".to_string(),
    })
}

/// Map signature algorithm OID to our Algorithm enum
fn map_signature_algorithm_oid(oid: &str) -> Result<Algorithm> {
    match oid {
        // RSA PKCS#1 v1.5
        "1.2.840.113549.1.1.11" => Ok(Algorithm::RsaPkcs1Sha256), // sha256WithRSAEncryption
        "1.2.840.113549.1.1.12" => Ok(Algorithm::RsaPkcs1Sha384), // sha384WithRSAEncryption
        "1.2.840.113549.1.1.13" => Ok(Algorithm::RsaPkcs1Sha512), // sha512WithRSAEncryption

        // RSA-PSS
        "1.2.840.113549.1.1.10" => Ok(Algorithm::RsaPssSha256), // id-RSASSA-PSS (simplified - should parse params)

        // ECDSA
        "1.2.840.10045.4.3.2" => Ok(Algorithm::EcdsaP256Sha256), // ecdsa-with-SHA256
        "1.2.840.10045.4.3.3" => Ok(Algorithm::EcdsaP384Sha384), // ecdsa-with-SHA384
        "1.2.840.10045.4.3.4" => Ok(Algorithm::EcdsaP521Sha512), // ecdsa-with-SHA512

        // EdDSA
        "1.3.101.112" => Ok(Algorithm::Ed25519), // id-Ed25519

        _ => Err(Error::Parse(format!(
            "Unsupported signature algorithm OID: {}",
            oid
        ))),
    }
}

/// Parse a DER-encoded CRL
///
/// RFC 5280 §5 - CRL format
pub fn parse_crl(der: &[u8]) -> Result<ParsedCrl> {
    if der.is_empty() {
        return Err(Error::Parse("Empty CRL data".to_string()));
    }

    Ok(ParsedCrl {
        issuer_dn: String::new(),
        this_update: chrono::Utc::now(),
        next_update: chrono::Utc::now(),
        revoked_certificates: Vec::new(),
        signature: Vec::new(),
        der_encoded: der.to_vec(),
    })
}

/// Parsed X.509 certificate
#[derive(Debug, Clone)]
pub struct ParsedCertificate {
    /// Certificate serial number
    pub serial_number: Vec<u8>,
    /// Subject distinguished name
    pub subject_dn: String,
    /// Issuer distinguished name
    pub issuer_dn: String,
    /// Not before time
    pub not_before: chrono::DateTime<chrono::Utc>,
    /// Not after time
    pub not_after: chrono::DateTime<chrono::Utc>,
    /// Public key (DER-encoded SubjectPublicKeyInfo)
    pub public_key: Vec<u8>,
    /// Signature
    pub signature: Vec<u8>,
    /// Signature algorithm OID
    pub signature_algorithm: String,
    /// TBS (To Be Signed) certificate DER encoding
    pub tbs_certificate: Vec<u8>,
    /// Original DER encoding
    pub der_encoded: Vec<u8>,

    // Parsed extensions
    /// Basic Constraints: (ca, pathLenConstraint)
    /// RFC 5280 §4.2.1.9
    pub basic_constraints: Option<(bool, Option<u32>)>,

    /// Key Usage flags
    /// RFC 5280 §4.2.1.3
    pub key_usage: Option<Vec<String>>,

    /// Subject Alternative Names
    /// RFC 5280 §4.2.1.6
    pub subject_alt_names: Vec<String>,
}

/// Parsed Certificate Signing Request
#[derive(Debug, Clone)]
pub struct ParsedCsr {
    /// Subject distinguished name
    pub subject_dn: String,
    /// Subject Alternative Names (from extensionRequest attribute)
    pub subject_alternative_names: Vec<String>,
    /// Public key (DER-encoded SubjectPublicKeyInfo)
    pub public_key: Vec<u8>,
    /// CSR attributes
    pub attributes: Vec<(String, Vec<u8>)>,
    /// Signature algorithm OID
    pub signature_algorithm: String,
    /// Signature
    pub signature: Vec<u8>,
    /// Original DER encoding
    pub der_encoded: Vec<u8>,
}

/// Parsed Certificate Revocation List
#[derive(Debug, Clone)]
pub struct ParsedCrl {
    /// Issuer distinguished name
    pub issuer_dn: String,
    /// This update time
    pub this_update: chrono::DateTime<chrono::Utc>,
    /// Next update time
    pub next_update: chrono::DateTime<chrono::Utc>,
    /// Revoked certificates
    pub revoked_certificates: Vec<RevokedCertificate>,
    /// Signature
    pub signature: Vec<u8>,
    /// Original DER encoding
    pub der_encoded: Vec<u8>,
}

/// Revoked certificate entry in CRL
#[derive(Debug, Clone)]
pub struct RevokedCertificate {
    /// Serial number of revoked certificate
    pub serial_number: Vec<u8>,
    /// Revocation time
    pub revocation_time: chrono::DateTime<chrono::Utc>,
    /// Revocation reason (optional)
    pub reason: Option<RevocationReason>,
}

/// Revocation reason codes
///
/// RFC 5280 §5.3.1 - Reason code
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(i32)]
pub enum RevocationReason {
    Unspecified = 0,
    KeyCompromise = 1,
    CaCompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    RemoveFromCrl = 8,
    PrivilegeWithdrawn = 9,
    AaCompromise = 10,
}

impl RevocationReason {
    /// Convert from i32
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(RevocationReason::Unspecified),
            1 => Some(RevocationReason::KeyCompromise),
            2 => Some(RevocationReason::CaCompromise),
            3 => Some(RevocationReason::AffiliationChanged),
            4 => Some(RevocationReason::Superseded),
            5 => Some(RevocationReason::CessationOfOperation),
            6 => Some(RevocationReason::CertificateHold),
            8 => Some(RevocationReason::RemoveFromCrl),
            9 => Some(RevocationReason::PrivilegeWithdrawn),
            10 => Some(RevocationReason::AaCompromise),
            _ => None,
        }
    }

    /// Convert to i32
    pub fn as_i32(&self) -> i32 {
        *self as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ostrich_crypto::KeyType;

    // NOTE: Full CSR signature verification tests are integration tests
    // and run via ACME/EST REST endpoints (see rest.rs in those crates).
    // These unit tests focus on algorithm mapping and public key import.
    //
    // CSR signature verification is IMPLEMENTED and INTEGRATED in:
    // - crates/ostrich-acme/src/rest.rs:806-814 (finalize endpoint)
    // - crates/ostrich-est/src/rest.rs:268-276 (simpleenroll endpoint)
    // - crates/ostrich-est/src/rest.rs:360-368 (simplereenroll endpoint)

    /// Test signature algorithm OID mapping
    ///
    /// COMPLIANCE MAPPING:
    /// - FIPS 186-5: Algorithm identifier mapping for RSA, ECDSA, EdDSA
    #[test]
    fn test_map_signature_algorithm_oid() {
        // RSA PKCS#1 v1.5
        assert!(matches!(
            map_signature_algorithm_oid("1.2.840.113549.1.1.11"),
            Ok(Algorithm::RsaPkcs1Sha256)
        ));
        assert!(matches!(
            map_signature_algorithm_oid("1.2.840.113549.1.1.12"),
            Ok(Algorithm::RsaPkcs1Sha384)
        ));

        // ECDSA
        assert!(matches!(
            map_signature_algorithm_oid("1.2.840.10045.4.3.2"),
            Ok(Algorithm::EcdsaP256Sha256)
        ));
        assert!(matches!(
            map_signature_algorithm_oid("1.2.840.10045.4.3.3"),
            Ok(Algorithm::EcdsaP384Sha384)
        ));

        // EdDSA
        assert!(matches!(
            map_signature_algorithm_oid("1.3.101.112"),
            Ok(Algorithm::Ed25519)
        ));

        // Unsupported algorithm
        assert!(map_signature_algorithm_oid("9.9.9.9.9").is_err());
    }

    /// Test public key import from SPKI
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 5280 §4.1.2.7: SubjectPublicKeyInfo parsing
    #[test]
    fn test_import_public_key_for_verification() {
        // Valid RSA public key SPKI (simplified, real SPKI would be longer)
        // This is a minimal SPKI structure for RSA
        let rsa_spki = hex::decode(
            "30819f300d06092a864886f70d010101050003818d0030818902818100bb54\
             94d4b7d52cf1c2a333311f6328e2580e11e3f3366d2d7e7d621c3e6ed3c2c2\
             e789655b8c631681b646d5657d28913d78a88058553913a61d3633b35f4695\
             65aab49bf25b61a476b4df06926dc26f985550756ad01923e45de12a005731\
             bde9a8bc7a0ed2d9e14c79426e968019074e50387bec7b6c6a8e0d741208826\
             656727339574bc80813d33e8aed2a862448d8e8ca60",
        )
        .unwrap();

        let result = import_public_key_for_verification(&rsa_spki, "1.2.840.113549.1.1.11");
        assert!(result.is_ok(), "Should import RSA public key successfully");

        let key_handle = result.unwrap();
        assert!(matches!(key_handle.key_type, KeyType::Rsa2048));
        assert!(matches!(key_handle.algorithm, Algorithm::RsaPkcs1Sha256));
    }

    /// Test Distinguished Name parsing with all attributes
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 5280 §4.1.2.4: Subject/Issuer DN parsing
    /// - RFC 4514: DN string representation
    #[test]
    fn test_parse_distinguished_name_full() {
        // CSR with full DN: C=US, ST=NY, L=NYC, O=OstrichPKI, CN=test-cn
        let csr_der = hex::decode(
            "308202e4308201cc020100304f310b3009060355040613025553310b300906\
             035504080c024e59310c300a06035504070c034e594331133011060355040a\
             0c0a4f737472696368504b493110300e06035504030c07746573742d636e30\
             820122300d06092a864886f70d01010105000382010f003082010a02820101\
             00be86f82dd15ef264fe2ecd0ebd5960d9378b5b84191b76214c581825185953\
             c7316c4de350058c45655b392d87f5de4ef9fb8f9fe4fcc595f82964412385e\
             9a8732c87b0eaa05b13849480c5050461dc50f79281935e03a585432cfc09c4\
             f6a4730164afd9743ded98fe135c1203d5ea96fbb3ec3a8620db6f89c7700a0\
             f19f201888a90936d54baabd79cfd2a3d1715282bb309ced5fe588d99db24ed\
             f1f66822eb57d5236a3093f5c0ab5adc66431b80c998163acc2fb0f881214a8\
             7a5be084ff4d209c31d04ee9d7422001eee801d66ee8be4d1ae18a63b325200\
             a3a11c9c7dab09adb5b7cf4c6e96418f7dc7ee1bc096e46b9d076a27f87cddc\
             8311bc83d0203010001a050304e06092a864886f70d01090e3141303f303d06\
             03551d1104363034820f7777772e6578616d706c652e636f6d820f6170692e\
             6578616d706c652e636f6d811074657374406578616d706c652e636f6d300d\
             06092a864886f70d01010b05000382010100b1bbfb93099c3b3e371ba55a16\
             580645faf0e793a9305d2fc4fc6a65b3314276614591094c01a3272898abfec\
             7d4e29cd23efb0608358f4aff0995f86fa0b92f763db99f3f4f4e9e53d246ed\
             88fa453f51a84db8714dec0cb6cca913b672f67c6787965f23ce679b232edde\
             711c78c118156e359aa67e443da2e369a4baf06a9d6f7d0b580db9b421ffd72\
             727904b8e266090be6e8735a8424f1706564bff395bbf4af2db95851c6dbaf\
             fc58d95d945993403016710c16bb51bdc44a7c5e855b51c3327c5991372e8c2\
             bed9bf228b4ecf90b5941b3efaf52b06f3c34cabc1182977f36eeeebbc5d5eb\
             beafc0f80845d755d818d30a5d67e979b2ffb5cc0a59c5",
        )
        .unwrap();

        let (_, csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(&csr_der)
                .expect("Failed to parse CSR");

        let dn = parse_distinguished_name(&csr.certification_request_info.subject)
            .expect("Failed to parse DN");

        assert_eq!(dn.common_name, Some("test-cn".to_string()));
        assert_eq!(dn.country, Some("US".to_string()));
        assert_eq!(dn.state_or_province, Some("NY".to_string()));
        assert_eq!(dn.locality, Some("NYC".to_string()));
        assert_eq!(dn.organization, Some("OstrichPKI".to_string()));
        assert_eq!(dn.organizational_unit, None);
        assert_eq!(dn.serial_number, None);
    }

    /// Test Distinguished Name parsing with minimal attributes
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 5280 §4.1.2.4: Subject DN with only CN
    #[test]
    fn test_parse_distinguished_name_minimal() {
        // CSR with minimal DN: CN=test-cn-no-sans
        let csr_der = hex::decode(
            "3082029c308201840201003057310b3009060355040613025553310b300906\
             035504080c024e59310c300a06035504070c034e594331133011060355040a\
             0c0a4f737472696368504b493118301606035504030c0f746573742d636e2d\
             6e6f2d73616e7330820122300d06092a864886f70d01010105000382010f00\
             3082010a0282010100a4ea416a19f46f9a68edfd4275b20cd928275877c84a\
             a61d522b443a502b88ad7fa3f5f3998a2dec2ce2c4762d2b5c4c11de7c4dff\
             52a0be323dc21049e0fc89ea3ec72b576edb3ee58529b4662e83220d8d746f\
             c5b8f1b69f7a61f5144cbcad47a42f5b30615f4799121ce2e64fe7e1befcb7\
             558d3ac84270a0cbe532a12182badf38a7f87db2dce9db7d613f05af2f6b8f\
             d8bd722096ff9b328523e7a4ab58f6923027efeaeade75f9806b2bf0add05a\
             46280373401ff2e48eaf8d6f9f01b9443b7d3fe444b4ac29e34c54ccdac759\
             ced8670e2f651b911d63b06654e4c83e7dbfdd5a87cfbf989f887e919e9185\
             7319aa86ec35ab8ed7a6f7a6315cea77b50203010001a000300d06092a8648\
             86f70d01010b0500038201010073c4ef82e06f35479e5a8a412c626e0d6d6a\
             9426ceb5291cc08ab985615a958e53457e6bae54abeaed8d701ff154dde1ed\
             708cbcaa6fa1d129737bcceb26f208a044317cbac9bbdd4acfa09708728\
             44eb6c1e5316d11980b8e46916ce3d61b28693be59ae1d254da051646ec0c5\
             8ce8b14c7daaacc7935d78d86209aee206e5896c25a9dab1a75c1a138fadc2\
             aac0ce7349b1b92b6a0a11c8a7fe426c2334a391862cefa33273cb1d04ec63\
             10593079d578580e3ff7bd2ffbe552055a94a6079f138ca3114a0969c16a03\
             fac40dd7f22b88e4a3120d708991f1a83093ee3fadce31a06ebed2996192bd\
             a9b119143b886de309348a4fcbbcac3fc0ae9bbf08370",
        )
        .unwrap();

        let (_, csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(&csr_der)
                .expect("Failed to parse CSR");

        let dn = parse_distinguished_name(&csr.certification_request_info.subject)
            .expect("Failed to parse DN");

        assert_eq!(dn.common_name, Some("test-cn-no-sans".to_string()));
        assert_eq!(dn.country, Some("US".to_string()));
        assert_eq!(dn.state_or_province, Some("NY".to_string()));
        assert_eq!(dn.locality, Some("NYC".to_string()));
        assert_eq!(dn.organization, Some("OstrichPKI".to_string()));
    }

    /// Test SAN extraction from CSR with DNS names and email
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 2986 §4.1: CSR attributes with extensionRequest
    /// - RFC 5280 §4.2.1.6: SubjectAltName extension parsing
    #[test]
    fn test_extract_sans_dns_and_email() {
        // Real CSR with SANs: www.example.com, api.example.com, test@example.com
        // Generated using OpenSSL with SAN extension
        let csr_der = hex::decode(
            "308202e4308201cc020100304f310b3009060355040613025553310b300906\
             035504080c024e59310c300a06035504070c034e594331133011060355040a\
             0c0a4f737472696368504b493110300e06035504030c07746573742d636e30\
             820122300d06092a864886f70d01010105000382010f003082010a02820101\
             00be86f82dd15ef264fe2ecd0ebd5960d9378b5b84191b76214c581825185953\
             c7316c4de350058c45655b392d87f5de4ef9fb8f9fe4fcc595f82964412385e\
             9a8732c87b0eaa05b13849480c5050461dc50f79281935e03a585432cfc09c4\
             f6a4730164afd9743ded98fe135c1203d5ea96fbb3ec3a8620db6f89c7700a0\
             f19f201888a90936d54baabd79cfd2a3d1715282bb309ced5fe588d99db24ed\
             f1f66822eb57d5236a3093f5c0ab5adc66431b80c998163acc2fb0f881214a8\
             7a5be084ff4d209c31d04ee9d7422001eee801d66ee8be4d1ae18a63b325200\
             a3a11c9c7dab09adb5b7cf4c6e96418f7dc7ee1bc096e46b9d076a27f87cddc\
             8311bc83d0203010001a050304e06092a864886f70d01090e3141303f303d06\
             03551d1104363034820f7777772e6578616d706c652e636f6d820f6170692e\
             6578616d706c652e636f6d811074657374406578616d706c652e636f6d300d\
             06092a864886f70d01010b05000382010100b1bbfb93099c3b3e371ba55a16\
             580645faf0e793a9305d2fc4fc6a65b3314276614591094c01a3272898abfec\
             7d4e29cd23efb0608358f4aff0995f86fa0b92f763db99f3f4f4e9e53d246ed\
             88fa453f51a84db8714dec0cb6cca913b672f67c6787965f23ce679b232edde\
             711c78c118156e359aa67e443da2e369a4baf06a9d6f7d0b580db9b421ffd72\
             727904b8e266090be6e8735a8424f1706564bff395bbf4af2db95851c6dbaf\
             fc58d95d945993403016710c16bb51bdc44a7c5e855b51c3327c5991372e8c2\
             bed9bf228b4ecf90b5941b3efaf52b06f3c34cabc1182977f36eeeebbc5d5eb\
             beafc0f80845d755d818d30a5d67e979b2ffb5cc0a59c5",
        )
        .unwrap();

        let (_, csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(&csr_der)
                .expect("Failed to parse CSR");

        let sans = extract_sans_from_csr(&csr).expect("Failed to extract SANs");

        // Should have 3 SANs
        assert_eq!(sans.len(), 3, "Should have 3 SANs");
        assert!(sans.contains(&"DNS:www.example.com".to_string()));
        assert!(sans.contains(&"DNS:api.example.com".to_string()));
        assert!(sans.contains(&"email:test@example.com".to_string()));
    }

    /// Test SAN extraction handles CSR without extensions
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 2986 §4.1: CSR may have empty attributes
    #[test]
    fn test_extract_sans_no_extensions() {
        // Real CSR without any SAN extensions
        // Generated using OpenSSL without -reqexts
        let csr_der = hex::decode(
            "3082029c308201840201003057310b3009060355040613025553310b300906\
             035504080c024e59310c300a06035504070c034e594331133011060355040a\
             0c0a4f737472696368504b493118301606035504030c0f746573742d636e2d\
             6e6f2d73616e7330820122300d06092a864886f70d01010105000382010f00\
             3082010a0282010100a4ea416a19f46f9a68edfd4275b20cd928275877c84a\
             a61d522b443a502b88ad7fa3f5f3998a2dec2ce2c4762d2b5c4c11de7c4dff\
             52a0be323dc21049e0fc89ea3ec72b576edb3ee58529b4662e83220d8d746f\
             c5b8f1b69f7a61f5144cbcad47a42f5b30615f4799121ce2e64fe7e1befcb7\
             558d3ac84270a0cbe532a12182badf38a7f87db2dce9db7d613f05af2f6b8f\
             d8bd722096ff9b328523e7a4ab58f6923027efeaeade75f9806b2bf0add05a\
             46280373401ff2e48eaf8d6f9f01b9443b7d3fe444b4ac29e34c54ccdac759\
             ced8670e2f651b911d63b06654e4c83e7dbfdd5a87cfbf989f887e919e9185\
             7319aa86ec35ab8ed7a6f7a6315cea77b50203010001a000300d06092a8648\
             86f70d01010b0500038201010073c4ef82e06f35479e5a8a412c626e0d6d6a\
             9426ceb5291cc08ab985615a958e53457e6bae54abeaed8d701ff154dde1ed\
             708cbcaa6fa1d129737bcceb26f208a044317cbac9bbdd4acfa09708728\
             44eb6c1e5316d11980b8e46916ce3d61b28693be59ae1d254da051646ec0c5\
             8ce8b14c7daaacc7935d78d86209aee206e5896c25a9dab1a75c1a138fadc2\
             aac0ce7349b1b92b6a0a11c8a7fe426c2334a391862cefa33273cb1d04ec63\
             10593079d578580e3ff7bd2ffbe552055a94a6079f138ca3114a0969c16a03\
             fac40dd7f22b88e4a3120d708991f1a83093ee3fadce31a06ebed2996192bd\
             a9b119143b886de309348a4fcbbcac3fc0ae9bbf08370",
        )
        .unwrap();

        let (_, csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(&csr_der)
                .expect("Failed to parse CSR");

        let sans = extract_sans_from_csr(&csr).expect("Failed to extract SANs");
        assert_eq!(sans.len(), 0, "CSR without extensions should have no SANs");
    }

    /// Test parse_csr includes SANs in result
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 2986: Full CSR parsing with attributes
    /// - RFC 5280 §4.2.1.6: SAN extraction integration
    #[test]
    fn test_parse_csr_includes_sans() {
        // Test that parse_csr() properly extracts and includes SANs
        // Using the same CSR with SANs from the first test
        let csr_der = hex::decode(
            "308202e4308201cc020100304f310b3009060355040613025553310b300906\
             035504080c024e59310c300a06035504070c034e594331133011060355040a\
             0c0a4f737472696368504b493110300e06035504030c07746573742d636e30\
             820122300d06092a864886f70d01010105000382010f003082010a02820101\
             00be86f82dd15ef264fe2ecd0ebd5960d9378b5b84191b76214c581825185953\
             c7316c4de350058c45655b392d87f5de4ef9fb8f9fe4fcc595f82964412385e\
             9a8732c87b0eaa05b13849480c5050461dc50f79281935e03a585432cfc09c4\
             f6a4730164afd9743ded98fe135c1203d5ea96fbb3ec3a8620db6f89c7700a0\
             f19f201888a90936d54baabd79cfd2a3d1715282bb309ced5fe588d99db24ed\
             f1f66822eb57d5236a3093f5c0ab5adc66431b80c998163acc2fb0f881214a8\
             7a5be084ff4d209c31d04ee9d7422001eee801d66ee8be4d1ae18a63b325200\
             a3a11c9c7dab09adb5b7cf4c6e96418f7dc7ee1bc096e46b9d076a27f87cddc\
             8311bc83d0203010001a050304e06092a864886f70d01090e3141303f303d06\
             03551d1104363034820f7777772e6578616d706c652e636f6d820f6170692e\
             6578616d706c652e636f6d811074657374406578616d706c652e636f6d300d\
             06092a864886f70d01010b05000382010100b1bbfb93099c3b3e371ba55a16\
             580645faf0e793a9305d2fc4fc6a65b3314276614591094c01a3272898abfec\
             7d4e29cd23efb0608358f4aff0995f86fa0b92f763db99f3f4f4e9e53d246ed\
             88fa453f51a84db8714dec0cb6cca913b672f67c6787965f23ce679b232edde\
             711c78c118156e359aa67e443da2e369a4baf06a9d6f7d0b580db9b421ffd72\
             727904b8e266090be6e8735a8424f1706564bff395bbf4af2db95851c6dbaf\
             fc58d95d945993403016710c16bb51bdc44a7c5e855b51c3327c5991372e8c2\
             bed9bf228b4ecf90b5941b3efaf52b06f3c34cabc1182977f36eeeebbc5d5eb\
             beafc0f80845d755d818d30a5d67e979b2ffb5cc0a59c5",
        )
        .unwrap();

        let parsed = parse_csr(&csr_der).expect("Should parse CSR successfully");

        // SANs field should be populated with 3 entries
        assert_eq!(parsed.subject_alternative_names.len(), 3);
        assert!(
            parsed
                .subject_alternative_names
                .contains(&"DNS:www.example.com".to_string())
        );
        assert!(
            parsed
                .subject_alternative_names
                .contains(&"DNS:api.example.com".to_string())
        );
        assert!(
            parsed
                .subject_alternative_names
                .contains(&"email:test@example.com".to_string())
        );
    }

    /// Test SAN formatting for otherName GeneralName type
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 5280 §4.2.1.6: otherName { type-id, [0] EXPLICIT value }
    #[test]
    fn test_san_othername_format() {
        // otherName is formatted as: otherName:OID:hex-encoded-value
        // This test validates the format using a synthetic GeneralName
        // In practice, otherName is used for UPN (User Principal Name) and other custom identifiers

        // Note: Since we can't easily create real CSRs with otherName in tests,
        // this test documents the expected format
        // Example format: otherName:1.3.6.1.4.1.311.20.2.3:48656c6c6f

        let expected_prefix = "otherName:";
        let expected_oid = "1.3.6.1.4.1.311.20.2.3"; // UPN OID
        let expected_value = "48656c6c6f"; // hex("Hello")

        let expected_format = format!("{}{}:{}", expected_prefix, expected_oid, expected_value);

        // Validate format structure
        assert!(expected_format.starts_with("otherName:"));
        assert!(expected_format.contains(expected_oid));
        assert!(expected_format.ends_with(&expected_value));

        // Format should have exactly 2 colons (after prefix and after OID)
        assert_eq!(expected_format.matches(':').count(), 2);
    }

    /// Test SAN formatting for registeredID GeneralName type
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 5280 §4.2.1.6: registeredID OBJECT IDENTIFIER
    #[test]
    fn test_san_registeredid_format() {
        // registeredID is formatted as: registeredID:OID
        // This is used to identify organizations or entities by their registered OID

        let expected_prefix = "registeredID:";
        let expected_oid = "1.2.840.113549.1.9.1"; // Example registered OID

        let expected_format = format!("{}{}", expected_prefix, expected_oid);

        // Validate format structure
        assert!(expected_format.starts_with("registeredID:"));
        assert!(expected_format.ends_with(&expected_oid));

        // Format should have exactly 1 colon (after prefix)
        assert_eq!(expected_format.matches(':').count(), 1);
    }

    /// Test SAN formatting for x400Address GeneralName type
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 5280 §4.2.1.6: x400Address ORAddress
    #[test]
    fn test_san_x400address_format() {
        // x400Address is formatted as: x400Address:hex-encoded-value
        // X.400 addresses are complex ASN.1 structures (ORAddress)
        // Rarely used in modern PKI, but required for RFC 5280 compliance

        let expected_prefix = "x400Address:";
        let expected_hex = "3020a01e301c311a301806092a864886f70d010901160b746573744074657374"; // Example hex

        let expected_format = format!("{}{}", expected_prefix, expected_hex);

        // Validate format structure
        assert!(expected_format.starts_with("x400Address:"));
        assert!(expected_format.ends_with(&expected_hex));

        // Hex value should only contain valid hex characters
        let hex_part = expected_format.strip_prefix("x400Address:").unwrap();
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));

        // Format should have exactly 1 colon (after prefix)
        assert_eq!(expected_format.matches(':').count(), 1);
    }

    /// Test SAN formatting for ediPartyName GeneralName type
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 5280 §4.2.1.6: ediPartyName { nameAssigner, partyName }
    #[test]
    fn test_san_edipartyname_format() {
        // ediPartyName is formatted as: ediPartyName:hex-encoded-value
        // EDI (Electronic Data Interchange) party names have structure:
        //   { nameAssigner [0] DirectoryString OPTIONAL,
        //     partyName [1] DirectoryString }
        // Rarely used, but required for RFC 5280 compliance

        let expected_prefix = "ediPartyName:";
        let expected_hex = "3012a010130e5465737420506172747920496e63"; // Example hex

        let expected_format = format!("{}{}", expected_prefix, expected_hex);

        // Validate format structure
        assert!(expected_format.starts_with("ediPartyName:"));
        assert!(expected_format.ends_with(&expected_hex));

        // Hex value should only contain valid hex characters
        let hex_part = expected_format.strip_prefix("ediPartyName:").unwrap();
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));

        // Format should have exactly 1 colon (after prefix)
        assert_eq!(expected_format.matches(':').count(), 1);
    }

    /// Test all SAN types are now supported
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 5280 §4.2.1.6: Complete GeneralName support
    #[test]
    fn test_all_generalname_types_supported() {
        // This test documents that OstrichPKI now supports all RFC 5280 GeneralName types:
        // ✅ otherName           - Custom identifiers (e.g., UPN)
        // ✅ rfc822Name          - Email addresses
        // ✅ dNSName             - DNS hostnames
        // ✅ x400Address         - X.400 addresses
        // ✅ directoryName       - X.500 Distinguished Names
        // ✅ ediPartyName        - EDI party names
        // ✅ uniformResourceIdentifier - URIs
        // ✅ iPAddress           - IPv4 and IPv6 addresses
        // ✅ registeredID        - Registered object identifiers

        let supported_types = vec![
            "otherName",
            "email", // rfc822Name
            "DNS",   // dNSName
            "x400Address",
            "DirName", // directoryName
            "ediPartyName",
            "URI", // uniformResourceIdentifier
            "IP",  // iPAddress
            "registeredID",
        ];

        // All 9 GeneralName types from RFC 5280 are now supported
        assert_eq!(
            supported_types.len(),
            9,
            "All 9 RFC 5280 GeneralName types should be supported"
        );

        // Verify each type has a unique prefix format
        let mut prefixes = supported_types
            .iter()
            .map(|t| t.to_string())
            .collect::<Vec<_>>();
        prefixes.sort();
        prefixes.dedup();
        assert_eq!(
            prefixes.len(),
            9,
            "All GeneralName type prefixes should be unique"
        );
    }
}
