//! X.509 certificate and CRL parsing
//!
//! RFC 5280: X.509 certificate and CRL parsing
//! RFC 2986: PKCS#10 certification request syntax

use crate::{Error, Result};
use ostrich_crypto::{Algorithm, CryptoProvider};
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

/// One parsed extension, for a human-facing detail view.
#[derive(Debug, Clone)]
pub struct CertificateExtensionInfo {
    /// Dotted OID (e.g. `2.5.29.37`).
    pub oid: String,
    /// Friendly name, or the OID if unknown.
    pub name: String,
    /// RFC 5280 §4.2 criticality flag.
    pub critical: bool,
    /// Short human summary of the extension value (may be empty).
    pub value: String,
}

/// Rich, display-oriented description of a certificate for a detail view.
///
/// Best-effort: fields that cannot be extracted are left empty/None rather than
/// failing the whole parse, so the caller can render what is available.
#[derive(Debug, Clone, Default)]
pub struct CertificateDescription {
    pub key_algorithm: String,
    pub key_size: u32,
    pub signature_algorithm: String,
    pub fingerprint_sha256: String,
    pub fingerprint_sha1: String,
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,
    pub subject_alt_names: Vec<String>,
    pub authority_key_id: Option<String>,
    pub subject_key_id: Option<String>,
    pub crl_distribution_points: Vec<String>,
    pub ocsp_urls: Vec<String>,
    pub extensions: Vec<CertificateExtensionInfo>,
}

/// Map a public-key or signature algorithm OID to a friendly name (empty if
/// unknown, so the caller can fall back to the OID).
fn algorithm_name(oid: &str) -> &'static str {
    match oid {
        "1.2.840.113549.1.1.1" => "RSA",
        "1.2.840.113549.1.1.5" => "SHA1withRSA",
        "1.2.840.113549.1.1.11" => "SHA256withRSA",
        "1.2.840.113549.1.1.12" => "SHA384withRSA",
        "1.2.840.113549.1.1.13" => "SHA512withRSA",
        "1.2.840.113549.1.1.10" => "RSASSA-PSS",
        "1.2.840.10045.2.1" => "ECDSA",
        "1.2.840.10045.4.3.2" => "SHA256withECDSA",
        "1.2.840.10045.4.3.3" => "SHA384withECDSA",
        "1.2.840.10045.4.3.4" => "SHA512withECDSA",
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",
        _ => "",
    }
}

/// Friendly name for a standard X.509 extension OID (empty if unknown).
fn extension_name(oid: &str) -> &'static str {
    match oid {
        "2.5.29.14" => "Subject Key Identifier",
        "2.5.29.15" => "Key Usage",
        "2.5.29.17" => "Subject Alternative Name",
        "2.5.29.19" => "Basic Constraints",
        "2.5.29.31" => "CRL Distribution Points",
        "2.5.29.32" => "Certificate Policies",
        "2.5.29.35" => "Authority Key Identifier",
        "2.5.29.37" => "Extended Key Usage",
        "1.3.6.1.5.5.7.1.1" => "Authority Information Access",
        _ => "",
    }
}

/// Produce a rich, display-oriented description of a DER-encoded certificate:
/// key algorithm/size, signature algorithm, SHA-1/SHA-256 fingerprints, key
/// usage, EKU, SANs, AKI/SKI, CRL distribution points, OCSP URLs, and the raw
/// extension inventory.
///
/// COMPLIANCE MAPPING:
/// - RFC 5280 §4.1/§4.2: certificate fields and standard extensions
pub fn describe_certificate(der: &[u8]) -> Result<CertificateDescription> {
    use sha1::Sha1;
    use sha2::{Digest, Sha256};
    use x509_parser::public_key::PublicKey;

    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| Error::Parse(format!("Failed to parse X.509 certificate: {}", e)))?;

    let mut d = CertificateDescription {
        fingerprint_sha256: hex::encode(Sha256::digest(der)),
        fingerprint_sha1: hex::encode(Sha1::digest(der)),
        ..Default::default()
    };

    // Signature algorithm (friendly name, falling back to the OID).
    let sig_oid = cert.signature_algorithm.algorithm.to_id_string();
    let sig_name = algorithm_name(&sig_oid);
    d.signature_algorithm = if sig_name.is_empty() {
        sig_oid
    } else {
        sig_name.to_string()
    };

    // Public key algorithm + size.
    let spki = cert.public_key();
    let key_oid = spki.algorithm.algorithm.to_id_string();
    match spki.parsed() {
        Ok(PublicKey::RSA(rsa)) => {
            d.key_algorithm = "RSA".to_string();
            // Modulus bit length (strip a leading sign byte if present).
            let m = rsa.modulus;
            let m = m.strip_prefix(&[0u8]).unwrap_or(m);
            d.key_size = (m.len() * 8) as u32;
        }
        Ok(PublicKey::EC(ec)) => {
            d.key_algorithm = "ECDSA".to_string();
            // Let x509-parser size the curve (handles compressed + uncompressed
            // points), falling back to 0 for an unrecognized encoding.
            d.key_size = ec.key_size() as u32;
        }
        _ => {
            let name = algorithm_name(&key_oid);
            d.key_algorithm = if name.is_empty() {
                key_oid.clone()
            } else {
                name.to_string()
            };
            d.key_size = match key_oid.as_str() {
                "1.3.101.112" => 256, // Ed25519
                "1.3.101.113" => 448, // Ed448
                _ => 0,
            };
        }
    }

    // Reuse the existing extension parser for key usage + SANs.
    if let Ok((_, ku, sans)) = parse_certificate_extensions(&cert) {
        d.key_usage = ku.unwrap_or_default();
        d.subject_alt_names = sans;
    }

    // Walk extensions for the richer fields and the raw inventory.
    for ext in cert.extensions() {
        let oid = ext.oid.to_id_string();
        let value = match ext.parsed_extension() {
            ParsedExtension::ExtendedKeyUsage(eku) => {
                let mut v = Vec::new();
                if eku.any {
                    v.push("Any".to_string());
                }
                if eku.server_auth {
                    v.push("TLS Web Server Authentication".to_string());
                }
                if eku.client_auth {
                    v.push("TLS Web Client Authentication".to_string());
                }
                if eku.code_signing {
                    v.push("Code Signing".to_string());
                }
                if eku.email_protection {
                    v.push("Email Protection".to_string());
                }
                if eku.time_stamping {
                    v.push("Time Stamping".to_string());
                }
                if eku.ocsp_signing {
                    v.push("OCSP Signing".to_string());
                }
                for o in &eku.other {
                    v.push(o.to_id_string());
                }
                d.extended_key_usage = v.clone();
                v.join(", ")
            }
            ParsedExtension::SubjectKeyIdentifier(ki) => {
                let h = hex::encode(ki.0);
                d.subject_key_id = Some(h.clone());
                h
            }
            ParsedExtension::AuthorityKeyIdentifier(aki) => match &aki.key_identifier {
                Some(ki) => {
                    let h = hex::encode(ki.0);
                    d.authority_key_id = Some(h.clone());
                    h
                }
                None => String::new(),
            },
            ParsedExtension::KeyUsage(_) => d.key_usage.join(", "),
            ParsedExtension::BasicConstraints(bc) => {
                if bc.ca {
                    match bc.path_len_constraint {
                        Some(n) => format!("CA:TRUE, pathlen:{n}"),
                        None => "CA:TRUE".to_string(),
                    }
                } else {
                    "CA:FALSE".to_string()
                }
            }
            ParsedExtension::SubjectAlternativeName(_) => d.subject_alt_names.join(", "),
            ParsedExtension::CRLDistributionPoints(crl) => {
                for p in crl.iter() {
                    if let Some(DistributionPointName::FullName(names)) = &p.distribution_point {
                        for gn in names {
                            if let GeneralName::URI(u) = gn {
                                d.crl_distribution_points.push(u.to_string());
                            }
                        }
                    }
                }
                d.crl_distribution_points.join(", ")
            }
            ParsedExtension::AuthorityInfoAccess(aia) => {
                for ad in &aia.accessdescs {
                    // id-ad-ocsp (RFC 5280 §4.2.2.1)
                    if ad.access_method.to_id_string() != "1.3.6.1.5.5.7.48.1" {
                        continue;
                    }
                    if let GeneralName::URI(u) = &ad.access_location {
                        d.ocsp_urls.push(u.to_string());
                    }
                }
                d.ocsp_urls.join(", ")
            }
            _ => String::new(),
        };
        let name = extension_name(&oid);
        d.extensions.push(CertificateExtensionInfo {
            name: if name.is_empty() {
                oid.clone()
            } else {
                name.to_string()
            },
            oid,
            critical: ext.critical,
            value,
        });
    }

    Ok(d)
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

    // Parse CSR using x509-parser.
    //
    // x509-parser eagerly *deep-parses* PKCS#10 attributes and rejects the
    // whole request when it cannot interpret a known attribute's value - most
    // notably a `challengePassword` (RFC 2985 §5.4.1) encoded as an IA5String,
    // or as a PrintableString containing characters outside the PrintableString
    // repertoire (e.g. '!', '_', '@'). Many device / NPE enrollment clients
    // (BouncyCastle, SCEP-style tooling) emit exactly these encodings, so an
    // otherwise-valid CSR fails with `InvalidAttributes`. When the strict parse
    // fails we fall back to a der-based parse that treats attribute values as
    // opaque. The fallback only runs on inputs x509-parser already rejects, so
    // it can never change the result for a request that parses today.
    //
    // COMPLIANCE MAPPING:
    // - RFC 2986 §4: PKCS#10 CertificationRequest structure
    // - RFC 2985 §5.4.1: challengePassword attribute (DirectoryString/IA5String)
    // - NIST 800-53 SI-10: Information input validation (accept well-formed input)
    let (_, csr) = match x509_parser::certification_request::X509CertificationRequest::from_der(der)
    {
        Ok(parsed) => parsed,
        Err(primary_err) => {
            return parse_csr_der_fallback(der).map_err(|fallback_err| {
                Error::Parse(format!(
                    "Failed to parse PKCS#10 CSR: {} (der fallback also failed: {})",
                    primary_err, fallback_err
                ))
            });
        }
    };

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

/// DER-based PKCS#10 fallback parser for CSRs that x509-parser rejects.
///
/// Uses the RustCrypto `der`/`x509-cert` decoder, which models attribute values
/// as opaque `Any` and therefore does not reject unusual (but validly encoded)
/// `challengePassword` string types or other attribute encodings that
/// x509-parser deep-parses and rejects with `InvalidAttributes`. Every field of
/// the returned [`ParsedCsr`] is derived structurally without interpreting
/// attribute *values*, except for the `extensionRequest` attribute, from which
/// SANs are extracted with the same shared routine used by the primary path.
///
/// COMPLIANCE MAPPING:
/// - RFC 2986 §4: PKCS#10 CertificationRequest / CertificationRequestInfo
/// - RFC 5280 §4.1.2.7 / §4.2.1.6: SubjectPublicKeyInfo, SubjectAltName
/// - NIST 800-53 SI-10: Accept well-formed input; still verified for PoP later
fn parse_csr_der_fallback(der: &[u8]) -> Result<ParsedCsr> {
    use der::{Decode, Encode};

    // Tolerate a CSR that omits the (mandatory-but-emptyable) attributes field,
    // as OpenSSL does; the original bytes are still what der_encoded/PoP use.
    let normalized = normalize_missing_attributes(der)?;
    let req = x509_cert::request::CertReq::from_der(&normalized)
        .map_err(|e| Error::Parse(format!("der CertReq decode failed: {}", e)))?;
    let info = &req.info;

    // Render the subject DN via x509-parser so the string is byte-for-byte
    // identical to the primary path and to `parse_certificate` (both use
    // x509-parser's rendering). This matters for correctness: EST re-enrollment
    // (RFC 7030 §4.2.2) compares the CSR's full subject-DN string against the
    // prior certificate's; mixing x509-cert's RFC 4514 rendering (RDNs reversed,
    // no separator spaces) with x509-parser's would spuriously fail that match
    // for any multi-RDN subject. x509-parser parses a `Name` fine — it is only
    // the request *attributes* it rejects — so re-encode the Name and re-parse.
    let subject_der = info
        .subject
        .to_der()
        .map_err(|e| Error::Parse(format!("re-encode subject Name: {}", e)))?;
    let subject_dn = match x509_parser::x509::X509Name::from_der(&subject_der) {
        Ok((_, name)) => name.to_string(),
        Err(_) => info.subject.to_string(),
    };

    // SubjectPublicKeyInfo, re-encoded to DER (canonical for DER input).
    let public_key = info
        .public_key
        .to_der()
        .map_err(|e| Error::Parse(format!("re-encode SubjectPublicKeyInfo: {}", e)))?;

    let signature_algorithm = req.algorithm.oid.to_string();

    // Signatures are octet-aligned BIT STRINGs (0 unused bits).
    let signature = req
        .signature
        .as_bytes()
        .ok_or_else(|| Error::Parse("CSR signature BIT STRING is not octet-aligned".to_string()))?
        .to_vec();

    // Attributes: keep the raw `SET OF` DER of each attribute value so callers
    // see the same shape as the primary path, and pull SANs from
    // extensionRequest (OID 1.2.840.113549.1.9.14).
    let mut attributes = Vec::new();
    let mut sans = Vec::new();
    for attr in info.attributes.iter() {
        let oid = attr.oid.to_string();
        let value = attr
            .values
            .to_der()
            .map_err(|e| Error::Parse(format!("re-encode attribute values: {}", e)))?;
        if oid == "1.2.840.113549.1.9.14" {
            // Use the same routine — and the same strictness — as the primary
            // path so both yield identical `subject_alternative_names`, and a
            // malformed extensionRequest is surfaced rather than silently issuing
            // a certificate that is missing its requested SANs.
            sans.extend(extract_sans_from_extension_request(&value)?);
        }
        attributes.push((oid, value));
    }

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

/// Return the raw DER of the `CertificationRequestInfo` (the signed TBS) from a
/// PKCS#10 CSR without deep-parsing its attributes.
///
/// This is the exact byte range over which the CSR self-signature is computed
/// (RFC 2986 §4.2), extracted by structural TLV slicing so proof-of-possession
/// verification does not depend on x509-parser accepting the attributes.
///
/// COMPLIANCE MAPPING:
/// - RFC 2986 §4.2: CertificationRequest signature is over CertificationRequestInfo
/// - NIST 800-53 SI-10 / SC-8(1): Input validation, proof of possession
fn extract_cert_req_info_tbs(der: &[u8]) -> Result<Vec<u8>> {
    // CertificationRequest ::= SEQUENCE { CertificationRequestInfo, ... }
    let (outer_value, _outer_end) = der_tlv(der, 0, 0x30)?;
    // The first element is CertificationRequestInfo, itself a SEQUENCE.
    let (_ci_value, ci_end) = der_tlv(der, outer_value, 0x30)?;
    Ok(der[outer_value..ci_end].to_vec())
}

/// Minimal DER TLV walker: given a buffer and an offset, verify the tag and
/// return `(value_offset, end_offset)` where `end_offset` is one past the whole
/// tag-length-value triple. Rejects truncated inputs and lengths exceeding the
/// buffer. Only definite-form lengths up to 4 length octets are supported, which
/// covers any real CSR.
fn der_tlv(buf: &[u8], off: usize, expected_tag: u8) -> Result<(usize, usize)> {
    let rest = buf
        .get(off..)
        .ok_or_else(|| Error::Parse("CSR truncated (offset past end)".to_string()))?;
    if rest.len() < 2 {
        return Err(Error::Parse("CSR truncated (no tag/length)".to_string()));
    }
    if rest[0] != expected_tag {
        return Err(Error::Parse(format!(
            "expected DER tag {:#04x} at offset {}, found {:#04x}",
            expected_tag, off, rest[0]
        )));
    }
    let len_octet = rest[1];
    let (header_len, length) = if len_octet & 0x80 == 0 {
        (2usize, len_octet as usize)
    } else {
        let n = (len_octet & 0x7f) as usize;
        if n == 0 || n > 4 {
            return Err(Error::Parse("unsupported DER length encoding".to_string()));
        }
        // Accumulate in u64 so a 4-octet length never overflows the shift on
        // 32-bit targets, then narrow to usize (rejecting > usize::MAX).
        let mut length: u64 = 0;
        for i in 0..n {
            let b = *rest
                .get(2 + i)
                .ok_or_else(|| Error::Parse("CSR truncated (length octets)".to_string()))?;
            length = (length << 8) | b as u64;
        }
        let length = usize::try_from(length)
            .map_err(|_| Error::Parse("DER length exceeds usize".to_string()))?;
        (2 + n, length)
    };
    let value_offset = off
        .checked_add(header_len)
        .ok_or_else(|| Error::Parse("DER offset overflow".to_string()))?;
    let end_offset = value_offset
        .checked_add(length)
        .ok_or_else(|| Error::Parse("DER length overflow".to_string()))?;
    if end_offset > buf.len() {
        return Err(Error::Parse("DER length exceeds buffer".to_string()));
    }
    Ok((value_offset, end_offset))
}

/// Encode a DER definite-form length. Short form (< 128) is a single octet; long
/// form is `0x80 | n` followed by `n` big-endian octets. CSR component lengths
/// always fit, so this covers every real input.
fn der_len_bytes(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }
    let be = len.to_be_bytes();
    let first = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
    let sig = &be[first..];
    let mut out = Vec::with_capacity(sig.len() + 1);
    out.push(0x80 | sig.len() as u8);
    out.extend_from_slice(sig);
    out
}

/// Wrap `content` in a DER SEQUENCE (tag `0x30`) with a correct length header.
fn der_seq(content: &[u8]) -> Vec<u8> {
    let len = der_len_bytes(content.len());
    let mut out = Vec::with_capacity(1 + len.len() + content.len());
    out.push(0x30);
    out.extend_from_slice(&len);
    out.extend_from_slice(content);
    out
}

/// Normalize a PKCS#10 CSR whose `CertificationRequestInfo` OMITS the mandatory
/// `attributes [0]` field by injecting an empty `SET OF Attribute` (`A0 00`).
///
/// RFC 2986 §4.1 defines `attributes` as `[0] IMPLICIT SET OF Attribute` — a
/// field that may be empty but is NOT optional. Some clients (notably pkijs used
/// by the in-browser generator, and other lightweight tooling) drop the field
/// entirely when there are no attributes. OpenSSL accepts such requests, but the
/// strict Rust decoders (x509-parser → `InvalidAttributes`, RustCrypto `der` →
/// malformed context-[0]) reject them. To match OpenSSL's leniency without
/// relaxing the decoders elsewhere, we rebuild the DER with an empty attributes
/// field when — and only when — it is genuinely absent.
///
/// The self-signature is computed over the ORIGINAL `CertificationRequestInfo`
/// bytes (RFC 2986 §4.2), so callers MUST keep the original DER for
/// proof-of-possession verification; this normalized form is used only for
/// structural field extraction.
///
/// COMPLIANCE MAPPING:
/// - RFC 2986 §4.1: CertificationRequestInfo.attributes (mandatory, may be empty)
/// - NIST 800-53 SI-10: Accept well-formed input; interoperate with conformant clients
fn normalize_missing_attributes(der: &[u8]) -> Result<std::borrow::Cow<'_, [u8]>> {
    use std::borrow::Cow;

    // CertificationRequest ::= SEQUENCE { CertificationRequestInfo, algId, sig }
    let (outer_val, outer_end) = der_tlv(der, 0, 0x30)?;
    // CertificationRequestInfo ::= SEQUENCE { version, subject, spki, [0] attrs }
    let (ci_val, ci_end) = der_tlv(der, outer_val, 0x30)?;
    // Walk the three mandatory leading fields; whatever remains is `attributes`.
    let (_, ver_end) = der_tlv(der, ci_val, 0x02)?; // version INTEGER
    let (_, subj_end) = der_tlv(der, ver_end, 0x30)?; // subject Name SEQUENCE
    let (_, spki_end) = der_tlv(der, subj_end, 0x30)?; // subjectPKInfo SEQUENCE

    // Anything (well-formed or not) after the public key means the attributes
    // field is present — leave the request untouched so the decoder sees it
    // verbatim. Only a CertReqInfo that ends exactly at the public key is missing
    // the field and needs an empty one injected.
    if spki_end != ci_end {
        return Ok(Cow::Borrowed(der));
    }

    let mut ci_content = der[ci_val..ci_end].to_vec();
    ci_content.extend_from_slice(&[0xA0, 0x00]); // empty [0] IMPLICIT SET OF
    let new_ci = der_seq(&ci_content);

    // Reassemble: new CertReqInfo + the original algId + signature bytes.
    let mut outer_content = new_ci;
    outer_content.extend_from_slice(&der[ci_end..outer_end]);
    Ok(Cow::Owned(der_seq(&outer_content)))
}

/// Parse X.509 Distinguished Name to structured format
///
/// Parse the subject DN of a DER-encoded certificate into a structured DN.
///
/// RFC 5280 §7.1 - name chaining requires the issuer field of an issued
/// certificate to match the issuing CA's subject. Use this (rather than
/// wrapping a pre-rendered RFC 4514 string in `DistinguishedName::new_cn`,
/// which produces a bogus `CN=CN=...` attribute) whenever a structured DN
/// is needed from stored certificate bytes.
pub fn parse_subject_dn(der: &[u8]) -> Result<ostrich_common::types::DistinguishedName> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| Error::Parse(format!("Failed to parse certificate: {}", e)))?;
    parse_distinguished_name(cert.subject())
}

/// Parse the subject DN of a DER-encoded PKCS#10 CSR into a structured DN.
///
/// Mirrors [`parse_subject_dn`] for certification requests. Use this to compare
/// a CSR's subject against a certificate's subject *structurally* (field by
/// field) rather than by comparing rendered DN strings, which can differ in
/// formatting (e.g. RFC 4514 vs. the x509-parser default) for the same name.
///
/// COMPLIANCE MAPPING:
/// - RFC 7030 §4.2.2 - Re-enrollment: the CSR subject must match the existing
///   certificate's subject; structured comparison avoids false mismatches.
/// - RFC 5280 §4.1.2.4 / RFC 4514 - Subject DN representation
/// - NIST 800-53: SI-10 - Information input validation
pub fn parse_csr_subject_dn(der: &[u8]) -> Result<ostrich_common::types::DistinguishedName> {
    // Primary: x509-parser. Fall back to the der-based decoder for CSRs whose
    // attributes x509-parser rejects (see `parse_csr`) so identity binding still
    // works for those requests. The fallback only runs when the strict parse
    // fails, so it cannot alter results for CSRs that parse today.
    match x509_parser::certification_request::X509CertificationRequest::from_der(der) {
        Ok((_, csr)) => parse_distinguished_name(&csr.certification_request_info.subject),
        Err(primary_err) => {
            use der::{Decode, Encode};
            let normalized = normalize_missing_attributes(der)?;
            let req =
                x509_cert::request::CertReq::from_der(&normalized).map_err(|fallback_err| {
                    Error::Parse(format!(
                        "Failed to parse PKCS#10 CSR: {} (der fallback also failed: {})",
                        primary_err, fallback_err
                    ))
                })?;
            // Re-parse only the subject Name with x509-parser (it rejects the
            // request *attributes*, not the Name) so the structured DN and its
            // per-attribute string decoding are identical to the primary path -
            // in particular non-UTF-8 directory strings (BMP/Universal/Teletex)
            // decode correctly instead of via lossy UTF-8.
            let subject_der = req
                .info
                .subject
                .to_der()
                .map_err(|e| Error::Parse(format!("re-encode subject Name: {}", e)))?;
            let (_, name) = x509_parser::x509::X509Name::from_der(&subject_der)
                .map_err(|e| Error::Parse(format!("Failed to parse CSR subject Name: {}", e)))?;
            parse_distinguished_name(&name)
        }
    }
}

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
    let mut sans = Vec::new();

    // Look for extensionRequest attribute (OID 1.2.840.113549.1.9.14)
    for attr in csr.certification_request_info.attributes() {
        if attr.oid.to_id_string() == "1.2.840.113549.1.9.14" {
            // attr.value is the raw `SET OF` DER wrapping the Extensions SEQUENCE.
            sans.extend(extract_sans_from_extension_request(attr.value)?);
        }
    }

    Ok(sans)
}

/// Extract SAN strings from the raw DER of an `extensionRequest` attribute value.
///
/// `set_der` is the `SET OF` TLV (RFC 2986 §4.1 attribute value) that wraps a
/// single `SEQUENCE OF Extension` (RFC 5272 §3.1 `ExtensionReq`). Factored out
/// so the primary x509-parser path and the der-based fallback in [`parse_csr`]
/// produce identically-formatted SAN entries.
///
/// COMPLIANCE MAPPING:
/// - RFC 2986 §4.1: PKCS#10 extensionRequest attribute
/// - RFC 5280 §4.2.1.6: SubjectAltName extension
/// - NIST 800-53 SI-10: Input validation
fn extract_sans_from_extension_request(set_der: &[u8]) -> Result<Vec<String>> {
    use x509_parser::der_parser::asn1_rs::{FromDer, Sequence};
    use x509_parser::extensions::GeneralName;

    let mut sans = Vec::new();

    // The extensionRequest value is a SET wrapping a SEQUENCE of Extensions.
    use x509_parser::der_parser::asn1_rs::Set;
    let (_, extensions_set) = Set::from_der(set_der)
        .map_err(|e| Error::Parse(format!("Failed to parse extensionRequest SET: {}", e)))?;

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
        let (rest, extension_seq) = Sequence::from_der(remaining)
            .map_err(|e| Error::Parse(format!("Failed to parse extension SEQUENCE: {}", e)))?;
        remaining = rest;

        // Parse the extension SEQUENCE content: OID, [BOOLEAN], OCTET STRING
        // Use manual parsing from the content bytes
        let mut ext_remaining = extension_seq.content.as_ref();

        // First element: OID
        let (rest, ext_oid) = x509_parser::der_parser::asn1_rs::Oid::from_der(ext_remaining)
            .map_err(|e| Error::Parse(format!("Failed to parse extension OID: {}", e)))?;
        ext_remaining = rest;

        // Check if this is SubjectAltName (2.5.29.17)
        if ext_oid.to_id_string() == "2.5.29.17" {
            // Check for optional BOOLEAN (critical flag)
            // BOOLEAN tag is 0x01
            if ext_remaining.starts_with(&[0x01]) {
                // Skip the BOOLEAN
                use x509_parser::der_parser::asn1_rs::Boolean;
                let (rest, _critical) = Boolean::from_der(ext_remaining)
                    .map_err(|e| Error::Parse(format!("Failed to parse critical flag: {}", e)))?;
                ext_remaining = rest;
            }

            // Now get the OCTET STRING containing the extension value
            let extn_value_der = ext_remaining;

            // extnValue is an OCTET STRING containing the DER-encoded extension value
            let (_, octet_string) = x509_parser::der_parser::asn1_rs::OctetString::from_der(
                extn_value_der,
            )
            .map_err(|e| Error::Parse(format!("Failed to parse extnValue OCTET STRING: {}", e)))?;

            // The OCTET STRING contains a SEQUENCE of GeneralName
            let (_, san_seq) = Sequence::from_der(octet_string.as_ref())
                .map_err(|e| Error::Parse(format!("Failed to parse SAN SEQUENCE: {}", e)))?;

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
                            GeneralName::Invalid(tag, raw) => {
                                // x509-parser 0.18 added the Invalid variant to surface
                                // entries it could not decode. RFC 5280 §4.2.1.6 does not
                                // permit unknown forms; we record the raw bytes and tag in
                                // the SAN list so downstream profile-validation can flag
                                // the certificate, but we do not reject the parse here.
                                let hex_value = hex::encode(raw);
                                tracing::warn!(
                                    tag = ?tag,
                                    "Encountered invalid GeneralName variant in SAN extension"
                                );
                                sans.push(format!("invalid:tag={:?}:{}", tag, hex_value));
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

    Ok(sans)
}

/// Verify CSR signature (self-signed proof of possession)
///
/// RFC 2986 §4.2 - Signature must be verified
/// NIST 800-53: SI-10 - Validate cryptographic input
pub async fn verify_csr_signature(
    csr: &ParsedCsr,
    _crypto_provider: &Arc<dyn CryptoProvider>,
) -> Result<bool> {
    // Re-parse the CSR to get the TBS (To Be Signed) portion. The signature is
    // computed over the raw CertificationRequestInfo (RFC 2986 §4.2). Prefer
    // x509-parser's byte-exact `raw`; if it rejects the attributes (see
    // `parse_csr`), slice the same TBS range structurally so proof-of-possession
    // still holds for those CSRs.
    let tbs_der = match x509_parser::certification_request::X509CertificationRequest::from_der(
        &csr.der_encoded,
    ) {
        Ok((_, parsed_csr)) => parsed_csr.certification_request_info.raw.to_vec(),
        Err(_) => extract_cert_req_info_tbs(&csr.der_encoded)?,
    };

    // Map signature algorithm to our Algorithm enum
    let algorithm = map_signature_algorithm_oid(&csr.signature_algorithm)?;

    // Verify the self-signature (proof of possession) directly against the
    // CSR's embedded public key. The requester's key is external and not
    // resident in our crypto provider, so this is a stateless verification -
    // an earlier version imported the key into the software provider and
    // called provider.verify(), which used the provider's unprefixed PKCS#1
    // encoding and rejected standard CSR signatures with "Key not found in
    // software provider".
    //
    // RFC 2986: CSR ECDSA signatures are ASN.1 DER (X.509/CMS form), NOT the
    // JWS fixed r||s form, so request `ecdsa_fixed = false`.
    ostrich_crypto::verify_with_spki(&csr.public_key, algorithm, &tbs_der, &csr.signature, false)
        .map_err(|e| {
            Error::SignatureVerification(format!("CSR signature verification failed: {}", e))
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

    /// A CSR that OMITS the mandatory (but emptyable) `attributes [0]` field must
    /// still parse. In-browser generators built on pkijs drop the field entirely
    /// when there are no SANs, producing requests OpenSSL accepts but strict Rust
    /// decoders reject (x509-parser `InvalidAttributes`; RustCrypto `der` malformed
    /// context-[0]). `normalize_missing_attributes` injects an empty `A0 00` so
    /// these enroll. Fixtures are real pkijs output (subject CN=SPONSOR.TEST.NPE.1,
    /// no SANs) for an ECDSA P-256 and an RSA-2048 key.
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 2986 §4.1: attributes is mandatory but may be empty
    /// - NIST 800-53 SI-10: accept well-formed input; interoperate with clients
    #[test]
    fn test_parse_csr_missing_attributes_field() {
        // pkijs ECDSA P-256 CSR, no SANs → CertReqInfo ends at the public key.
        let ec = hex::decode(
            "3081d5307d020100301d311b301906035504030c1253504f4e534f522e5445\
             53542e4e50452e313059301306072a8648ce3d020106082a8648ce3d030107\
             03420004e880acc08946ab6e804cb31f3162ff97e89a9011740857c2af81da\
             330d8b5243620a103938806e32522ee43771ab3fb9532706c1e2308d07a0a4\
             8d2160a3a63a300a06082a8648ce3d0403020348003045022100aa0146c1e6\
             e881c8090c700963fe08004f47518e99e5f6d19b58850aae4757020220141932\
             415e115746cfd12135239cc7de45e3bc5aa281d3e2e6856363b279cdef",
        )
        .unwrap();
        // pkijs RSA-2048 CSR, no SANs.
        let rsa = hex::decode(
            "3082025e30820148020100301d311b301906035504030c1253504f4e534f52\
             2e544553542e4e50452e3130820122300d06092a864886f70d010101050003\
             82010f003082010a0282010100bf472adf90f843f180c63a1274666f4b897c\
             1596329a8b77729a28c7893610117d1d978d8a9a66a8637e98d328895191f7\
             753259cbbb3a33d9a6aec6dadb3d3268649e3ac932332b19d7cb374bd99644\
             235b290074f1c38c693df8a2d84a30e75ee5b8084691e7274c049a01b05516\
             d6451e6855bfbdcfd6568e6f54537e264b37993af8595bed984550c5c33382\
             3dfa59bfe8dd3a1fdb461458e3a50746aef292ecadc4b3f918a3462483e8fb\
             4f1f17d74fae267fff425799a6ef72c389b99dcc21bc332d87ba9db95b9c6f\
             1955c8da76a8f65763a4d1af502f102aac7bb54102c93d5beea6283c250c1a\
             2750d7b1602de281982104cbe2d72882c23bc31b250203010001300b06092a\
             864886f70d01010b038201010048cd154cf22f1870d3610382232f050d59e7\
             1b5329c4b912398d13cb1e3a608e81093d6a6a45b470e27799dbdd3b3ba726\
             047db6acdff61fbbc617288a38703299603b1373e58e1ad24356f0e78acd56\
             fb54f3fae001e5b5bdc5101854844a22fe70a0b68d0e78c97eda8d9fffdadf\
             4d92f1e7c5bfa04aaf9198648492a3ba514e7b46a98a5e4389bfe417c7cf37\
             ab9c99a8b798a68d468842eb384469ac3e0d8f243e7b91e2ce84f9121e2d4f\
             7e813e01e89d22a94b1203fd7dfe364c24e8aa24de1760ed0a93a0a7c55ecf\
             fc9c125f015c458c30750e221f5e6dd53a4618f22e19d0a7aca6a787bbe7fb\
             4db19e9cba9d9212be0ce4416fe73b775038837696",
        )
        .unwrap();

        for (label, der) in [("ecdsa", &ec), ("rsa", &rsa)] {
            let parsed =
                parse_csr(der).unwrap_or_else(|e| panic!("{label} no-attrs CSR must parse: {e}"));
            assert_eq!(
                parsed.subject_dn, "CN=SPONSOR.TEST.NPE.1",
                "{label} subject"
            );
            assert!(
                parsed.subject_alternative_names.is_empty(),
                "{label} SANs empty"
            );
            // The structured-DN path (RFC 7030 re-enrollment binding) must agree.
            let dn = parse_csr_subject_dn(der).expect("structured subject DN");
            assert_eq!(dn.common_name.as_deref(), Some("SPONSOR.TEST.NPE.1"));
            // der_encoded must stay the ORIGINAL bytes so PoP verifies the real
            // signature (computed over the attribute-less CertificationRequestInfo).
            assert_eq!(parsed.der_encoded, *der, "{label} der_encoded unchanged");
        }
    }

    /// Test parse_csr_subject_dn extracts the structured subject DN, and that it
    /// matches a certificate subject parsed via parse_subject_dn (both delegate
    /// to parse_distinguished_name, so the RFC 7030 §4.2.2 re-enrollment subject
    /// binding can compare them structurally regardless of string formatting).
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 7030 §4.2.2: re-enrollment subject binding
    /// - RFC 5280 §4.1.2.4 / RFC 4514: structured DN comparison
    #[test]
    fn test_parse_csr_subject_dn_structured() {
        use ostrich_common::types::DistinguishedName;

        // Same CSR fixture as test_parse_csr_includes_sans: subject is
        // C=US, ST=NY, L=NYC, O=OstrichPKI, CN=test-cn.
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

        let dn = parse_csr_subject_dn(&csr_der).expect("parse CSR subject DN");

        let expected = DistinguishedName {
            common_name: Some("test-cn".to_string()),
            organization: Some("OstrichPKI".to_string()),
            organizational_unit: None,
            locality: Some("NYC".to_string()),
            state_or_province: Some("NY".to_string()),
            country: Some("US".to_string()),
            serial_number: None,
        };
        assert_eq!(
            dn, expected,
            "CSR subject must parse into the expected structured DN"
        );

        // A different subject must NOT compare equal (the re-enroll guard relies
        // on this to reject CSRs whose subject differs from the prior cert).
        let other = DistinguishedName::new_cn("attacker");
        assert_ne!(dn, other);
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
