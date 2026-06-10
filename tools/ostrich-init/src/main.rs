//! OstrichPKI CA initialization tool
//!
//! Bootstraps a root Certificate Authority: generates a CA key pair in the
//! configured crypto provider (PKCS#11 HSM or software), self-signs a root
//! certificate, and registers both in the database (`ca_keys` +
//! `ca_certificates`). The printed certificate ID is what `ca-server` consumes
//! via `CA_CERTIFICATE_ID`.
//!
//! Current limitation: RSA only. The certificate builder declares
//! sha256WithRSAEncryption; algorithm agility (ECDSA/EdDSA/ML-DSA roots) is a
//! tracked follow-up (see POAM notes in ostrich-x509 builder).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-12 (Key Establishment) - CA key generated in provider
//! - NIST 800-53: SC-17 (PKI Certificates) - root certificate creation
//! - NIST 800-53: CM-2 (Baseline Configuration) - CA identity registered as data
//! - NIAP PP-CA: FCS_CKM.1 - CA key generation
//! - NIAP PP-CA: FCS_STG_EXT.1 - keys generated non-extractable; HSM strongly
//!   recommended (software keys are rejected by ca-server at bootstrap)
//! - RFC 5280 §4.1 - self-signed certificate profile (basicConstraints CA,
//!   keyCertSign + cRLSign)

use anyhow::{Context, Result, bail};
use clap::Parser;
use ostrich_common::types::{DistinguishedName, SerialNumber};
use ostrich_crypto::{Algorithm, CryptoProviderFactory, KeyType};
use ostrich_x509::CertificateBuilder;
use ostrich_x509::profile::KeyUsage;

/// OstrichPKI CA initialization
#[derive(Parser, Debug)]
#[command(name = "ostrich-init")]
#[command(about = "Initialize a root CA: generate key, self-sign, register in database")]
#[command(version)]
struct Args {
    /// Database URL
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,

    /// CA common name (CN)
    #[arg(long, default_value = "OstrichPKI Root CA")]
    common_name: String,

    /// Organization (O)
    #[arg(long)]
    organization: Option<String>,

    /// Country (C), 2-letter code
    #[arg(long)]
    country: Option<String>,

    /// CA key type (RSA only for now: Rsa2048, Rsa3072, Rsa4096)
    #[arg(long, default_value = "Rsa3072")]
    key_type: String,

    /// Unique label for the CA key in the provider and database
    #[arg(long, default_value = "ostrich-root-ca")]
    key_label: String,

    /// Certificate validity in days
    #[arg(long, default_value = "3650")]
    validity_days: u32,

    /// basicConstraints pathLenConstraint (omit for no limit)
    #[arg(long)]
    path_len: Option<u8>,

    /// PKCS#11 library path (SoftHSM2/HSM). Omit to use the software provider
    /// (dev only - ca-server rejects software CA keys per FCS_STG_EXT.1).
    #[arg(long, env = "PKCS11_MODULE_PATH")]
    pkcs11_module: Option<String>,

    /// PKCS#11 slot ID
    #[arg(long, env = "PKCS11_SLOT_ID", default_value = "0")]
    pkcs11_slot: u64,

    /// PKCS#11 user PIN
    #[arg(long, env = "PKCS11_PIN")]
    pkcs11_pin: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    // RFC 5280 §4.1.1.2: the builder declares sha256WithRSAEncryption, so the
    // key must be RSA for the self-signature to verify.
    let key_type: KeyType =
        serde_json::from_value(serde_json::Value::String(args.key_type.clone()))
            .with_context(|| format!("Unknown key type '{}'", args.key_type))?;
    if !matches!(
        key_type,
        KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096
    ) {
        bail!(
            "Key type {:?} is not yet supported (RSA only until algorithm agility lands)",
            key_type
        );
    }

    // Database
    let db_config = ostrich_db::PoolConfig::from_url(&args.database_url)?;
    let db_pool = ostrich_db::DatabasePool::new(&db_config).await?;
    tracing::info!("Running database migrations");
    db_pool.migrate().await?;

    let ca_repo = ostrich_db::repository::CaRepository::new(db_pool.clone());
    if ca_repo
        .find_ca_key_by_label(&args.key_label)
        .await?
        .is_some()
    {
        bail!(
            "A CA key labeled '{}' is already registered; choose another --key-label",
            args.key_label
        );
    }

    // Crypto provider
    // NIAP PP-CA: FCS_STG_EXT.1 - HSM-backed keys for production
    let (crypto, provider_type, slot): (_, &str, Option<i64>) =
        match (&args.pkcs11_module, &args.pkcs11_pin) {
            (Some(module), Some(pin)) => {
                tracing::info!(module = %module, slot = args.pkcs11_slot, "Using PKCS#11 provider");
                (
                    CryptoProviderFactory::create_pkcs11_provider(
                        std::path::Path::new(module),
                        args.pkcs11_slot,
                        pin,
                    )
                    .await
                    .context("Failed to initialize PKCS#11 provider")?,
                    "Pkcs11",
                    Some(args.pkcs11_slot as i64),
                )
            }
            (None, None) => {
                tracing::warn!(
                    "Using SOFTWARE crypto provider. ca-server will reject this key \
                     (NIAP FCS_STG_EXT.1 requires HSM-backed CA keys); use SoftHSM2 \
                     via --pkcs11-module for a working dev setup."
                );
                (
                    CryptoProviderFactory::create_software_provider(),
                    "Software",
                    None,
                )
            }
            _ => bail!("Both --pkcs11-module and --pkcs11-pin are required for PKCS#11"),
        };

    // Generate the CA key pair (non-extractable per FCS_STG_EXT.1)
    // NIST 800-53: SC-12, NIAP PP-CA: FCS_CKM.1
    tracing::info!(key_type = ?key_type, label = %args.key_label, "Generating CA key pair");
    let key_handle = crypto
        .generate_key_pair(key_type, &args.key_label, false)
        .await
        .context("CA key generation failed")?;
    let public_key_der = crypto
        .export_public_key(&key_handle)
        .await
        .context("Failed to export CA public key")?;

    // Build the self-signed root certificate
    // RFC 5280 §4.2.1.9 basicConstraints CA=true; §4.2.1.3 keyCertSign+cRLSign
    let subject = DistinguishedName {
        common_name: Some(args.common_name.clone()),
        organization: args.organization.clone(),
        country: args.country.clone(),
        ..Default::default()
    };

    // RFC 5280 §4.1.2.2 - positive random serial, <= 20 octets
    let mut serial_bytes = ostrich_common::util::random::secure_random_bytes(20);
    serial_bytes[0] &= 0x7F;
    let serial = SerialNumber::from_bytes(serial_bytes)?;

    let tbs = CertificateBuilder::new()
        .serial_number(serial.clone())
        .subject(subject.clone())
        .issuer(subject.clone()) // self-signed: issuer == subject
        .validity_days(args.validity_days)
        .public_key(public_key_der)
        .basic_constraints(true, args.path_len)
        .add_key_usage(KeyUsage::KeyCertSign)
        .add_key_usage(KeyUsage::CrlSign)
        .add_key_usage(KeyUsage::DigitalSignature)
        .build_tbs()?;
    let not_before = tbs.not_before;
    let not_after = tbs.not_after;
    let tbs_der = tbs.to_der()?;

    // Self-sign. Must be PKCS#1 v1.5 SHA-256 to match the AlgorithmIdentifier
    // the builder wrote (RFC 5280 §4.1.1.2).
    // NIAP PP-CA: FCS_COP.1 - signature generation
    let signature = crypto
        .sign(&key_handle, Algorithm::RsaPkcs1Sha256, &tbs_der)
        .await
        .context("Self-signing failed")?;
    let der_encoded = assemble_certificate(&tbs_der, &signature)?;
    let pem_encoded =
        pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &der_encoded)
            .context("PEM encoding failed")?;

    // Register key + certificate in the database
    // NIST 800-53: CM-2 - CA identity as configuration data
    let key_type_str = enum_name(&key_handle.key_type)?;
    let algorithm_str = enum_name(&Algorithm::RsaPkcs1Sha256)?;
    let ca_key_row = ca_repo
        .create_ca_key(
            &args.key_label,
            &key_type_str,
            &algorithm_str,
            provider_type,
            slot,
            &key_handle.key_id,
            false,
        )
        .await
        .context("Failed to register CA key")?;

    let ca_cert_row = ca_repo
        .create_ca_certificate(
            ca_key_row.id,
            serial.as_bytes(),
            &subject.to_string_rfc4514(),
            &subject.to_string_rfc4514(),
            not_before,
            not_after,
            &der_encoded,
            &pem_encoded,
            true, // root
            None,
            args.path_len.map(i32::from),
        )
        .await
        .context("Failed to register CA certificate")?;

    println!("Root CA initialized successfully.");
    println!("  Subject:        {}", subject.to_string_rfc4514());
    println!("  Key label:      {}", args.key_label);
    println!("  Provider:       {}", provider_type);
    println!("  Valid until:    {}", not_after);
    println!("  CA key ID:      {}", ca_key_row.id);
    println!("  Certificate ID: {}", ca_cert_row.id);
    println!();
    println!("Start the CA server with:");
    println!(
        "  CA_CERTIFICATE_ID={} ostrich-ca-server ...",
        ca_cert_row.id
    );
    println!();
    println!("CA certificate (PEM):");
    println!("{}", pem_encoded);

    Ok(())
}

/// Assemble TBS DER + signature into a complete DER certificate.
/// Mirrors ostrich-ca's issuance assembly (RFC 5280 §4.1).
fn assemble_certificate(tbs_der: &[u8], signature: &[u8]) -> Result<Vec<u8>> {
    use der::{Decode, Encode, asn1::BitString};
    use x509_cert::{Certificate, TbsCertificate};

    let tbs = TbsCertificate::from_der(tbs_der).context("Failed to re-parse TBS certificate")?;
    let signature_algorithm = tbs.signature.clone();
    let signature =
        BitString::from_bytes(signature).context("Failed to encode signature BitString")?;
    let certificate = Certificate {
        tbs_certificate: tbs,
        signature_algorithm,
        signature,
    };
    certificate
        .to_der()
        .context("Failed to encode certificate")
}

/// Serde unit-variant name for an ostrich-crypto enum (matches the string
/// formats stored in ca_keys and parsed back by ca-server).
fn enum_name<T: serde::Serialize>(value: &T) -> Result<String> {
    match serde_json::to_value(value)? {
        serde_json::Value::String(s) => Ok(s),
        other => bail!("Unexpected enum encoding: {}", other),
    }
}
