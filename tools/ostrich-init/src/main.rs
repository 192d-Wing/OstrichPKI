//! OstrichPKI CA initialization tool
//!
//! Bootstraps a root Certificate Authority: generates a CA key pair in the
//! configured crypto provider (PKCS#11 HSM or software), self-signs a root
//! certificate, and registers both in the database (`ca_keys` +
//! `ca_certificates`). The printed certificate ID is what `ca-server` consumes
//! via `CA_CERTIFICATE_ID`.
//!
//! Supports RSA, ECDSA (P-256/P-384), Ed25519, and ML-DSA (FIPS 204) CA keys
//! via the shared ostrich-x509 signing module (algorithm derived from key type).
//! ML-DSA keys are software-backed (no HSM supports ML-DSA yet).
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
use ostrich_crypto::{CryptoProviderFactory, KeyType};
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

    /// CA key type: Rsa2048/3072/4096, EcP256, EcP384, Ed25519, MlDsa44/65/87
    #[arg(long, default_value = "Rsa3072")]
    key_type: String,

    /// Unique label for the CA key in the provider and database
    #[arg(long, default_value = "ostrich-root-ca")]
    key_label: String,

    /// Certificate validity in days
    #[arg(long, default_value = "3650")]
    validity_days: u32,

    /// basicConstraints pathLenConstraint (omit for no limit on a root;
    /// defaults to 0 for a subordinate)
    #[arg(long)]
    path_len: Option<u8>,

    /// Issue a SUBORDINATE (intermediate) CA certificate signed by the parent
    /// CA certificate with this ID, instead of a self-signed root. The parent
    /// CA key must be resolvable in the configured crypto provider (the same
    /// SoftHSM token / slot, or software store, that holds it).
    ///
    /// NIAP PP-CA: FMT_SMF.1 - CA hierarchy management
    /// RFC 5280 §4.2.1.9 - subordinate CA basicConstraints
    #[arg(long, env = "CA_PARENT_CERTIFICATE_ID")]
    subordinate_of: Option<String>,

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

    /// Exit successfully (without doing anything) if a CA key with this
    /// label is already registered. Makes the tool idempotent for one-shot
    /// init containers (CM-2: convergent baseline configuration).
    #[arg(long, default_value = "false")]
    if_exists_ok: bool,

    /// Provision the initial Administrator account with this username.
    /// Requires --admin-password. Idempotent: skipped if the user exists.
    /// NIST 800-53: AC-2 - initial account provisioning (replaces the
    /// hardcoded seed user removed from migration 00003 per CM-6/IA-5)
    #[arg(long, env = "CA_ADMIN_USERNAME")]
    admin_username: Option<String>,

    /// Initial Administrator password (hashed with Argon2id; never stored
    /// or logged in plaintext). NIST 800-53: IA-5(1)
    #[arg(long, env = "CA_ADMIN_PASSWORD")]
    admin_password: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    // The self-signature algorithm is derived from the CA key type via the
    // shared agility module (RSA, ECDSA P-256/P-384, Ed25519). The builder's
    // declared AlgorithmIdentifier and the signing call both come from it, so
    // tbsCertificate.signature == signatureAlgorithm (RFC 5280 §4.1.1.2).
    let key_type: KeyType =
        serde_json::from_value(serde_json::Value::String(args.key_type.clone()))
            .with_context(|| format!("Unknown key type '{}'", args.key_type))?;
    let sig_alg = ostrich_x509::signing::recommended_signature_algorithm(key_type)
        .with_context(|| format!("Key type {:?} not supported for CA signing", key_type))?;

    // Database
    let db_config = ostrich_db::PoolConfig::from_url(&args.database_url)?;
    let db_pool = ostrich_db::DatabasePool::new(&db_config).await?;
    tracing::info!("Running database migrations");
    db_pool.migrate().await?;

    // Provision the initial Administrator account (idempotent).
    // Runs before the CA-exists early-return so re-running the tool can add
    // the admin to an already-bootstrapped deployment.
    provision_admin(&args, &db_pool).await?;

    let ca_repo = ostrich_db::repository::CaRepository::new(db_pool.clone());
    if ca_repo
        .find_ca_key_by_label(&args.key_label)
        .await?
        .is_some()
    {
        if args.if_exists_ok {
            println!(
                "CA key '{}' already registered; nothing to do (--if-exists-ok).",
                args.key_label
            );
            return Ok(());
        }
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

    // Subordinate (intermediate) CA mode: sign a new intermediate CA cert with
    // an EXISTING parent CA key resolved from the same provider. Root mode
    // (the code below) is unchanged when --subordinate-of is absent.
    if let Some(parent_id) = args.subordinate_of.clone() {
        return run_subordinate(
            &args,
            &ca_repo,
            crypto.as_ref(),
            key_type,
            provider_type,
            slot,
            &parent_id,
        )
        .await;
    }

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
    // RFC 5280 §4.1.2.2 - positive random serial from the FIPS DRBG
    // (NIST SP 800-90A CTR_DRBG), not the `rand` crate. NIAP FCS_RBG_EXT.1.
    let mut serial_bytes = ostrich_crypto::fips_random_bytes(20)?;
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
        .signature_algorithm(sig_alg)
        .build_tbs()?;
    let not_before = tbs.not_before;
    let not_after = tbs.not_after;
    let tbs_der = tbs.to_der()?;

    // Self-sign with the algorithm the builder declared, then encode the
    // signature into the X.509 form (ECDSA fixed r||s -> DER; RSA/Ed25519
    // pass through). RFC 5280 §4.1.1.2 / NIAP PP-CA: FCS_COP.1.
    let raw_signature = crypto
        .sign(&key_handle, sig_alg, &tbs_der)
        .await
        .context("Self-signing failed")?;
    let signature = ostrich_x509::signing::encode_x509_signature(sig_alg, raw_signature)
        .context("Failed to encode signature")?;
    let der_encoded = assemble_certificate(&tbs_der, &signature)?;
    let pem_encoded =
        pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &der_encoded)
            .context("PEM encoding failed")?;

    // Register key + certificate in the database
    // NIST 800-53: CM-2 - CA identity as configuration data
    let key_type_str = enum_name(&key_handle.key_type)?;
    let algorithm_str = enum_name(&sig_alg)?;
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

/// Issue a subordinate (intermediate) CA certificate.
///
/// Builds an intermediate CA certificate whose subject is the new CA's DN and
/// whose issuer is the parent CA's subject, signs it with the parent CA's key
/// (resolved from the current crypto provider), and registers the new
/// intermediate key + certificate (is_root=false, parent_ca_id set).
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-12 (Key Establishment), SC-17 (PKI Certificates)
/// - NIAP PP-CA: FMT_SMF.1 - CA hierarchy management
/// - NIAP PP-CA: FDP_CER_EXT.1 - certificate field generation (SKI/AKI/BC)
/// - NIAP PP-CA: FCS_STG_EXT.1 - intermediate key generated non-extractable
/// - RFC 5280 §4.2.1.9 - subordinate CA basicConstraints (CA=true, pathLen)
/// - RFC 5280 §4.2.1.1/§4.2.1.2 - Authority/Subject Key Identifier
///
/// Fails closed: if the parent CA's key cannot be resolved/reconstructed for
/// signing, the function errors instead of producing an unsigned/garbage cert.
#[allow(clippy::too_many_arguments)]
async fn run_subordinate(
    args: &Args,
    ca_repo: &ostrich_db::repository::CaRepository,
    crypto: &dyn ostrich_crypto::CryptoProvider,
    key_type: KeyType,
    provider_type: &str,
    slot: Option<i64>,
    parent_id: &str,
) -> Result<()> {
    // 1. Load the parent CA certificate and key reference.
    let parent_uuid =
        uuid::Uuid::parse_str(parent_id).context("--subordinate-of is not a valid UUID")?;
    let parent_cert = ca_repo
        .find_ca_certificate(parent_uuid)
        .await?
        .with_context(|| format!("Parent CA certificate {} not found", parent_uuid))?;
    let parent_key = ca_repo
        .find_ca_key(parent_cert.ca_key_id)
        .await?
        .with_context(|| {
            format!("Parent CA key {} not found", parent_cert.ca_key_id)
        })?;

    // Reconstruct the parent KeyHandle exactly as ca-server's bootstrap_ca does
    // (serde-string KeyType/Algorithm; ProviderId from provider_type + slot).
    // NIAP PP-CA: FCS_STG_EXT.1 - the key material stays in the provider; only
    // the handle is rebuilt here.
    let parent_provider_id = match parent_key.provider_type.as_str() {
        "Pkcs11" => ostrich_crypto::key::ProviderId::Pkcs11 {
            slot_id: parent_key.provider_slot_id.unwrap_or(0) as u64,
        },
        "Software" => ostrich_crypto::key::ProviderId::Software,
        other => bail!("Unknown parent CA key provider type: {}", other),
    };
    let parent_key_handle = ostrich_crypto::KeyHandle {
        provider_id: parent_provider_id,
        key_id: parent_key.key_id.clone(),
        key_type: parse_crypto_enum(&parent_key.key_type)
            .context("Invalid key_type on parent ca_keys row")?,
        algorithm: parse_crypto_enum(&parent_key.algorithm)
            .context("Invalid algorithm on parent ca_keys row")?,
        label: parent_key.label.clone(),
    };

    // Fail closed: confirm the parent key is actually resolvable for signing in
    // the configured provider before we generate anything. export_public_key
    // exercises the provider lookup without producing a signature.
    crypto
        .export_public_key(&parent_key_handle)
        .await
        .with_context(|| {
            format!(
                "Parent CA key '{}' (provider {}) is not resolvable in the configured \
                 crypto provider. The intermediate must be created against the SAME \
                 SoftHSM token/slot (or software store) that holds the parent key.",
                parent_key.label, parent_key.provider_type
            )
        })?;

    // 2. Generate the intermediate key (non-extractable, FCS_STG_EXT.1).
    tracing::info!(
        key_type = ?key_type, label = %args.key_label,
        "Generating intermediate CA key pair"
    );
    let int_key_handle = crypto
        .generate_key_pair(key_type, &args.key_label, false)
        .await
        .context("Intermediate CA key generation failed")?;
    let int_spki = crypto
        .export_public_key(&int_key_handle)
        .await
        .context("Failed to export intermediate CA public key")?;

    // 3. Signature algorithm is driven by the PARENT key type (the parent signs
    //    the intermediate). RFC 5280 §4.1.1.2.
    let parent_sig_alg =
        ostrich_x509::signing::recommended_signature_algorithm(parent_key_handle.key_type)
            .with_context(|| {
                format!(
                    "Parent key type {:?} is not supported for CA signing",
                    parent_key_handle.key_type
                )
            })?;

    // 4. Build the intermediate TBS.
    let subject = DistinguishedName {
        common_name: Some(args.common_name.clone()),
        organization: args.organization.clone(),
        country: args.country.clone(),
        ..Default::default()
    };
    // RFC 5280 §7.1 - issuer must be the parent's structured subject DN.
    let issuer_dn = ostrich_x509::parser::parse_subject_dn(&parent_cert.der_encoded)
        .map_err(|e| anyhow::anyhow!("Failed to parse parent CA subject DN: {}", e))?;

    let path_len = args.path_len.unwrap_or(0);

    // RFC 5280 §4.1.2.2 - positive random serial, <= 20 octets.
    // RFC 5280 §4.1.2.2 - positive random serial from the FIPS DRBG
    // (NIST SP 800-90A CTR_DRBG), not the `rand` crate. NIAP FCS_RBG_EXT.1.
    let mut serial_bytes = ostrich_crypto::fips_random_bytes(20)?;
    serial_bytes[0] &= 0x7F;
    let serial = SerialNumber::from_bytes(serial_bytes)?;

    // RFC 5280 §4.2.1.2 - SKI = key id of the intermediate's own public key.
    let ski = ostrich_x509::signing::key_identifier(&int_spki)
        .context("Failed to compute intermediate subject key identifier")?;
    // RFC 5280 §4.2.1.1 - AKI = key id of the parent CA's public key.
    let parent_spki = ostrich_x509::parser::parse_certificate(&parent_cert.der_encoded)
        .map_err(|e| anyhow::anyhow!("Failed to parse parent CA certificate: {}", e))?
        .public_key;
    let aki = ostrich_x509::signing::key_identifier(&parent_spki)
        .context("Failed to compute authority key identifier from parent CA")?;

    let tbs = CertificateBuilder::new()
        .serial_number(serial.clone())
        .subject(subject.clone())
        .issuer(issuer_dn)
        .validity_days(args.validity_days)
        .public_key(int_spki)
        // RFC 5280 §4.2.1.9 - subordinate CA: CA=true with pathLenConstraint.
        .basic_constraints(true, Some(path_len))
        .add_key_usage(KeyUsage::KeyCertSign)
        .add_key_usage(KeyUsage::CrlSign)
        .add_key_usage(KeyUsage::DigitalSignature)
        .subject_key_id(ski)
        .authority_key_id(aki)
        .signature_algorithm(parent_sig_alg)
        .build_tbs()?;
    let not_before = tbs.not_before;
    let not_after = tbs.not_after;
    let tbs_der = tbs.to_der()?;

    // 5. Sign the intermediate TBS with the PARENT key.
    // NIAP PP-CA: FCS_COP.1 - signature generation.
    let raw_signature = crypto
        .sign(&parent_key_handle, parent_sig_alg, &tbs_der)
        .await
        .context("Signing intermediate CA with parent key failed")?;
    let signature = ostrich_x509::signing::encode_x509_signature(parent_sig_alg, raw_signature)
        .context("Failed to encode signature")?;
    let der_encoded = assemble_certificate(&tbs_der, &signature)?;
    let pem_encoded =
        pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &der_encoded)
            .context("PEM encoding failed")?;

    // 6. Register intermediate key + certificate.
    // The ca_keys.algorithm column records the algorithm THIS key signs with
    // when the intermediate later runs as a CA server and signs leaves, so it
    // is derived from the intermediate's OWN key type, not the parent's.
    let int_sig_alg =
        ostrich_x509::signing::recommended_signature_algorithm(int_key_handle.key_type)
            .with_context(|| {
                format!(
                    "Intermediate key type {:?} is not supported for CA signing",
                    int_key_handle.key_type
                )
            })?;
    let key_type_str = enum_name(&int_key_handle.key_type)?;
    let algorithm_str = enum_name(&int_sig_alg)?;
    let int_key_row = ca_repo
        .create_ca_key(
            &args.key_label,
            &key_type_str,
            &algorithm_str,
            provider_type,
            slot,
            &int_key_handle.key_id,
            false,
        )
        .await
        .context("Failed to register intermediate CA key")?;

    let int_cert_row = ca_repo
        .create_ca_certificate(
            int_key_row.id,
            serial.as_bytes(),
            &subject.to_string_rfc4514(), // subject_dn = the intermediate's own subject
            &parent_cert.subject_dn,      // issuer_dn = the parent's subject
            not_before,
            not_after,
            &der_encoded,
            &pem_encoded,
            false,                 // not a root
            Some(parent_cert.id),  // parent linkage
            Some(i32::from(path_len)),
        )
        .await
        .context("Failed to register intermediate CA certificate")?;

    // 7. Output for downstream use.
    println!("Subordinate CA certificate created successfully.");
    println!("  Subject:        {}", subject.to_string_rfc4514());
    println!("  Issuer (parent):{}", parent_cert.subject_dn);
    println!("  Key label:      {}", args.key_label);
    println!("  Provider:       {}", provider_type);
    println!("  pathLen:        {}", path_len);
    println!("  Valid until:    {}", not_after);
    println!("  CA key ID:      {}", int_key_row.id);
    println!("Subordinate CA certificate ID: {}", int_cert_row.id);
    println!();
    println!("Run this intermediate as its own CA server with:");
    println!("CA_CERTIFICATE_ID={}", int_cert_row.id);
    println!();
    println!("Intermediate CA certificate (PEM):");
    println!("{}", pem_encoded);

    Ok(())
}

/// Parse an ostrich-crypto enum (KeyType/Algorithm) from its serde string form.
fn parse_crypto_enum<T: serde::de::DeserializeOwned>(s: &str) -> Result<T> {
    serde_json::from_value(serde_json::Value::String(s.to_string()))
        .map_err(|e| anyhow::anyhow!("'{}': {}", s, e))
}

/// Provision the initial Administrator account if requested.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AC-2 - account provisioning
/// - NIST 800-53: IA-5(1) - Argon2id hashing; plaintext never persisted/logged
/// - NIST 800-53: CM-6 - explicit provisioning instead of hardcoded seed users
/// - NIAP PP-CA: FMT_SMR.2 - Administrator role assignment
async fn provision_admin(args: &Args, db_pool: &ostrich_db::DatabasePool) -> Result<()> {
    let (username, password) = match (&args.admin_username, &args.admin_password) {
        (Some(u), Some(p)) => (u, p),
        (None, None) => return Ok(()),
        _ => bail!("Both --admin-username and --admin-password are required to provision an admin"),
    };

    if password.len() < 12 {
        // NIST 800-63B §3.1.1: minimum 8, longer required for privileged accounts
        bail!("Admin password must be at least 12 characters (NIST 800-63B)");
    }

    let users = ostrich_db::repository::DbUserRepository::new(db_pool.clone());
    if users.user_exists(username).await? {
        println!("User '{}' already exists; skipping provisioning.", username);
        return Ok(());
    }

    let hash = ostrich_common::auth::password::hash_password(
        &ostrich_common::auth::PasswordHashConfig::default(),
        &secrecy::SecretString::from(password.clone()),
    )
    .map_err(|e| anyhow::anyhow!("Password hashing failed: {}", e))?;

    let id = users
        .create_user(
            username,
            Some("Initial Administrator"),
            &hash,
            &[ostrich_common::auth::Role::Administrator],
        )
        .await
        .context("Failed to create admin user")?;

    println!("Administrator account '{}' created (id {}).", username, id);
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
