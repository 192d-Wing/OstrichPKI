//! Certificate Authority CLI commands
//!
//! RFC 5280: X.509 Public Key Infrastructure

use base64::Engine;
use clap::Subcommand;
use ostrich_common::types::DistinguishedName;
use std::path::PathBuf;

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum CaCommands {
    /// Get CA information
    Info {
        /// CA service URL (REST API)
        #[arg(long, default_value = "http://localhost:8080")]
        url: String,
    },

    /// Issue a new certificate
    Issue {
        /// CA service URL (REST API)
        #[arg(long, default_value = "http://localhost:8080")]
        url: String,

        /// Certificate profile name
        #[arg(long)]
        profile: String,

        /// Subject Common Name
        #[arg(long)]
        cn: String,

        /// Subject Organization
        #[arg(long)]
        org: Option<String>,

        /// Subject Organizational Unit
        #[arg(long)]
        ou: Option<String>,

        /// Subject Locality
        #[arg(long)]
        locality: Option<String>,

        /// Subject State/Province
        #[arg(long)]
        state: Option<String>,

        /// Subject Country (2-letter code)
        #[arg(long)]
        country: Option<String>,

        /// DNS Subject Alternative Names (can be specified multiple times)
        #[arg(long)]
        dns: Vec<String>,

        /// Email Subject Alternative Names (can be specified multiple times)
        #[arg(long)]
        email: Vec<String>,

        /// IP Subject Alternative Names (can be specified multiple times)
        #[arg(long)]
        ip: Vec<String>,

        /// Public key file (PEM or DER format)
        #[arg(long)]
        public_key: PathBuf,

        /// Requestor identity
        #[arg(long)]
        requestor: String,

        /// Output file for certificate (PEM format)
        #[arg(long, short)]
        output: PathBuf,
    },

    /// Revoke a certificate
    Revoke {
        /// CA service URL (REST API)
        #[arg(long, default_value = "http://localhost:8080")]
        url: String,

        /// Certificate ID (UUID)
        #[arg(long)]
        cert_id: String,

        /// Revocation reason
        #[arg(long, value_enum)]
        reason: RevocationReasonCli,

        /// Requestor identity
        #[arg(long)]
        requestor: String,

        /// Justification for revocation
        #[arg(long)]
        justification: Option<String>,
    },

    /// Check certificate revocation status
    Status {
        /// CA service URL (REST API)
        #[arg(long, default_value = "http://localhost:8080")]
        url: String,

        /// Certificate ID (UUID)
        #[arg(long)]
        cert_id: String,
    },

    /// Generate a CRL
    GenerateCrl {
        /// CA service URL (REST API)
        #[arg(long, default_value = "http://localhost:8080")]
        url: String,

        /// Output file for CRL (PEM format)
        #[arg(long, short)]
        output: PathBuf,
    },

    /// List available certificate profiles
    ListProfiles {
        /// CA service URL (REST API)
        #[arg(long, default_value = "http://localhost:8080")]
        url: String,
    },
}

/// Revocation reason CLI enum
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum RevocationReasonCli {
    Unspecified,
    KeyCompromise,
    CaCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    RemoveFromCrl,
    PrivilegeWithdrawn,
    AaCompromise,
}

impl RevocationReasonCli {
    pub fn to_i32(&self) -> i32 {
        match self {
            Self::Unspecified => 0,
            Self::KeyCompromise => 1,
            Self::CaCompromise => 2,
            Self::AffiliationChanged => 3,
            Self::Superseded => 4,
            Self::CessationOfOperation => 5,
            Self::CertificateHold => 6,
            Self::RemoveFromCrl => 8,
            Self::PrivilegeWithdrawn => 9,
            Self::AaCompromise => 10,
        }
    }
}

pub async fn handle_command(cmd: CaCommands) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        CaCommands::Info { url } => handle_info(&url).await?,
        CaCommands::Issue {
            url,
            profile,
            cn,
            org,
            ou,
            locality,
            state,
            country,
            dns,
            email,
            ip,
            public_key,
            requestor,
            output,
        } => {
            handle_issue(
                &url, &profile, cn, org, ou, locality, state, country, dns, email, ip, public_key,
                requestor, output,
            )
            .await?
        }
        CaCommands::Revoke {
            url,
            cert_id,
            reason,
            requestor,
            justification,
        } => handle_revoke(&url, &cert_id, reason, requestor, justification).await?,
        CaCommands::Status { url, cert_id } => handle_status(&url, &cert_id).await?,
        CaCommands::GenerateCrl { url, output } => handle_generate_crl(&url, output).await?,
        CaCommands::ListProfiles { url } => handle_list_profiles(&url).await?,
    }

    Ok(())
}

async fn handle_info(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let response = client.get(format!("{}/api/v1/ca/info", url)).send().await?;

    if !response.status().is_success() {
        let error_text = response.text().await?;
        return Err(format!("API error: {}", error_text).into());
    }

    let info: serde_json::Value = response.json().await?;
    println!("CA Information:");
    println!("  CA ID: {}", info["ca_id"].as_str().unwrap_or("N/A"));
    println!("  CA DN: {}", info["ca_dn"].as_str().unwrap_or("N/A"));

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_issue(
    url: &str,
    profile: &str,
    cn: String,
    org: Option<String>,
    ou: Option<String>,
    locality: Option<String>,
    state: Option<String>,
    country: Option<String>,
    dns_names: Vec<String>,
    email_names: Vec<String>,
    ip_names: Vec<String>,
    public_key_path: PathBuf,
    requestor: String,
    output: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    // Read public key
    let public_key_bytes = std::fs::read(&public_key_path)?;
    let public_key_b64 = base64::prelude::BASE64_STANDARD.encode(&public_key_bytes);

    // Build subject DN
    let subject = DistinguishedName {
        common_name: Some(cn),
        organization: org,
        organizational_unit: ou,
        locality,
        state_or_province: state,
        country,
        serial_number: None,
    };

    // Build subject alternative names
    let mut subject_alt_names = Vec::new();
    for dns in dns_names {
        subject_alt_names.push(serde_json::json!({
            "dns_name": dns
        }));
    }
    for email in email_names {
        subject_alt_names.push(serde_json::json!({
            "rfc822_name": email
        }));
    }
    for ip in ip_names {
        subject_alt_names.push(serde_json::json!({
            "ip_address": ip
        }));
    }

    // Build request
    let request = serde_json::json!({
        "profile_name": profile,
        "subject": subject,
        "subject_alt_names": subject_alt_names,
        "public_key": public_key_b64,
        "requestor": requestor,
    });

    // Send request
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/api/v1/certificates", url))
        .json(&request)
        .send()
        .await?;

    if !response.status().is_success() {
        let error_text = response.text().await?;
        return Err(format!("API error: {}", error_text).into());
    }

    let result: serde_json::Value = response.json().await?;

    // Write certificate to file
    let pem_encoded = result["pem_encoded"]
        .as_str()
        .ok_or("Missing pem_encoded in response")?;
    std::fs::write(&output, pem_encoded)?;

    println!("Certificate issued successfully!");
    println!(
        "  Certificate ID: {}",
        result["certificate_id"].as_str().unwrap_or("N/A")
    );
    println!(
        "  Serial Number: {}",
        result["serial_number"].as_str().unwrap_or("N/A")
    );
    println!(
        "  Valid From: {}",
        result["not_before"].as_str().unwrap_or("N/A")
    );
    println!(
        "  Valid Until: {}",
        result["not_after"].as_str().unwrap_or("N/A")
    );
    println!("  Certificate written to: {}", output.display());

    Ok(())
}

async fn handle_revoke(
    url: &str,
    cert_id: &str,
    reason: RevocationReasonCli,
    requestor: String,
    justification: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = serde_json::json!({
        "reason": reason.to_i32(),
        "requestor": requestor,
        "justification": justification,
    });

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/api/v1/certificates/{}/revoke", url, cert_id))
        .json(&request)
        .send()
        .await?;

    if !response.status().is_success() {
        let error_text = response.text().await?;
        return Err(format!("API error: {}", error_text).into());
    }

    let result: serde_json::Value = response.json().await?;

    println!("Certificate revoked successfully!");
    println!(
        "  Revocation Time: {}",
        result["revocation_time"].as_str().unwrap_or("N/A")
    );

    Ok(())
}

async fn handle_status(url: &str, cert_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/api/v1/certificates/{}/status", url, cert_id))
        .send()
        .await?;

    if !response.status().is_success() {
        let error_text = response.text().await?;
        return Err(format!("API error: {}", error_text).into());
    }

    let result: serde_json::Value = response.json().await?;

    println!("Certificate Status:");
    let revoked = result["revoked"].as_bool().unwrap_or(false);
    if revoked {
        println!("  Status: REVOKED");
        if let Some(time) = result["revocation_time"].as_str() {
            println!("  Revocation Time: {}", time);
        }
        if let Some(reason) = result["reason"].as_i64() {
            println!("  Reason: {}", reason);
        }
    } else {
        println!("  Status: VALID");
    }

    Ok(())
}

async fn handle_generate_crl(url: &str, output: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let response = client.post(format!("{}/api/v1/crl", url)).send().await?;

    if !response.status().is_success() {
        let error_text = response.text().await?;
        return Err(format!("API error: {}", error_text).into());
    }

    let result: serde_json::Value = response.json().await?;

    // Write CRL to file
    let pem_encoded = result["pem_encoded"]
        .as_str()
        .ok_or("Missing pem_encoded in response")?;
    std::fs::write(&output, pem_encoded)?;

    println!("CRL generated successfully!");
    println!(
        "  CRL Number: {}",
        result["crl_number"].as_u64().unwrap_or(0)
    );
    println!(
        "  This Update: {}",
        result["this_update"].as_str().unwrap_or("N/A")
    );
    println!(
        "  Next Update: {}",
        result["next_update"].as_str().unwrap_or("N/A")
    );
    println!(
        "  Revoked Certificates: {}",
        result["revoked_count"].as_u64().unwrap_or(0)
    );
    println!("  CRL written to: {}", output.display());

    Ok(())
}

async fn handle_list_profiles(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/api/v1/profiles", url))
        .send()
        .await?;

    if !response.status().is_success() {
        let error_text = response.text().await?;
        return Err(format!("API error: {}", error_text).into());
    }

    let result: serde_json::Value = response.json().await?;

    println!("Available Certificate Profiles:");
    println!();

    if let Some(profiles) = result["profiles"].as_array() {
        for profile in profiles {
            println!("Profile: {}", profile["name"].as_str().unwrap_or("N/A"));
            println!(
                "  Type: {}",
                profile["profile_type"].as_str().unwrap_or("N/A")
            );
            println!(
                "  Description: {}",
                profile["description"].as_str().unwrap_or("N/A")
            );
            println!(
                "  Validity: {} days",
                profile["validity_days"].as_u64().unwrap_or(0)
            );
            println!(
                "  Key Type: {}",
                profile["key_type"].as_str().unwrap_or("N/A")
            );
            println!(
                "  Algorithm: {}",
                profile["algorithm"].as_str().unwrap_or("N/A")
            );
            println!(
                "  CA Certificate: {}",
                profile["basic_constraints_ca"].as_bool().unwrap_or(false)
            );
            if let Some(path_len) = profile["basic_constraints_path_len"].as_u64() {
                println!("  Path Length: {}", path_len);
            }
            println!(
                "  SAN Required: {}",
                profile["subject_alt_name_required"]
                    .as_bool()
                    .unwrap_or(false)
            );
            println!();
        }
    }

    Ok(())
}
