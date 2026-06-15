//! Live cross-implementation verification of OstrichPKI's FIPS-backed classical
//! signatures (AWS-LC FIPS module via aws-lc-rs) against the OpenSSL CLI.
//!
//! For each key type the software provider generates a key, exports its SPKI,
//! and signs a message; OpenSSL then verifies the signature against that SPKI.
//! A successful external verify proves the signatures and public-key encodings
//! produced inside the FIPS boundary are standards-conformant and interoperable.
//!
//! Covered: RSA-2048 (PKCS#1 v1.5 / SHA-256), RSA-3072 (PKCS#1 v1.5 / SHA-384),
//! ECDSA P-256 (SHA-256), ECDSA P-384 (SHA-384).
//!
//! COMPLIANCE: SAR / ATO_EVIDENCE evidence for NIST SC-13 (FIPS-validated
//! cryptography) and NIAP FCS_COP.1 (signature generation).
//!
//! Gated on the `openssl` binary; skips otherwise.

use std::path::Path;
use std::process::Command;

use ostrich_crypto::software::SoftwareProvider;
use ostrich_crypto::{Algorithm, CryptoProvider, KeyType};

fn openssl_ok(args: &[&str]) -> bool {
    Command::new("openssl")
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn have_openssl() -> bool {
    Command::new("openssl").arg("version").output().is_ok()
}

/// Convert a fixed-width ECDSA signature (r||s) to ASN.1 DER, which is what
/// `openssl dgst -verify` expects.
fn ecdsa_fixed_to_der(fixed: &[u8]) -> Vec<u8> {
    let (r, s) = fixed.split_at(fixed.len() / 2);
    // Minimal DER INTEGER: strip leading zeros, prepend 0x00 if high bit set.
    fn der_int(bytes: &[u8]) -> Vec<u8> {
        let mut v = bytes;
        while v.len() > 1 && v[0] == 0 {
            v = &v[1..];
        }
        let mut body = Vec::new();
        if v[0] & 0x80 != 0 {
            body.push(0x00);
        }
        body.extend_from_slice(v);
        let mut out = vec![0x02, body.len() as u8];
        out.extend_from_slice(&body);
        out
    }
    let mut seq_body = der_int(r);
    seq_body.extend(der_int(s));
    let mut out = vec![0x30, seq_body.len() as u8];
    out.extend_from_slice(&seq_body);
    out
}

/// SPKI DER -> PEM via OpenSSL, returning the PEM path.
fn spki_der_to_pem(dir: &Path, spki: &[u8], stem: &str) -> std::path::PathBuf {
    let der = dir.join(format!("{stem}.der"));
    let pem = dir.join(format!("{stem}.pem"));
    std::fs::write(&der, spki).unwrap();
    assert!(
        openssl_ok(&[
            "pkey",
            "-pubin",
            "-inform",
            "DER",
            "-in",
            der.to_str().unwrap(),
            "-out",
            pem.to_str().unwrap(),
        ]),
        "openssl must parse the provider's SPKI for {stem}"
    );
    pem
}

#[tokio::test]
async fn fips_signatures_verify_in_openssl() {
    if !have_openssl() {
        eprintln!("fips_signature_openssl_interop: openssl not found; skipping");
        return;
    }
    let dir = std::env::temp_dir().join(format!("ostrich-fipssig-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = |f: &str| dir.join(f).to_str().unwrap().to_string();

    let provider = SoftwareProvider::new();
    let msg = b"FIPS classical signature interop payload";
    std::fs::write(dir.join("msg.bin"), msg).unwrap();

    // (key type, signing algorithm, openssl digest, is_ecdsa)
    let cases = [
        (
            KeyType::Rsa2048,
            Algorithm::RsaPkcs1Sha256,
            "-sha256",
            false,
        ),
        (
            KeyType::Rsa3072,
            Algorithm::RsaPkcs1Sha384,
            "-sha384",
            false,
        ),
        (KeyType::EcP256, Algorithm::EcdsaP256Sha256, "-sha256", true),
        (KeyType::EcP384, Algorithm::EcdsaP384Sha384, "-sha384", true),
    ];

    for (i, (kt, alg, digest, is_ecdsa)) in cases.iter().enumerate() {
        let stem = format!("k{i}");
        let key = provider.generate_key_pair(*kt, &stem, false).await.unwrap();
        let spki = provider.export_public_key(&key).await.unwrap();
        let sig = provider.sign(&key, *alg, msg).await.unwrap();

        let pem = spki_der_to_pem(&dir, &spki, &stem);

        // The provider emits ECDSA in fixed r||s form; OpenSSL wants ASN.1 DER.
        let sig_bytes = if *is_ecdsa {
            ecdsa_fixed_to_der(&sig)
        } else {
            sig.clone()
        };
        let sig_path = format!("{stem}.sig");
        std::fs::write(dir.join(&sig_path), &sig_bytes).unwrap();

        let verified = openssl_ok(&[
            "dgst",
            digest,
            "-verify",
            pem.to_str().unwrap(),
            "-signature",
            &p(&sig_path),
            &p("msg.bin"),
        ]);
        assert!(
            verified,
            "OpenSSL must verify the FIPS-backed {kt:?} signature ({alg:?})"
        );

        // Negative control: a different message must NOT verify.
        std::fs::write(dir.join("bad.bin"), b"tampered").unwrap();
        let bad = openssl_ok(&[
            "dgst",
            digest,
            "-verify",
            pem.to_str().unwrap(),
            "-signature",
            &p(&sig_path),
            &p("bad.bin"),
        ]);
        assert!(
            !bad,
            "{kt:?}: a tampered message must fail OpenSSL verification"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}
