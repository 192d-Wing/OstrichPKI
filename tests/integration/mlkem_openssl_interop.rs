//! Live cross-implementation interop for ML-KEM (FIPS 203): OstrichPKI's
//! `ostrich_crypto::kem` (aws-lc-rs backend) against the OpenSSL CLI.
//!
//! Proves both directions of the KEM agree on the standard FIPS 203 encodings:
//!   A) OstrichPKI encapsulates -> OpenSSL decapsulates to the SAME secret
//!   B) OpenSSL encapsulates    -> OstrichPKI decapsulates to the SAME secret
//!
//! Only the standardized public surfaces cross the boundary — the raw
//! encapsulation key (`ek`) and the ciphertext (`c`). Each side keeps its own
//! private key in its own format, so no private-key encoding interop is assumed.
//!
//! The X.509 SubjectPublicKey for ML-KEM is the raw `ek`
//! (draft-ietf-lamps-kyber-certificates), so an SPKI is just a fixed
//! param-set-specific header followed by `ek`. We bridge raw<->SPKI by
//! splicing that header (verified identical across keys of a parameter set).
//!
//! COMPLIANCE: exercises FIPS 203 ML-KEM-768 interoperability for the SAR /
//! ATO_EVIDENCE.md (NIST SC-12/SC-13, NIAP FCS_CKM.2).
//!
//! Gated on an `openssl` binary that supports ML-KEM-768; skips otherwise.

use std::path::Path;
use std::process::Command;

use ostrich_crypto::{encapsulate, KeyType, MlKemKeyPair};

/// ML-KEM-768 encapsulation-key length, FIPS 203 Table 3.
const EK_LEN: usize = 1184;

fn run_openssl(args: &[&str]) -> bool {
    Command::new("openssl")
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Skip unless OpenSSL is present AND can actually generate an ML-KEM-768 key.
fn openssl_has_mlkem(dir: &Path) -> bool {
    if Command::new("openssl").arg("version").output().is_err() {
        return false;
    }
    let probe = dir.join("probe.pem");
    run_openssl(&[
        "genpkey",
        "-algorithm",
        "ML-KEM-768",
        "-out",
        probe.to_str().unwrap(),
    ])
}

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ostrich-mlkem-{}-{}", tag, std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn ostrich_encapsulates_openssl_decapsulates() {
    let dir = tmpdir("a");
    if !openssl_has_mlkem(&dir) {
        eprintln!("mlkem_openssl_interop(A): openssl lacks ML-KEM; skipping");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }
    let p = |f: &str| dir.join(f).to_str().unwrap().to_string();

    // OpenSSL owns the key pair.
    assert!(run_openssl(&[
        "genpkey",
        "-algorithm",
        "ML-KEM-768",
        "-out",
        &p("priv.pem")
    ]));
    assert!(run_openssl(&[
        "pkey",
        "-in",
        &p("priv.pem"),
        "-pubout",
        "-outform",
        "DER",
        "-out",
        &p("pub.der"),
    ]));

    // Extract the raw ek (trailing EK_LEN bytes of the SPKI).
    let spki = std::fs::read(dir.join("pub.der")).unwrap();
    assert!(spki.len() > EK_LEN, "unexpected SPKI length {}", spki.len());
    let ek = &spki[spki.len() - EK_LEN..];

    // OstrichPKI encapsulates to OpenSSL's public key.
    let enc = encapsulate(KeyType::MlKem768, ek).expect("ostrich encapsulate");
    std::fs::write(dir.join("ct.bin"), &enc.ciphertext).unwrap();

    // OpenSSL decapsulates with its private key.
    assert!(run_openssl(&[
        "pkeyutl",
        "-decap",
        "-inkey",
        &p("priv.pem"),
        "-in",
        &p("ct.bin"),
        "-secret",
        &p("ss_openssl.bin"),
    ]));
    let ss_openssl = std::fs::read(dir.join("ss_openssl.bin")).unwrap();

    assert_eq!(
        ss_openssl.as_slice(),
        enc.shared_secret.as_slice(),
        "OstrichPKI-encapsulated secret must equal OpenSSL-decapsulated secret"
    );
    assert_eq!(ss_openssl.len(), 32);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn openssl_encapsulates_ostrich_decapsulates() {
    let dir = tmpdir("b");
    if !openssl_has_mlkem(&dir) {
        eprintln!("mlkem_openssl_interop(B): openssl lacks ML-KEM; skipping");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }
    let p = |f: &str| dir.join(f).to_str().unwrap().to_string();

    // OstrichPKI owns the key pair.
    let kp = MlKemKeyPair::generate(KeyType::MlKem768).unwrap();
    let ek = kp.public_key_bytes().unwrap();
    assert_eq!(ek.len(), EK_LEN);

    // Obtain a real param-set SPKI header from a throwaway OpenSSL key, then
    // splice [header || our ek] so OpenSSL will import our public key.
    assert!(run_openssl(&[
        "genpkey",
        "-algorithm",
        "ML-KEM-768",
        "-out",
        &p("tmpl.pem")
    ]));
    assert!(run_openssl(&[
        "pkey",
        "-in",
        &p("tmpl.pem"),
        "-pubout",
        "-outform",
        "DER",
        "-out",
        &p("tmpl_pub.der"),
    ]));
    let tmpl = std::fs::read(dir.join("tmpl_pub.der")).unwrap();
    let header = &tmpl[..tmpl.len() - EK_LEN];

    let mut spki = Vec::with_capacity(header.len() + ek.len());
    spki.extend_from_slice(header);
    spki.extend_from_slice(&ek);
    std::fs::write(dir.join("our_pub.der"), &spki).unwrap();
    // Convert to PEM (also validates OpenSSL accepts our spliced SPKI as a key).
    assert!(run_openssl(&[
        "pkey",
        "-pubin",
        "-inform",
        "DER",
        "-in",
        &p("our_pub.der"),
        "-out",
        &p("our_pub.pem"),
    ]));

    // OpenSSL encapsulates to OstrichPKI's public key.
    assert!(run_openssl(&[
        "pkeyutl",
        "-encap",
        "-inkey",
        &p("our_pub.pem"),
        "-pubin",
        "-out",
        &p("ct.bin"),
        "-secret",
        &p("ss_openssl.bin"),
    ]));
    let ct = std::fs::read(dir.join("ct.bin")).unwrap();
    let ss_openssl = std::fs::read(dir.join("ss_openssl.bin")).unwrap();

    // OstrichPKI decapsulates with its private key.
    let ss_ostrich = kp.decapsulate(&ct).expect("ostrich decapsulate");

    assert_eq!(
        ss_ostrich.as_slice(),
        ss_openssl.as_slice(),
        "OstrichPKI-decapsulated secret must equal OpenSSL-encapsulated secret"
    );
    assert_eq!(ss_ostrich.len(), 32);

    let _ = std::fs::remove_dir_all(&dir);
}
