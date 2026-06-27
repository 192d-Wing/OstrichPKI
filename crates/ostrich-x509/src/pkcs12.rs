//! Encrypted PKCS#12 (PFX, RFC 7292) packaging.
//!
//! Builds a password-protected PKCS#12 containing a private key and its
//! certificate, for server-side key generation delivery (the EST EFS flow). The
//! private key is placed in a `pkcs8ShroudedKeyBag` encrypted with PBES2
//! (PBKDF2-HMAC-SHA256 + AES-256-CBC, RFC 8018); the certificate is placed in a
//! `certBag` (in the clear, as is conventional — only the key is secret); and
//! the whole `AuthenticatedSafe` is integrity-protected with a PKCS#12 MAC
//! (HMAC-SHA256 keyed via the RFC 7292 Appendix B KDF).
//!
//! COMPLIANCE / POAM: the PBES2 envelope and PKCS#12 MAC use the RustCrypto
//! `pkcs5`/`pkcs12` crates (PBKDF2/AES-CBC/HMAC), which are NOT the project's
//! FIPS-validated module (aws-lc-rs). Key *generation* stays inside aws-lc-rs;
//! only the password-based transport envelope is non-FIPS. This is acceptable
//! for ephemeral, single-use server-side key delivery. POAM: migrate the PBE to
//! an aws-lc-rs path once it exposes PBKDF2/AES-CBC + PKCS#12.
//! NIST 800-53: SC-12/SC-13 (key management), SC-28 (protection at rest in transit).

use cms::content_info::ContentInfo;
use der::asn1::OctetString;
use der::{Any, Decode, Encode, Tag};
use hmac::{Hmac, Mac};
use pkcs12::cert_type::CertBag;
use pkcs12::digest_info::DigestInfo;
use pkcs12::kdf::{Pkcs12KeyType, derive_key_utf8};
use pkcs12::mac_data::MacData;
use pkcs12::pfx::{Pfx, Version};
use pkcs12::safe_bag::SafeBag;
use pkcs12::{PKCS_12_CERT_BAG_OID, PKCS_12_PKCS8_KEY_BAG_OID, PKCS_12_X509_CERT_OID};
use pkcs8::PrivateKeyInfo;
use pkcs8::pkcs5::pbes2;
use sha2::Sha256;
use spki::AlgorithmIdentifierOwned;

use crate::{Error, Result};

/// PBKDF2 iteration count for the key envelope. OWASP-recommended floor for
/// PBKDF2-HMAC-SHA256.
const PBKDF2_ITERATIONS: u32 = 600_000;
/// PKCS#12 MAC KDF iteration count.
const MAC_ITERATIONS: i32 = 100_000;

/// `id-data` content type (PKCS#7/CMS).
const OID_DATA: der::oid::ObjectIdentifier =
    der::oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
/// SHA-256 digest algorithm OID.
const OID_SHA256: der::oid::ObjectIdentifier =
    der::oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

fn enc_err(ctx: &str, e: impl std::fmt::Display) -> Error {
    Error::Encoding(format!("PKCS#12 {ctx}: {e}"))
}

/// Build a `ContentInfo` of type `data` whose content is `inner_der` wrapped in
/// an OCTET STRING (the SafeContents/AuthenticatedSafe carrier).
fn data_content_info(inner_der: &[u8]) -> Result<ContentInfo> {
    let content =
        Any::new(Tag::OctetString, inner_der.to_vec()).map_err(|e| enc_err("data content", e))?;
    Ok(ContentInfo {
        content_type: OID_DATA,
        content,
    })
}

/// Build a password-encrypted PKCS#12 (PFX) from a PKCS#8 private key and a
/// DER X.509 certificate.
///
/// - `private_key_pkcs8_der` — RFC 5958 PKCS#8 (unencrypted) DER.
/// - `certificate_der` — the issued X.509 certificate, DER.
/// - `password` — the one-time password protecting the key and MAC.
pub fn build_encrypted_pkcs12(
    private_key_pkcs8_der: &[u8],
    certificate_der: &[u8],
    password: &str,
) -> Result<Vec<u8>> {
    use ostrich_common::util::random::secure_random_bytes;

    // 1. Encrypt the private key with PBES2 (PBKDF2-SHA256 + AES-256-CBC). The
    //    salt/iv come from the FIPS RNG; only the PBE math is RustCrypto.
    let salt = secure_random_bytes(16);
    let iv: [u8; 16] = secure_random_bytes(16)
        .try_into()
        .map_err(|_| Error::Encoding("PKCS#12 iv length".to_string()))?;
    let params = pbes2::Parameters::pbkdf2_sha256_aes256cbc(PBKDF2_ITERATIONS, &salt, &iv)
        .map_err(|e| enc_err("pbes2 params", e))?;
    let pki = PrivateKeyInfo::from_der(private_key_pkcs8_der)
        .map_err(|e| enc_err("parse PKCS#8", e))?;
    let encrypted_key = pki
        .encrypt_with_params(params, password.as_bytes())
        .map_err(|e| enc_err("encrypt key", e))?;

    // 2. pkcs8ShroudedKeyBag holding the EncryptedPrivateKeyInfo. SafeBag's
    //    encoder wraps `bag_value` in the `[0] EXPLICIT` itself, so this is the
    //    raw inner DER.
    let key_bag = SafeBag {
        bag_id: PKCS_12_PKCS8_KEY_BAG_OID,
        bag_value: encrypted_key.as_bytes().to_vec(),
        bag_attributes: None,
    };
    let key_safe_contents: Vec<SafeBag> = vec![key_bag];
    let key_contents_der = key_safe_contents
        .to_der()
        .map_err(|e| enc_err("encode key bag", e))?;

    // 3. certBag holding the X.509 certificate.
    let cert_bag = CertBag {
        cert_id: PKCS_12_X509_CERT_OID,
        cert_value: OctetString::new(certificate_der).map_err(|e| enc_err("cert octets", e))?,
    };
    let cert_bag_der = cert_bag.to_der().map_err(|e| enc_err("encode certBag", e))?;
    let cert_safe_bag = SafeBag {
        bag_id: PKCS_12_CERT_BAG_OID,
        bag_value: cert_bag_der,
        bag_attributes: None,
    };
    let cert_safe_contents: Vec<SafeBag> = vec![cert_safe_bag];
    let cert_contents_der = cert_safe_contents
        .to_der()
        .map_err(|e| enc_err("encode cert bag", e))?;

    // 4. AuthenticatedSafe = SEQUENCE OF ContentInfo { keyContents, certContents }.
    let auth_safe: Vec<ContentInfo> = vec![
        data_content_info(&key_contents_der)?,
        data_content_info(&cert_contents_der)?,
    ];
    let auth_safe_der = auth_safe.to_der().map_err(|e| enc_err("encode authSafe", e))?;

    // 5. PKCS#12 MAC (HMAC-SHA256) over the AuthenticatedSafe DER, keyed via the
    //    RFC 7292 Appendix B KDF.
    let mac_salt = secure_random_bytes(20);
    let mac_key = derive_key_utf8::<Sha256>(
        password,
        &mac_salt,
        Pkcs12KeyType::Mac,
        MAC_ITERATIONS,
        32,
    )
    .map_err(|e| enc_err("mac kdf", e))?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&mac_key).map_err(|e| enc_err("hmac key", e))?;
    mac.update(&auth_safe_der);
    let mac_value = mac.finalize().into_bytes();

    let mac_data = MacData {
        mac: DigestInfo {
            algorithm: AlgorithmIdentifierOwned {
                oid: OID_SHA256,
                parameters: Some(Any::new(Tag::Null, Vec::new()).map_err(|e| enc_err("null", e))?),
            },
            digest: OctetString::new(mac_value.as_slice()).map_err(|e| enc_err("mac octets", e))?,
        },
        mac_salt: OctetString::new(mac_salt).map_err(|e| enc_err("mac salt octets", e))?,
        iterations: MAC_ITERATIONS,
    };

    // 6. Assemble + DER-encode the PFX.
    let pfx = Pfx {
        version: Version::V3,
        auth_safe: data_content_info(&auth_safe_der)?,
        mac_data: Some(mac_data),
    };
    pfx.to_der().map_err(|e| enc_err("encode PFX", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;

    // A real RSA-2048 PKCS#8 key + matching self-signed X.509 cert (generated
    // with openssl), so the round-trip exercises the actual encoder against
    // genuine key/cert DER.
    const PKCS8_B64: &str = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCr0nWJdh4R0TlEGdjJOdR8B5kFxMa3RofWmM4+b8g33LWga0uU8Y+JwHuMgYAnqaK7nJrSXnOmBxZudsvleoXgxeDlP66ndzlItTeMYG9w7fyMow3ReQeEsBoXRoRHzTV9GbqW0MDy3X582kjJ8NaN4n59picQPQyqKqNJDcM+UgO3u3lB8hYMkZ+ka3zl8MVSZgSr+LzkfsSRVh63Qu8HAlKIoUv4A47ZakVJ2rqPRHZTT+KXDkBtbYKmdpolTWs4KaN/1XuFnl2odhKr0x4Hq5aleahW6nB3DJUcniU1LSnCxIhYR5kZrdlvVcO9nHDzyGOgxNjTGCHwexcMwCwvAgMBAAECggEABu8+iSa4PfXYvtPgOPbZiYvw9BemAX2aO+H86O4wAXkp52iNK1y4c1HOarRLTM5+392JLhZbyoactCadQgy43IJ/+iCg1udr63BM5qB5vvAL8k0eYKbm08cbtnbFHfS9ROhF7JJORz8DPNy+dVAACMfsXPvYtcIRAckov+kLSTeLN8mAonTM5gtwOkWyigBa7eDVIsh8IegJDKFA0RwQKR0Fr2p6QLOINaY0w0YMJ6kknyJyt5/NincK8phpU3kgKevsX3CQAPgA4w4VNfQoGQ6eVjb2fe5HvbFc72oUmgMEL2ZEdFAksh0xx65OkheAwT6io5sN0B1Wx0zC0J3tYQKBgQDZ98dAM6QvcE2DcidBOE3k2RYPnH3C0jrO3sRR1l2czROj+NGf47TDrKgn8iEC9ubnax86YANA0suhP2HtJ74Iht13FdaKtwD5l8HLqCTxoeq2JfcBTdtsdynHrcGW2YC73W2StPzLiI9xgfsnkXPPam5vJkUs8lzSM4T0opdOPwKBgQDJzW8ykz8nqnYGi1E4g3KWUBq5L9f/KcSwn9xIV8LWzntU/fA5d4jfxdWHX8bveBtUOkIXzX7V9b+ml3Bv1SgNhBcCX6VezUJUL8aLV48A0qpiZs0DSHnNguy17304TlqgLz2dmlR7FHfxkckdolPoy7WGsw06t9+FGjYZYIGGEQKBgGQqVpltYeUfAbAHNHznR/yDunygGLb/72CDxMoq7cgSAhWXUZXdiYNmg7wfrAX1urTcaHRmDPisJkHKo9DdM5oth/aixX3njX4lvDw/4AJeu0LLfZBO3CgjNsL5WX5eI6exoRoLLCTIc8rgxa8wS30k1u0jNCTsl7VNUasuUMP3AoGBAJDM0Lo4f7uFi7S8aKYlY6ZJijNRCiq0HMcjndtm5Y5ekI52u9VwWQ1AFixR5BvWUb3JI72SnS0HbeIqjeogx+GS4zO3z6BLpglkUpGPXTQY9VswKnDto0B8bj9Jvc8WId8IpqycnXvHPx1eHzIdVRoYeYNSnO6CG2eVXDYvUiERAoGAOUb4SvkFrfIIlYDxrS8k9XuVRycghG5NVQmfrrKffhYYdB8EbGW1NWrxUBtek9+2WkfUsFKiGyMtdN8zF+B1WUYY9cA0oE0flNnbHCg/4LHxfmJyrGVz7k4630Vw6F+tTmo4ySKh/aHPzfaj2CGVGVbBzRdj+O5YEF4/HnCYWdg=";
    const CERT_B64: &str = "MIIDBzCCAe+gAwIBAgIUEjZ0oT7ypoPp9zzXRMYtNoRDNH0wDQYJKoZIhvcNAQELBQAwEzERMA8GA1UEAwwIZWZzLXRlc3QwHhcNMjYwNjI3MjIyMTE1WhcNMjYwNzI3MjIyMTE1WjATMREwDwYDVQQDDAhlZnMtdGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKvSdYl2HhHROUQZ2Mk51HwHmQXExrdGh9aYzj5vyDfctaBrS5Txj4nAe4yBgCeporucmtJec6YHFm52y+V6heDF4OU/rqd3OUi1N4xgb3Dt/IyjDdF5B4SwGhdGhEfNNX0ZupbQwPLdfnzaSMnw1o3ifn2mJxA9DKoqo0kNwz5SA7e7eUHyFgyRn6RrfOXwxVJmBKv4vOR+xJFWHrdC7wcCUoihS/gDjtlqRUnauo9EdlNP4pcOQG1tgqZ2miVNazgpo3/Ve4WeXah2EqvTHgerlqV5qFbqcHcMlRyeJTUtKcLEiFhHmRmt2W9Vw72ccPPIY6DE2NMYIfB7FwzALC8CAwEAAaNTMFEwHQYDVR0OBBYEFBtz4GGQJqnH5PcaoPGfwTXhqjyCMB8GA1UdIwQYMBaAFBtz4GGQJqnH5PcaoPGfwTXhqjyCMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBABms2IRtnDMzptAgKP5yXf1f6RvI2m6Fff/J6n5RfdJwKNlInzeWGiSxZJLiddHKNayqsOMZy7Zh1CwzNRflwFau7JDTEebIwlWrIY6EwHWTgDLlW04QTORrPVZWB5wFb1TSnzsdAy+30fUNV/sT8MplxekOKw3u2pWPbU6c28s7Qbmk5V2mMquEQlxVLy7cGovgdzlk7Qse/BxGHWOn/+SJ3gfRXXjpg/BggH6pr3l2w+RLg0rYYwqGwcQDK2xB8u79BcBdGaNvHYE4HBIGb25A0Kw1yuLFZi0PyEqmmgPVONNHElGG+lXlWqgUipVC/kGxWPZX0aN12fyGbq77PFc=";

    #[test]
    fn pfx_builds_and_parses_and_key_decrypts() {
        use der::Decode;
        use pkcs8::EncryptedPrivateKeyInfo;

        let pkcs8 = B64.decode(PKCS8_B64).unwrap();
        let cert = B64.decode(CERT_B64).unwrap();
        let password = "one-time-secret";

        let pfx_der = build_encrypted_pkcs12(&pkcs8, &cert, password).expect("build pfx");

        // Re-parse the PFX structurally.
        let pfx = Pfx::from_der(&pfx_der).expect("parse pfx");
        assert!(pfx.mac_data.is_some());

        // Extract the AuthenticatedSafe -> first ContentInfo (key bag) -> decrypt
        // the shrouded key with the password and confirm it round-trips to the
        // original PKCS#8.
        let auth_safe_octets = pfx
            .auth_safe
            .content
            .decode_as::<OctetString>()
            .expect("authSafe octets");
        let content_infos =
            Vec::<ContentInfo>::from_der(auth_safe_octets.as_bytes()).expect("authSafe seq");
        let key_octets = content_infos[0]
            .content
            .decode_as::<OctetString>()
            .expect("key contents octets");
        let bags = Vec::<SafeBag>::from_der(key_octets.as_bytes()).expect("key bags");
        // bag_value is the [0] EXPLICIT wrapper; strip the 0xA0 + length header.
        let bv = &bags[0].bag_value;
        let inner = strip_explicit_0(bv);
        let epki = EncryptedPrivateKeyInfo::from_der(inner).expect("epki");
        let decrypted = epki.decrypt(password.as_bytes()).expect("decrypt key");
        assert_eq!(decrypted.as_bytes(), pkcs8.as_slice());
    }

    /// Interop helper (run with `--ignored`): writes a PFX to the temp dir so it
    /// can be validated against openssl, e.g.:
    ///   `openssl pkcs12 -info -in $TMPDIR/efs_test.p12 -passin pass:one-time-secret -nodes`
    /// Confirmed (openssl 3.5): MAC sha256 verifies, shrouded keybag is
    /// PBES2/PBKDF2/AES-256-CBC, and both the key and certificate extract.
    #[test]
    #[ignore]
    fn write_pfx_for_openssl() {
        let pkcs8 = B64.decode(PKCS8_B64).unwrap();
        let cert = B64.decode(CERT_B64).unwrap();
        let pfx = build_encrypted_pkcs12(&pkcs8, &cert, "one-time-secret").unwrap();
        let path = std::env::temp_dir().join("efs_test.p12");
        std::fs::write(&path, pfx).unwrap();
        eprintln!("wrote {}", path.display());
    }

    /// Strip a `[0] EXPLICIT` header (the SafeBag bag_value wrapper on decode).
    fn strip_explicit_0(tlv: &[u8]) -> &[u8] {
        assert_eq!(tlv[0], 0xA0);
        let len_byte = tlv[1];
        let header = if len_byte < 0x80 {
            2
        } else {
            2 + (len_byte & 0x7f) as usize
        };
        &tlv[header..]
    }
}
