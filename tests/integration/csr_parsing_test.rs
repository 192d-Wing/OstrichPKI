//! Integration tests for CSR parsing
//!
//! RFC 2986: PKCS#10 Certification Request
//! RFC 5280 §4.1.2.4: Distinguished Name parsing
//! RFC 5280 §4.2.1.6: Subject Alternative Name extraction
//!
//! COMPLIANCE MAPPING:
//! - RFC 2986: CSR structure parsing
//! - RFC 4514: DN string representation
//! - RFC 5280: X.509 extensions in CSRs
//! - NIST 800-53 SI-10: Input validation
//! - NIAP PP-CA FDP_ITC.1: Import user data

use ostrich_crypto::provider::CryptoProvider;
use ostrich_crypto::software::SoftwareProvider;
use ostrich_x509::parser::{parse_csr, parse_distinguished_name, verify_csr_signature};
use std::sync::Arc;
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::der_parser::asn1_rs::FromDer;

/// Test CSR with full DN and multiple SANs
///
/// DN: C=US, ST=NY, L=NYC, O=OstrichPKI, CN=test-cn
/// SANs: DNS:www.example.com, DNS:api.example.com, email:test@example.com
/// Algorithm: RSA-2048 with SHA-256
#[tokio::test]
async fn test_parse_csr_full_dn_with_sans() {
    // Real CSR generated with OpenSSL
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
    .expect("Failed to decode hex");

    // Parse CSR
    let parsed = parse_csr(&csr_der).expect("Failed to parse CSR");

    // Parse DN separately for structured access (RFC 5280 §4.1.2.4, RFC 4514)
    let (_, csr_struct) =
        X509CertificationRequest::from_der(&csr_der).expect("Failed to parse CSR for DN");
    let dn = parse_distinguished_name(&csr_struct.certification_request_info.subject)
        .expect("Failed to parse DN");

    // Verify DN fields
    assert_eq!(dn.common_name, Some("test-cn".to_string()));
    assert_eq!(dn.country, Some("US".to_string()));
    assert_eq!(dn.state_or_province, Some("NY".to_string()));
    assert_eq!(dn.locality, Some("NYC".to_string()));
    assert_eq!(dn.organization, Some("OstrichPKI".to_string()));

    // Verify SANs (RFC 5280 §4.2.1.6)
    assert_eq!(parsed.subject_alternative_names.len(), 3);
    assert!(parsed
        .subject_alternative_names
        .contains(&"DNS:www.example.com".to_string()));
    assert!(parsed
        .subject_alternative_names
        .contains(&"DNS:api.example.com".to_string()));
    assert!(parsed
        .subject_alternative_names
        .contains(&"email:test@example.com".to_string()));

    // Verify public key is present
    assert!(!parsed.public_key.is_empty());

    // Verify signature algorithm
    assert_eq!(parsed.signature_algorithm, "1.2.840.113549.1.1.11"); // sha256WithRSAEncryption

    // TODO: CSR signature verification requires crypto provider enhancement
    // to support temporary public keys for verification.
    // Signature verification is tested via ACME/EST REST endpoint integration tests.
    // See: crates/ostrich-acme/src/rest.rs:806-814
    //      crates/ostrich-est/src/rest.rs:268-276
}

/// Test CSR with minimal DN and no SANs
///
/// DN: C=US, ST=NY, L=NYC, O=OstrichPKI, CN=test-cn-no-sans
/// SANs: (none)
/// Algorithm: RSA-2048 with SHA-256
#[tokio::test]
async fn test_parse_csr_minimal_no_sans() {
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
    .expect("Failed to decode hex");

    let parsed = parse_csr(&csr_der).expect("Failed to parse CSR");

    // Parse DN for structured access
    let (_, csr_struct) =
        X509CertificationRequest::from_der(&csr_der).expect("Failed to parse CSR for DN");
    let dn = parse_distinguished_name(&csr_struct.certification_request_info.subject)
        .expect("Failed to parse DN");

    // Verify DN
    assert_eq!(dn.common_name, Some("test-cn-no-sans".to_string()));
    assert_eq!(dn.country, Some("US".to_string()));

    // Verify no SANs
    assert_eq!(parsed.subject_alternative_names.len(), 0);

    // TODO: Signature verification - see note in test_parse_csr_full_dn_with_sans
}

/// Test CSR signature verification with invalid signature
///
/// COMPLIANCE MAPPING:
/// - RFC 2986 §4.2: Signature validation (negative test)
/// - NIST 800-53 SI-10: Invalid input rejection
///
/// TODO: This test is currently disabled pending crypto provider enhancement
/// for temporary public key verification support.
#[tokio::test]
#[ignore]
async fn test_csr_invalid_signature_rejected() {
    // Valid CSR DER
    let mut csr_der = hex::decode(
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
    .expect("Failed to decode hex");

    // Corrupt the signature (last 32 bytes)
    let len = csr_der.len();
    for byte in csr_der.iter_mut().skip(len - 32) {
        *byte ^= 0xFF; // Flip all bits in signature
    }

    let parsed = parse_csr(&csr_der).expect("Should parse CSR structure");

    // Signature verification should fail
    let crypto = Arc::new(SoftwareProvider::new()) as Arc<dyn CryptoProvider>;
    let valid = verify_csr_signature(&parsed, &crypto)
        .await
        .expect("Verification should complete");

    assert!(!valid, "Corrupted CSR signature must be rejected");
}

/// Test DN parsing handles missing optional fields gracefully
///
/// COMPLIANCE MAPPING:
/// - RFC 5280 §4.1.2.4: Optional DN attributes
/// - RFC 4514: DN attribute handling
#[test]
fn test_dn_parsing_with_missing_fields() {
    // CSR with only CN and C (minimal DN)
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
    .expect("Failed to decode hex");

    let (_, csr) = X509CertificationRequest::from_der(&csr_der).expect("Failed to parse CSR");

    let dn = parse_distinguished_name(&csr.certification_request_info.subject)
        .expect("Failed to parse DN");

    // Present fields
    assert!(dn.common_name.is_some());
    assert!(dn.country.is_some());

    // Missing optional fields should be None
    assert_eq!(dn.organizational_unit, None);
    assert_eq!(dn.serial_number, None);
}
