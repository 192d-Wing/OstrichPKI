//! Cryptographic Operation Benchmarks
//!
//! Performance benchmarks for critical cryptographic operations used in PKI.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Security Testing)
//! - NIST 800-53: CP-2 (Contingency Plan) - Capacity planning

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
// OsRng comes from rsa's re-exported rand_core: the rsa 0.9 APIs require the
// rand_core 0.6 traits, while the workspace `rand` is 0.9 (rand_core 0.9).
// Same pattern as crates/ostrich-crypto/src/software/mod.rs.
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::rand_core::OsRng;
use rsa::signature::{Keypair, RandomizedSigner, Verifier};
use sha2::Sha256;

/// Benchmark RSA key generation at various key sizes
fn bench_rsa_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("RSA Key Generation");

    for bits in [2048, 3072, 4096] {
        group.bench_with_input(BenchmarkId::new("keygen", bits), &bits, |b, &bits| {
            b.iter(|| {
                let mut rng = OsRng;
                RsaPrivateKey::new(&mut rng, bits).expect("Failed to generate key")
            });
        });
    }

    group.finish();
}

/// Benchmark RSA signing operations
fn bench_rsa_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("RSA Signing");

    // Pre-generate keys for signing benchmarks
    let mut rng = OsRng;
    let private_key_2048 = RsaPrivateKey::new(&mut rng, 2048).expect("keygen failed");
    let private_key_4096 = RsaPrivateKey::new(&mut rng, 4096).expect("keygen failed");

    let signing_key_2048 = SigningKey::<Sha256>::new(private_key_2048);
    let signing_key_4096 = SigningKey::<Sha256>::new(private_key_4096);

    // Test data (simulating certificate TBS data)
    let message_small = vec![0u8; 256]; // Small certificate
    let message_medium = vec![0u8; 1024]; // Typical certificate
    let message_large = vec![0u8; 4096]; // Large certificate with extensions

    group.throughput(Throughput::Bytes(1024));

    group.bench_function("RSA-2048-SHA256 (1KB)", |b| {
        b.iter(|| {
            let mut rng = OsRng;
            signing_key_2048.sign_with_rng(&mut rng, black_box(&message_medium))
        });
    });

    group.bench_function("RSA-4096-SHA256 (1KB)", |b| {
        b.iter(|| {
            let mut rng = OsRng;
            signing_key_4096.sign_with_rng(&mut rng, black_box(&message_medium))
        });
    });

    group.bench_function("RSA-2048-SHA256 (256B)", |b| {
        b.iter(|| {
            let mut rng = OsRng;
            signing_key_2048.sign_with_rng(&mut rng, black_box(&message_small))
        });
    });

    group.bench_function("RSA-2048-SHA256 (4KB)", |b| {
        b.iter(|| {
            let mut rng = OsRng;
            signing_key_2048.sign_with_rng(&mut rng, black_box(&message_large))
        });
    });

    group.finish();
}

/// Benchmark RSA signature verification
fn bench_rsa_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("RSA Verification");

    // Pre-generate keys and signatures
    let mut rng = OsRng;
    let private_key_2048 = RsaPrivateKey::new(&mut rng, 2048).expect("keygen failed");
    let private_key_4096 = RsaPrivateKey::new(&mut rng, 4096).expect("keygen failed");

    let signing_key_2048 = SigningKey::<Sha256>::new(private_key_2048.clone());
    let signing_key_4096 = SigningKey::<Sha256>::new(private_key_4096.clone());

    let verifying_key_2048 = signing_key_2048.verifying_key();
    let verifying_key_4096 = signing_key_4096.verifying_key();

    let message = vec![0u8; 1024];
    let signature_2048 = signing_key_2048.sign_with_rng(&mut rng, &message);
    let signature_4096 = signing_key_4096.sign_with_rng(&mut rng, &message);

    group.throughput(Throughput::Bytes(1024));

    group.bench_function("RSA-2048-SHA256 verify", |b| {
        b.iter(|| verifying_key_2048.verify(black_box(&message), black_box(&signature_2048)));
    });

    group.bench_function("RSA-4096-SHA256 verify", |b| {
        b.iter(|| verifying_key_4096.verify(black_box(&message), black_box(&signature_4096)));
    });

    group.finish();
}

/// Benchmark SHA-256 hashing for various input sizes
fn bench_sha256_hashing(c: &mut Criterion) {
    use sha2::Digest;

    let mut group = c.benchmark_group("SHA-256 Hashing");

    for size in [64, 256, 1024, 4096, 16384] {
        let data = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("hash", size), &data, |b, data| {
            b.iter(|| {
                let mut hasher = Sha256::new();
                hasher.update(black_box(data));
                hasher.finalize()
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_rsa_keygen,
    bench_rsa_signing,
    bench_rsa_verification,
    bench_sha256_hashing,
);
criterion_main!(benches);
