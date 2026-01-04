//! Encoding/Decoding Benchmarks
//!
//! Performance benchmarks for Base64 and other encoding operations.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Security Testing)

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

/// Benchmark Base64 encoding
fn bench_base64_encoding(c: &mut Criterion) {
    use ostrich_common::util::encoding::{encode_base64, encode_base64url};

    let mut group = c.benchmark_group("Base64 Encoding");

    for size in [32, 256, 1024, 4096, 16384] {
        let data = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("standard", size), &data, |b, data| {
            b.iter(|| encode_base64(black_box(data)));
        });

        group.bench_with_input(BenchmarkId::new("url-safe", size), &data, |b, data| {
            b.iter(|| encode_base64url(black_box(data)));
        });
    }

    group.finish();
}

/// Benchmark Base64 decoding
fn bench_base64_decoding(c: &mut Criterion) {
    use ostrich_common::util::encoding::{
        decode_base64, decode_base64url, encode_base64, encode_base64url,
    };

    let mut group = c.benchmark_group("Base64 Decoding");

    for size in [32, 256, 1024, 4096, 16384] {
        let data = vec![0xABu8; size];
        let encoded_std = encode_base64(&data);
        let encoded_url = encode_base64url(&data);

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("standard", size),
            &encoded_std,
            |b, encoded| {
                b.iter(|| decode_base64(black_box(encoded)).expect("decode failed"));
            },
        );

        group.bench_with_input(
            BenchmarkId::new("url-safe", size),
            &encoded_url,
            |b, encoded| {
                b.iter(|| decode_base64url(black_box(encoded)).expect("decode failed"));
            },
        );
    }

    group.finish();
}

/// Benchmark hex encoding/decoding
fn bench_hex_operations(c: &mut Criterion) {
    use ostrich_common::util::encoding::{decode_hex, encode_hex};

    let mut group = c.benchmark_group("Hex Encoding");

    for size in [32, 256, 1024, 4096] {
        let data = vec![0xABu8; size];
        let encoded = encode_hex(&data);

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("encode", size), &data, |b, data| {
            b.iter(|| encode_hex(black_box(data)));
        });

        group.bench_with_input(BenchmarkId::new("decode", size), &encoded, |b, encoded| {
            b.iter(|| decode_hex(black_box(encoded)).expect("decode failed"));
        });
    }

    group.finish();
}

/// Benchmark DER encoding/decoding of common structures
fn bench_der_operations(c: &mut Criterion) {
    use der::{Decode, Encode};
    use x509_cert::certificate::Rfc5280;
    use x509_cert::serial_number::SerialNumber;

    let mut group = c.benchmark_group("DER Operations");

    // Serial number encoding/decoding
    let serial: SerialNumber<Rfc5280> = SerialNumber::from(0x123456789ABCDEFu64);
    let serial_der = serial.to_der().expect("encode failed");

    group.bench_function("encode serial number", |b| {
        b.iter(|| serial.to_der().expect("encode failed"));
    });

    group.bench_function("decode serial number", |b| {
        b.iter(|| {
            SerialNumber::<Rfc5280>::from_der(black_box(&serial_der)).expect("decode failed")
        });
    });

    group.finish();
}

/// Benchmark JSON serialization for ACME protocol messages
fn bench_json_serialization(c: &mut Criterion) {
    use serde::{Deserialize, Serialize};
    use serde_json;

    #[derive(Serialize, Deserialize, Clone)]
    struct AcmeOrder {
        status: String,
        identifiers: Vec<Identifier>,
        authorizations: Vec<String>,
        finalize: String,
        certificate: Option<String>,
    }

    #[derive(Serialize, Deserialize, Clone)]
    struct Identifier {
        #[serde(rename = "type")]
        id_type: String,
        value: String,
    }

    let mut group = c.benchmark_group("JSON Serialization");

    // Create test order
    let order = AcmeOrder {
        status: "pending".to_string(),
        identifiers: vec![
            Identifier {
                id_type: "dns".to_string(),
                value: "example.com".to_string(),
            },
            Identifier {
                id_type: "dns".to_string(),
                value: "www.example.com".to_string(),
            },
        ],
        authorizations: vec![
            "https://acme.example.com/authz/1".to_string(),
            "https://acme.example.com/authz/2".to_string(),
        ],
        finalize: "https://acme.example.com/order/1/finalize".to_string(),
        certificate: None,
    };

    let order_json = serde_json::to_string(&order).expect("serialize failed");

    group.bench_function("serialize ACME order", |b| {
        b.iter(|| serde_json::to_string(black_box(&order)).expect("serialize failed"));
    });

    group.bench_function("deserialize ACME order", |b| {
        b.iter(|| {
            serde_json::from_str::<AcmeOrder>(black_box(&order_json)).expect("deserialize failed")
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_base64_encoding,
    bench_base64_decoding,
    bench_hex_operations,
    bench_der_operations,
    bench_json_serialization,
);
criterion_main!(benches);
