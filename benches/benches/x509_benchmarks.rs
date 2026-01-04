//! X.509 Certificate Benchmarks
//!
//! Performance benchmarks for certificate operations.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Security Testing)
//! - RFC 5280 - X.509 PKI Certificate Profile

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use der::{Decode, Encode};
use x509_cert::name::Name;

// A sample self-signed certificate in DER format (RSA 2048)
// This is a pre-generated test certificate for benchmark consistency
const SAMPLE_CERT_DER: &[u8] = include_bytes!("../test_data/sample_cert.der");

/// Benchmark certificate parsing (DER decoding)
fn bench_certificate_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("X.509 Certificate Parsing");

    group.throughput(Throughput::Bytes(SAMPLE_CERT_DER.len() as u64));

    group.bench_function("parse DER certificate", |b| {
        b.iter(|| {
            x509_cert::Certificate::from_der(black_box(SAMPLE_CERT_DER)).expect("parse failed")
        });
    });

    group.finish();
}

/// Benchmark certificate encoding (DER encoding)
fn bench_certificate_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("X.509 Certificate Encoding");

    let cert = x509_cert::Certificate::from_der(SAMPLE_CERT_DER).expect("parse failed");

    group.bench_function("encode DER certificate", |b| {
        b.iter(|| cert.to_der().expect("encode failed"));
    });

    group.finish();
}

/// Benchmark Name (DN) parsing
fn bench_name_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("X.500 Name Parsing");

    let simple_dn = "CN=Test";
    let medium_dn = "CN=Test Certificate,O=OstrichPKI,C=US";
    let complex_dn = "CN=Test Certificate,OU=Certificate Authority,O=OstrichPKI,L=San Francisco,ST=California,C=US";

    group.bench_function("parse simple DN", |b| {
        b.iter(|| Name::from_str(black_box(simple_dn)).expect("parse failed"));
    });

    group.bench_function("parse medium DN", |b| {
        b.iter(|| Name::from_str(black_box(medium_dn)).expect("parse failed"));
    });

    group.bench_function("parse complex DN", |b| {
        b.iter(|| Name::from_str(black_box(complex_dn)).expect("parse failed"));
    });

    group.finish();
}

/// Benchmark Name encoding
fn bench_name_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("X.500 Name Encoding");

    let name = Name::from_str("CN=Test Certificate,O=OstrichPKI,C=US").expect("parse failed");

    group.bench_function("encode DN to DER", |b| {
        b.iter(|| name.to_der().expect("encode failed"));
    });

    group.finish();
}

/// Benchmark serial number operations
fn bench_serial_number(c: &mut Criterion) {
    use x509_cert::certificate::Rfc5280;
    use x509_cert::serial_number::SerialNumber;

    let mut group = c.benchmark_group("Serial Number Operations");

    // Create a serial number with explicit profile type
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

use std::str::FromStr;

criterion_group!(
    benches,
    bench_certificate_parsing,
    bench_certificate_encoding,
    bench_name_parsing,
    bench_name_encoding,
    bench_serial_number,
);
criterion_main!(benches);
