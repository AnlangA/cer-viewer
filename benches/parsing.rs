//! Criterion benchmarks for cer-viewer parsing performance.
//!
//! Run with: `cargo bench`

use cer_viewer::cert::{self, CertChain};
use cer_viewer::formats::csr;
use cer_viewer::utils::format_bytes_hex_colon;
use criterion::{criterion_group, criterion_main, Criterion};
use sha2::{Digest, Sha256};
use std::hint::black_box;

/// PEM certificate data (baidu.com).
fn pem_cert_data() -> &'static [u8] {
    include_bytes!("../assets/baidu.com.pem")
}

/// PEM certificate data (github.com).
fn pem_cert_data_2() -> &'static [u8] {
    include_bytes!("../assets/github.com.pem")
}

/// CSR PEM data.
fn csr_pem_data() -> &'static [u8] {
    include_bytes!("../assets/test.csr")
}

fn bench_pem_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("pem_parsing");

    group.bench_function("parse_pem_certificate_baidu", |b| {
        let data = pem_cert_data();
        b.iter(|| black_box(cert::parse_pem_certificate(data)));
    });

    group.bench_function("parse_pem_certificate_github", |b| {
        let data = pem_cert_data_2();
        b.iter(|| black_box(cert::parse_pem_certificate(data)));
    });

    group.finish();
}

fn bench_der_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("der_parsing");

    // Convert PEM to DER for DER parsing benchmark
    let pem_data = pem_cert_data();
    let der_data = cert::parse_pem_certificate(pem_data).unwrap().raw_der;

    group.bench_function("parse_der_certificate", |b| {
        b.iter(|| black_box(cert::parse_der_certificate(&der_data)));
    });

    group.finish();
}

fn bench_csr_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("csr_parsing");

    group.bench_function("parse_csr_pem", |b| {
        let data = csr_pem_data();
        b.iter(|| black_box(csr::parse_csr_pem(data)));
    });

    group.finish();
}

fn bench_chain_building(c: &mut Criterion) {
    let mut group = c.benchmark_group("chain_building");

    // Parse multiple certs for chain building
    let pem_1 = pem_cert_data();
    let pem_2 = pem_cert_data_2();

    let certs = vec![
        cert::parse_pem_certificate(pem_1).unwrap(),
        cert::parse_pem_certificate(pem_2).unwrap(),
    ];

    group.bench_function("build_chain_two_certs", |b| {
        b.iter(|| black_box(CertChain::build(certs.clone())));
    });

    // Single cert chain
    let single = vec![cert::parse_pem_certificate(pem_1).unwrap()];
    group.bench_function("build_chain_single_cert", |b| {
        b.iter(|| black_box(CertChain::build(single.clone())));
    });

    group.finish();
}

fn bench_fingerprint(c: &mut Criterion) {
    let mut group = c.benchmark_group("fingerprint");

    let pem_data = pem_cert_data();
    let der_data = cert::parse_pem_certificate(pem_data).unwrap().raw_der;

    group.bench_function("sha256_fingerprint", |b| {
        b.iter(|| {
            let hash = Sha256::digest(&der_data);
            black_box(format_bytes_hex_colon(&hash));
        });
    });

    group.finish();
}

fn bench_base64_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("base64_encoding");

    let pem_data = pem_cert_data();
    let cert = cert::parse_pem_certificate(pem_data).unwrap();

    group.bench_function("to_pem", |b| {
        b.iter(|| black_box(cert.to_pem()));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_pem_parsing,
    bench_der_parsing,
    bench_csr_parsing,
    bench_chain_building,
    bench_fingerprint,
    bench_base64_encoding,
);

criterion_main!(benches);
