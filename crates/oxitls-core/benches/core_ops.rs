//! Criterion benchmarks for `oxitls-core` core operations.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use oxitls_core::{AlertDescription, CipherSuite, ConnectionInfo, TlsError, TlsVersion};

fn bench_connection_info_builder(c: &mut Criterion) {
    c.bench_function("connection_info_builder_full", |b| {
        b.iter(|| {
            ConnectionInfo::new()
                .with_version(black_box(TlsVersion::Tls13))
                .with_cipher_suite(black_box(CipherSuite::Tls13Aes256GcmSha384))
                .with_alpn_protocol(black_box(b"h2".to_vec()))
                .with_sni(black_box("example.com".to_string()))
        });
    });
}

fn bench_connection_info_builder_minimal(c: &mut Criterion) {
    c.bench_function("connection_info_builder_version_only", |b| {
        b.iter(|| ConnectionInfo::new().with_version(black_box(TlsVersion::Tls12)));
    });
}

fn bench_tls_error_display(c: &mut Criterion) {
    c.bench_function("tls_error_display_other", |b| {
        let e = TlsError::Other("test error for benchmarking".to_string());
        b.iter(|| format!("{}", black_box(&e)));
    });
}

fn bench_tls_error_display_cert_invalid(c: &mut Criterion) {
    c.bench_function("tls_error_display_cert_invalid", |b| {
        let e = TlsError::CertInvalid("BadSignature".to_string());
        b.iter(|| format!("{}", black_box(&e)));
    });
}

fn bench_tls_error_display_protocol_violation(c: &mut Criterion) {
    c.bench_function("tls_error_display_protocol_violation", |b| {
        let e = TlsError::ProtocolViolation("peer misbehaved: foo".to_string());
        b.iter(|| format!("{}", black_box(&e)));
    });
}

fn bench_cipher_suite_iana(c: &mut Criterion) {
    c.bench_function("cipher_suite_iana_value_tls13_aes256", |b| {
        let suite = CipherSuite::Tls13Aes256GcmSha384;
        b.iter(|| black_box(suite).iana_value());
    });
}

fn bench_cipher_suite_from_iana(c: &mut Criterion) {
    c.bench_function("cipher_suite_from_iana_all_known", |b| {
        let known: [[u8; 2]; 9] = [
            [0x13, 0x01],
            [0x13, 0x02],
            [0x13, 0x03],
            [0xC0, 0x2B],
            [0xC0, 0x2C],
            [0xC0, 0x2F],
            [0xC0, 0x30],
            [0xCC, 0xA9],
            [0xCC, 0xA8],
        ];
        b.iter(|| {
            for bytes in &known {
                let _ = CipherSuite::from_iana(black_box(*bytes));
            }
        });
    });
}

fn bench_from_rustls_error_cert_invalid(c: &mut Criterion) {
    c.bench_function("from_rustls_error_no_certs_presented", |b| {
        b.iter(|| {
            let e = black_box(rustls::Error::NoCertificatesPresented);
            TlsError::from(e)
        });
    });
}

fn bench_tls_error_io_from(c: &mut Criterion) {
    c.bench_function("TlsError_io_from", |b| {
        b.iter(|| black_box(TlsError::from(std::io::Error::other("bench"))))
    });
}

fn bench_tls_error_other_alloc(c: &mut Criterion) {
    c.bench_function("TlsError_other_alloc", |b| {
        b.iter(|| black_box(TlsError::Other("bench_error_string".to_string())))
    });
}

fn bench_tls_error_alert_no_alloc(c: &mut Criterion) {
    c.bench_function("TlsError_alert_received_no_alloc", |b| {
        b.iter(|| black_box(TlsError::AlertReceived(AlertDescription::BadCertificate)))
    });
}

criterion_group!(
    core_ops,
    bench_connection_info_builder,
    bench_connection_info_builder_minimal,
    bench_tls_error_display,
    bench_tls_error_display_cert_invalid,
    bench_tls_error_display_protocol_violation,
    bench_cipher_suite_iana,
    bench_cipher_suite_from_iana,
    bench_from_rustls_error_cert_invalid,
    bench_tls_error_io_from,
    bench_tls_error_other_alloc,
    bench_tls_error_alert_no_alloc,
);
criterion_main!(core_ops);
