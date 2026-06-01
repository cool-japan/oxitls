//! Criterion benchmark: TLS 1.3 handshake latency vs intermediate chain depth.
//!
//! Measures how adding intermediate CA certificates (0, 1, 3, 5, 10) to the
//! server's certificate chain affects full TLS 1.3 handshake latency.
//!
//! Chain structure for depth `n`:
//!   Root CA  →  Intermediate₁  →  …  →  Intermediateₙ  →  Leaf
//!
//! The client trusts only the Root CA. Config construction (key generation,
//! chain building) happens OUTSIDE the timed loop; only the loopback
//! handshake is measured.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use oxitls_adapter_rustls_rustcrypto::{
    client_config, server_config, RustcryptoAcceptor, RustcryptoConnector, ServerName,
};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, SerialNumber};
use rustls::RootCertStore;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;

// ── Chain helpers ─────────────────────────────────────────────────────────────

/// Build an rcgen CA params for the given subject CN with `BasicConstraints::Unconstrained`.
fn ca_params(cn: &str, serial: u64) -> CertificateParams {
    let mut p = CertificateParams::default();
    p.distinguished_name.push(rcgen::DnType::CommonName, cn);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    p.serial_number = Some(SerialNumber::from(serial));
    p
}

/// Build a server leaf certificate params for `localhost`.
fn leaf_params(serial: u64) -> CertificateParams {
    let mut p = CertificateParams::new(vec!["localhost".to_string()]).expect("leaf params");
    p.is_ca = IsCa::NoCa;
    p.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    p.serial_number = Some(SerialNumber::from(serial));
    p
}

/// Build a pair of rustls `(ClientConfig, ServerConfig)` for a chain of the
/// given intermediate depth.
///
/// The server sends the full chain (leaf + all intermediates). The client
/// trusts only the root CA anchor.
fn make_configs_for_depth(depth: usize) -> (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>) {
    // ----- Root CA (self-signed) -----
    let root_kp = KeyPair::generate().expect("root keypair");
    let root_ca = CertifiedIssuer::self_signed(ca_params("Root CA", 1), root_kp)
        .expect("root CA self_signed");
    let root_der: CertificateDer<'static> = root_ca.der().clone();

    // ----- Intermediate CAs (signed chain) -----
    let mut intermediates: Vec<CertificateDer<'static>> = Vec::with_capacity(depth);
    let mut current_issuer = root_ca;
    for i in 0..depth {
        let int_kp = KeyPair::generate().expect("intermediate keypair");
        let int_cn = format!("Intermediate CA {}", i + 1);
        let int_ca =
            CertifiedIssuer::signed_by(ca_params(&int_cn, (2 + i) as u64), int_kp, &current_issuer)
                .expect("intermediate CA signed_by");
        intermediates.push(int_ca.der().clone());
        current_issuer = int_ca;
    }

    // ----- Leaf (signed by last issuer in chain) -----
    let leaf_kp = KeyPair::generate().expect("leaf keypair");
    let leaf_cert = leaf_params((2 + depth) as u64)
        .signed_by(&leaf_kp, &current_issuer)
        .expect("leaf signed_by");
    let leaf_der: CertificateDer<'static> = leaf_cert.der().clone();
    let leaf_pkcs8 = leaf_kp.serialize_der();

    // ----- Server config: sends leaf + intermediates (leaf-first) -----
    let mut chain_ders: Vec<CertificateDer<'static>> = Vec::with_capacity(depth + 1);
    chain_ders.push(leaf_der);
    // Append intermediates in chain order (closest-to-leaf first).
    chain_ders.extend(intermediates.into_iter().rev());

    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_pkcs8));
    let server_cfg = server_config(chain_ders, key).expect("server config");

    // ----- Client config: trusts only root CA -----
    let mut roots = RootCertStore::empty();
    roots.add(root_der).expect("add root cert");
    let client_cfg = client_config(roots).expect("client config");

    (client_cfg, server_cfg)
}

// ── Benchmark ─────────────────────────────────────────────────────────────────

fn bench_chain_depth(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    let mut group = c.benchmark_group("tls13_chain_depth");

    for depth in [0usize, 1, 3, 5, 10] {
        // Build configs OUTSIDE the iter loop so only the handshake is timed.
        let (client_cfg, server_cfg) = make_configs_for_depth(depth);

        group.bench_with_input(
            BenchmarkId::new("intermediates", depth),
            &(client_cfg, server_cfg),
            |b, (client_cfg, server_cfg)| {
                b.iter(|| {
                    rt.block_on(async {
                        let (client_io, server_io) = tokio::io::duplex(65_536);
                        let connector = RustcryptoConnector::new(Arc::clone(client_cfg));
                        let acceptor = RustcryptoAcceptor::new(Arc::clone(server_cfg));
                        let sn = ServerName::try_from("localhost".to_string())
                            .expect("valid server name");

                        let (client_res, server_res) = tokio::join!(
                            connector.connect(sn, client_io),
                            acceptor.accept(server_io),
                        );
                        client_res.expect("client handshake");
                        server_res.expect("server handshake");
                    });
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_chain_depth);
criterion_main!(benches);
