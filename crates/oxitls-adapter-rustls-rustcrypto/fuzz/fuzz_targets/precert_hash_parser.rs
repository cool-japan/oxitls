#![no_main]
// Fuzz `precert_tbs_and_issuer_hash`, the RFC 6962 §3.2 precert_entry
// reconstruction used by embedded-SCT verification. It parses TWO
// fully-attacker-controlled DER certificates (the leaf presented by the peer
// and, when available, its issuer), re-encodes the leaf's TBSCertificate with
// the SCT-list extension stripped, and hashes the issuer's SPKI. Both are
// handshake-time inputs from an untrusted server, so this is exactly the
// class of hand-rolled-adjacent (parse + re-encode + strip-one-extension)
// logic the project's OCSP/SCT security fixes were about.
//
// The goal is to assert that no amount of malformed input causes a panic --
// only a clean `Err(SctVerifyError::ParseError(..))` is acceptable for
// malformed DER.
//
// Run with:
//   cargo fuzz run precert_hash_parser

use libfuzzer_sys::fuzz_target;
use oxitls_adapter_rustls_rustcrypto::verifier::sct::precert_tbs_and_issuer_hash;

fuzz_target!(|data: &[u8]| {
    // Split the fuzz input into two independently-malformed DER byte strings:
    // the first byte picks the split point (so the fuzzer can freely explore
    // both "leaf malformed, issuer fine" and "leaf fine, issuer malformed"
    // shapes), the remainder is divided accordingly between `leaf_der` and
    // `issuer_der`. `rest.len()` is always a valid split bound for
    // `rest.split_at`, so this cannot panic regardless of `data`'s contents.
    let Some((&split_byte, rest)) = data.split_first() else {
        return;
    };
    let split = usize::from(split_byte).min(rest.len());
    let (leaf_der, issuer_der) = rest.split_at(split);

    // Must never panic -- a well-formed `Result` either way is fine.
    let _ = precert_tbs_and_issuer_hash(leaf_der, issuer_der);
});
