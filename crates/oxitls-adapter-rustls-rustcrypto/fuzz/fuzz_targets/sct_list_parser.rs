#![no_main]
// Fuzz oxitls's own hand-rolled SCT list parser (RFC 6962 §3.3) with arbitrary
// bytes. `parse_sct_list` decodes a u16-length-prefixed TLS wire format that,
// in the real handshake path, comes straight from an X.509 certificate
// extension controlled by whatever server the client connects to -- it is
// fully attacker-controlled input reachable pre-trust-decision. The goal is
// to assert that no amount of malformed input causes a panic (index
// out-of-bounds, integer overflow, or unwind) rather than a clean `Err`.
//
// Run with:
//   cargo fuzz run sct_list_parser

use libfuzzer_sys::fuzz_target;
use oxitls_adapter_rustls_rustcrypto::verifier::sct::parse_sct_list;

fuzz_target!(|data: &[u8]| {
    // Whatever `parse_sct_list` does with arbitrary bytes, it must return a
    // `Result` -- never panic. All internal length arithmetic is bounded by
    // `u16` (max list/entry length 65535) and every slice index is checked
    // against `end`/`bytes.len()` before use, so this should never trip, but
    // that invariant is exactly what this target exists to keep honest as the
    // parser evolves.
    let _ = parse_sct_list(data);
});
