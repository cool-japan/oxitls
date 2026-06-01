#![no_main]
// Fuzz the PEM certificate and private-key parsers with arbitrary bytes.
//
// The goal is to assert that no amount of malformed input causes a panic
// (uncontrolled crash or unwind) in the rustls-pemfile parsers.
//
// Run with:
//   cargo fuzz run client_config_parser

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Feed arbitrary bytes through the PEM cert parser.
    let mut cert_reader = std::io::BufReader::new(data);
    let _certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader).collect();

    // Also try the private-key parser path.
    let mut key_reader = std::io::BufReader::new(data);
    let _key = rustls_pemfile::private_key(&mut key_reader);

    // And the generic item parser.
    let mut item_reader = std::io::BufReader::new(data);
    let _items: Vec<_> = rustls_pemfile::read_all(&mut item_reader).collect();
});
