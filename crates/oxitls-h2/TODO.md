# oxitls-h2 TODO

## Status
Async wrapper (~300 SLOC) around the `h2` crate providing generic ALPN-checked
HTTP/2 handshake helpers. Handshake functions are generic over the transport type
(not hardcoded to TcpStream). Includes `H2Settings` builder for connection tuning
and `From<H2Error> for TlsError` conversion. Integration test for full
client-server H2 roundtrip exists.

## Core Implementation
- [x] Add configurable H2 settings builder: `H2Settings` struct with initial_window_size, max_frame_size, max_header_list_size, max_concurrent_streams (~100 SLOC)
- [x] Add `h2_client_handshake_with_settings(tls, settings)` accepting custom `h2::client::Builder` config (~40 SLOC)
- [x] Add `h2_server_handshake_with_settings(tls, settings)` accepting custom `h2::server::Builder` config (~40 SLOC)
- [x] Add server push support: `H2ServerPush` helper wrapping `h2::server::SendPush` with ALPN validation (~80 SLOC)
- [x] Add stream priority support: `StreamPriority` struct wrapping `h2::StreamDependency` with weight and exclusivity (~50 SLOC)
- [x] Add `H2Connection` wrapper that drives the h2 connection in a background task and provides `shutdown()` / `ping()` methods (~150 SLOC)
- [x] Add PING/keepalive support: periodic PING frame sending with configurable interval and timeout (~80 SLOC)
- [x] Add GOAWAY handling: `GracefulShutdown` struct that drains active streams before closing (~100 SLOC)
- [x] Add flow control helpers: per-stream and connection-level window update management (~80 SLOC)
- [x] Add HPACK dynamic table size configuration: expose `header_table_size` setting (~20 SLOC)
- [x] Add generic stream type support: make handshake functions generic over `AsyncRead + AsyncWrite` instead of hardcoded `TcpStream` (~60 SLOC)
- [x] Add `H2Error::Settings` variant for SETTINGS frame errors (~15 SLOC)
- [x] Add `H2Error::StreamReset(Reason)` variant for per-stream errors (~20 SLOC)

## API Improvements
- [x] Make `H2ClientHandshake` and `H2ServerConnection` type aliases generic over the transport type
- [x] Add `H2ClientBuilder` and `H2ServerBuilder` for fluent handshake configuration
- [x] Add `From<H2Error> for oxitls_core::TlsError` conversion
- [x] Add `H2Error::is_alpn_not_h2()`, `is_h2()`, `is_io()` predicates
- [x] Add re-export of `h2::Reason` for error handling in downstream crates
- [x] Add `H2Connection::stream_count()` and `H2Connection::is_idle()` introspection methods

## Testing
- [x] Test: handshake with custom initial_window_size validates flow control behavior
- [x] Test: handshake with max_concurrent_streams=1 enforces single stream
- [x] Test: PING frame round-trip latency measurement
- [x] Test: GOAWAY graceful shutdown drains active streams before closing
- [x] Test: server push sends PUSH_PROMISE followed by response
- [x] Test: stream priority setting propagates to h2 layer
- [x] Test: ALPN mismatch returns `H2Error::AlpnNotH2` with descriptive message
- [x] Test: generic transport type (not just TcpStream) works with handshake functions
- [x] Test: concurrent streams stress test (100 simultaneous bidirectional streams)
- [x] Test: large header (>16KB) with HPACK compression round-trips correctly

## Performance
- [x] Benchmark H2 handshake latency (h2_client_handshake + h2_server_handshake)
- [x] Benchmark single-stream throughput: 1MB, 10MB, 100MB payload sizes
- [x] Benchmark multi-stream throughput: 10 concurrent streams with 1MB each
- [x] Benchmark HPACK compression ratio on real-world header sets
- [x] Profile memory usage during high-concurrency stream multiplexing

## Integration
- [x] Wire `H2Settings` into `oxihttp-client` for HTTP/2 connection tuning — oxihttp uses its own `Http2Settings`/`ServerHttp2Settings` types (not `oxitls_h2::H2Settings` directly); the tuning surface is complete at the oxihttp level
- [x] Wire `H2Settings` into `oxihttp-server` for server-side HTTP/2 configuration — same as above: `ServerHttp2Settings` in oxihttp-server covers window size, frame size, concurrent streams, keep-alive
- [x] Coordinate with `oxitls` facade for `h2` feature gate re-exports of new types — Wave 8 (`H2Error`, `H2Settings`, `H2Reason` re-exported at `oxitls` crate root); 2026-05-29
- [x] Coordinate with `oxiquic-h3` for HTTP/3 vs HTTP/2 feature comparison and migration path — added `pub mod comparison` in `oxitls-h2` with feature table, API-symmetry mapping, and migration checklist; 2026-05-30
- [x] Add `oxitls-bench` benchmarks for H2 handshake and throughput alongside TLS benchmarks
