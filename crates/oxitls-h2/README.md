# oxitls-h2 — HTTP/2 over OxiTLS streams

[![Crates.io](https://img.shields.io/crates/v/oxitls-h2.svg)](https://crates.io/crates/oxitls-h2)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`oxitls-h2` is the HTTP/2 binding for the OxiTLS ecosystem. It layers the [`h2`] crate over `tokio-rustls` TLS streams, providing **ALPN-checked** handshake helpers and ergonomic client/server builders. Every handshake function verifies that the `h2` ALPN protocol was actually negotiated before handing the stream to the h2 framing layer, so a misconfigured peer fails fast with [`H2Error::AlpnNotH2`] instead of producing a silent protocol mismatch.

The handshake helpers are generic over the transport `S` (`TcpStream`, `UnixStream`, in-memory `duplex` pipes, or any `AsyncRead + AsyncWrite + Unpin + Send` type). The crate is **Pure Rust** (`#![forbid(unsafe_code)]`); combined with the RustCrypto-backed provider the whole HTTP/2-over-TLS stack contains no C/C++/Fortran.

## Installation

```toml
[dependencies]
oxitls-h2 = "0.3.1"
```

Via the façade (enables `oxitls-h2` as the `h2` feature):

```toml
[dependencies]
oxitls = { version = "0.3.1", features = ["h2"] }
```

## Quick Start

```rust,no_run
# async fn doc() -> Result<(), oxitls_h2::H2Error> {
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use oxitls_h2::h2_client_handshake;

// `tls` is a connected client TLS stream that negotiated ALPN "h2".
# let tls: TlsStream<TcpStream> = panic!();
let (mut send_req, conn) = h2_client_handshake(tls).await?;

// Drive the connection in a background task.
tokio::spawn(async move { let _ = conn.await; });

// `send_req` is an `h2::client::SendRequest` for opening streams.
# let _ = &mut send_req;
# Ok(())
# }
```

### Client builder with tuned settings

```rust,no_run
# use std::time::Duration;
# async fn doc() -> Result<(), oxitls_h2::H2Error> {
use tokio::io::duplex;
use oxitls_h2::H2ClientBuilder;

let (client_io, _server_io) = duplex(65536);
let (_send_req, _conn) = H2ClientBuilder::new()
    .with_max_concurrent_streams(100)
    .with_initial_window_size(1 << 20)   // 1 MiB
    .with_keepalive(Duration::from_secs(30))
    .handshake(client_io)
    .await?;
# Ok(())
# }
```

### Server builder

```rust,no_run
# async fn doc() -> Result<(), oxitls_h2::H2Error> {
use tokio::io::duplex;
use oxitls_h2::H2ServerBuilder;

let (_client_io, server_io) = duplex(65536);
let mut server_conn = H2ServerBuilder::new()
    .with_max_concurrent_streams(100)
    .accept(server_io)
    .await?;

while let Some(request) = server_conn.accept_request().await {
    let (_req, mut _respond) = request?;
    // handle the request …
}
# Ok(())
# }
```

## API Overview

### Handshake functions

All four are `async` and generic over the transport `S` (`AsyncRead + AsyncWrite + Unpin + Send + 'static`); each verifies the `h2` ALPN protocol first.

| Function | Description |
|----------|-------------|
| `h2_client_handshake(tls)` | Client handshake over a `tokio_rustls::client::TlsStream<S>` → `H2ClientHandshake` |
| `h2_server_handshake(tls)` | Server handshake over a `tokio_rustls::server::TlsStream<S>` → `H2ServerConnection` |
| `h2_client_handshake_with_settings(tls, &H2Settings)` | As above, applying custom [`H2Settings`] to the h2 client builder |
| `h2_server_handshake_with_settings(tls, &H2Settings)` | As above, applying custom [`H2Settings`] to the h2 server builder |

### `H2ClientBuilder`

Builder for an HTTP/2 client connection (`Debug`, `Clone`, `Default`). Configure, then call `handshake(io)` → `(h2::client::SendRequest<Bytes>, H2Connection<IO>)`.

| Method | Description |
|--------|-------------|
| `new()` | All settings at h2 defaults |
| `with_max_concurrent_streams(n)` | Max concurrent streams advertised |
| `with_initial_window_size(n)` | Stream-level flow-control window |
| `with_max_header_list_size(n)` | Max received header list size |
| `with_hpack_table_size(n)` | HPACK dynamic table size |
| `with_max_send_buffer_size(n)` | Max per-stream send buffer (bytes) |
| `with_keepalive(d)` | Enable keepalive pings at interval `d` |
| `handshake(io)` | Perform the handshake (async) |

### `H2ServerBuilder`

Builder for an HTTP/2 server connection (`Debug`, `Clone`, `Default`). Configure, then call `accept(io)` → `H2ServerConn<IO>`.

| Method | Description |
|--------|-------------|
| `new()` | All settings at h2 defaults |
| `with_max_concurrent_streams(n)` | Max concurrent streams allowed |
| `with_initial_window_size(n)` | Stream-level flow-control window |
| `with_max_header_list_size(n)` | Max received header list size |
| `with_hpack_table_size(n)` | HPACK dynamic table size |
| `with_max_send_buffer_size(n)` | Max per-stream send buffer (bytes) |
| `with_push_enabled(b)` | Stored for informational purposes (h2 push is driven by the client's `SETTINGS_ENABLE_PUSH`) |
| `with_keepalive(d)` | Store a keepalive interval (driven manually) |
| `accept(io)` | Perform the server handshake (async) |

### `H2Settings`

Plain settings struct (`Debug`, `Clone`, `Default`) used by the `*_with_settings` handshake functions. All fields are `Option<u32>`; `None` means "use the h2 default". Fluent setters mirror the field names.

| Field / setter | Meaning |
|----------------|---------|
| `initial_window_size` / `with_initial_window_size` | Initial stream flow-control window (bytes) |
| `max_frame_size` / `with_max_frame_size` | Max frame payload size; must be in `[16384, 16777215]` |
| `max_concurrent_streams` / `with_max_concurrent_streams` | Max concurrent streams per connection |
| `max_header_list_size` / `with_max_header_list_size` | Max header list size (bytes) |
| `header_table_size` / `with_header_table_size` | HPACK encoder dynamic table size (bytes) |
| `initial_connection_window_size` / `with_initial_connection_window_size` | Initial connection-level window (bytes) |

### Connection wrappers

| Type | Description |
|------|-------------|
| `H2Connection<IO>` | Managed client connection driving the raw `h2::client::Connection` in a background task (with optional keepalive) |
| `H2ServerConn<IO>` | Managed server connection exposing request acceptance |
| `StreamCounter` | `Arc<AtomicUsize>`-backed stream counter (`new`, `increment`, `decrement`, `get`); `Clone`, `Debug`, `Default` |

`H2Connection<IO>` methods:

| Method | Description |
|--------|-------------|
| `ping()` | Send a PING frame and return the measured RTT `Duration` |
| `stream_count()` | Number of currently active streams |
| `is_idle()` | True when there are no active streams |
| `graceful_shutdown(timeout)` | Await the driver task with a timeout (no GOAWAY API on the client side) |
| `abort()` | Abort the driver and any keepalive task immediately |

`H2ServerConn<IO>` methods:

| Method | Description |
|--------|-------------|
| `accept_request()` | Accept the next request → `Option<Result<(http::Request<h2::RecvStream>, h2::server::SendResponse<Bytes>), H2Error>>`; `None` after clean close |
| `graceful_shutdown()` | Send a GOAWAY frame to the client |
| `has_streams()` | True if there are active streams |

### Flow control, priority, and server push

| Type | Description |
|------|-------------|
| `OxiFlowControl` | Thin wrapper over `h2::FlowControl` using `H2Error`. Methods: `new(inner)`, `available_capacity() -> isize`, `used_capacity() -> usize`, `release_capacity(n)` |
| `StreamPriority` | PRIORITY-frame parameters (`dependency: u32`, `exclusive: bool`, `weight: u8`); `new(...)`, `Default` (`weight = 16`) |
| `H2ServerPush` | Wrapper over `h2::server::SendResponse` exposing `push(http::Request<()>) -> H2PushedStream`, `into_inner()` |
| `H2PushedStream` | Handle to send the pushed response via `send_response(http::Response<()>, end_of_stream)` |

### Type aliases

| Alias | Definition |
|-------|------------|
| `H2ClientHandshake<S>` | `(h2::client::SendRequest<Bytes>, h2::client::Connection<S, Bytes>)` |
| `H2ServerConnection<S>` | `h2::server::Connection<S, Bytes>` |
| `TcpH2ClientHandshake` | `H2ClientHandshake<tokio_rustls::client::TlsStream<TcpStream>>` |
| `TcpH2ServerConnection` | `H2ServerConnection<tokio_rustls::server::TlsStream<TcpStream>>` |

### Re-exports

`h2::Reason` is re-exported for convenience (used by [`H2Error::StreamReset`]).

### `comparison` module

Documentation-only module comparing HTTP/2 (this crate) with HTTP/3 (`oxiquic-h3`), including a feature matrix, an API-symmetry mapping table, and a migration checklist. Exposes one type alias, `H2Builder` (= [`H2ClientBuilder`]), to emphasise the H2↔H3 mapping.

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `default` | — | Empty (no optional features) |

## `H2Error` variants

`H2Error` implements `Debug`, `Display`, `std::error::Error` (with `source()`), and `From<h2::Error>` / `From<std::io::Error>`. A `From<H2Error> for oxitls_core::TlsError` conversion bridges into the core error type. The `From<h2::Error>` impl automatically maps reset errors to `StreamReset(reason)`.

| Variant | Description |
|---------|-------------|
| `AlpnNotH2(String)` | The TLS stream did not negotiate the `h2` ALPN protocol |
| `H2(h2::Error)` | An error returned by the [`h2`] crate |
| `Io(std::io::Error)` | An I/O error |
| `GracefulShutdownTimeout` | Graceful shutdown timed out before the connection drained |
| `Settings(String)` | A settings or configuration error |
| `StreamReset(h2::Reason)` | The stream was reset by the peer with the given reason code |
| `Timeout` | A ping or keepalive operation timed out |

Predicate helpers: `is_alpn_not_h2()`, `is_h2()`, `is_io()`, `is_graceful_shutdown_timeout()`, `is_stream_reset()`, `is_timeout()` (true for `Timeout` **and** `GracefulShutdownTimeout`).

## Cross-references

- **`oxitls`** — the façade; enable this crate via the `h2` feature.
- **`oxitls-core`** — defines [`TlsError`], into which `H2Error` converts.
- **`oxitls-adapter-rustls-rustcrypto`** — the Pure-Rust provider used to establish the underlying TLS stream (and the ALPN `h2` advertisement).
- **`oxitls-rcgen`** — generate the certificates used in the TLS handshake.

## License

Apache-2.0 — COOLJAPAN OU (Team Kitasan)
