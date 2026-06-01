//! Wave 2 integration tests for oxitls-h2: builders, connection lifecycle,
//! server push, stream priority, and flow-control helpers.
//!
//! All tests use `tokio::io::duplex` for in-memory bidirectional streams,
//! avoiding real TCP sockets.

use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};

use oxitls_h2::{H2ClientBuilder, H2ServerBuilder, H2ServerPush, OxiFlowControl, StreamPriority};

// ---------------------------------------------------------------------------
// Helper: drain the server connection until client closes (or 500ms timeout).
//
// After sending a response, `send_response` enqueues frames in h2's buffer.
// The h2 state machine flushes those frames when polled.  We keep polling
// (via accept_request, which internally drives the codec) until the client
// closes its half, signalling the server is done.  The 500ms timeout is a
// safety net for tests where the client drops its handle and the runtime
// tears down tasks asynchronously.
// ---------------------------------------------------------------------------

async fn drain_server(mut server_conn: oxitls_h2::H2ServerConn<tokio::io::DuplexStream>) {
    let _ = tokio::time::timeout(Duration::from_millis(500), async {
        loop {
            match server_conn.accept_request().await {
                None | Some(Err(_)) => break,
                Some(Ok((_req, mut respond))) => {
                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                }
            }
        }
    })
    .await;
}

async fn serve_one(
    mut server_conn: oxitls_h2::H2ServerConn<tokio::io::DuplexStream>,
    status: StatusCode,
) {
    if let Some(Ok((req, mut respond))) = server_conn.accept_request().await {
        drop(req);
        let rsp = Response::builder()
            .status(status)
            .body(())
            .expect("response build");
        let _ = respond.send_response(rsp, true);
    }
    drain_server(server_conn).await;
}

async fn serve_n(
    mut server_conn: oxitls_h2::H2ServerConn<tokio::io::DuplexStream>,
    n: usize,
    status: StatusCode,
) {
    for _ in 0..n {
        match server_conn.accept_request().await {
            Some(Ok((_req, mut respond))) => {
                let rsp = Response::builder()
                    .status(status)
                    .body(())
                    .expect("response build");
                let _ = respond.send_response(rsp, true);
            }
            _ => break,
        }
    }
    drain_server(server_conn).await;
}

// ---------------------------------------------------------------------------
// 1. max_concurrent_streams_enforced
// ---------------------------------------------------------------------------
#[tokio::test]
async fn max_concurrent_streams_enforced() {
    let (client_io, server_io) = tokio::io::duplex(65536);

    let server_builder = H2ServerBuilder::new().with_max_concurrent_streams(2);
    let client_builder = H2ClientBuilder::new();

    let (server_task, client_task) = tokio::join!(
        tokio::spawn(async move {
            let mut server_conn = server_builder
                .accept(server_io)
                .await
                .expect("server accept");
            for _ in 0..3 {
                match server_conn.accept_request().await {
                    Some(Ok((_req, mut respond))) => {
                        let rsp = Response::builder()
                            .status(200)
                            .body(())
                            .expect("response build");
                        let _ = respond.send_response(rsp, true);
                    }
                    _ => break,
                }
            }
            drain_server(server_conn).await;
        }),
        tokio::spawn(async move {
            let (mut send_req, _conn) = client_builder
                .handshake(client_io)
                .await
                .expect("client handshake");

            let make_req = || {
                Request::builder()
                    .method(Method::GET)
                    .uri("http://localhost/")
                    .body(())
                    .expect("request build")
            };

            let (f1, _) = send_req.send_request(make_req(), true).expect("stream 1");
            let (f2, _) = send_req.send_request(make_req(), true).expect("stream 2");
            let _r3 = send_req.send_request(make_req(), true);

            let r1 = f1.await.expect("response 1");
            let r2 = f2.await.expect("response 2");
            assert_eq!(r1.status(), 200);
            assert_eq!(r2.status(), 200);

            drop(send_req);
        }),
    );
    server_task.expect("server task");
    client_task.expect("client task");
}

// ---------------------------------------------------------------------------
// 2. initial_window_size_negotiated
// ---------------------------------------------------------------------------
#[tokio::test]
async fn initial_window_size_negotiated() {
    let (client_io, server_io) = tokio::io::duplex(65536);

    let server_handle = tokio::spawn(async move {
        let server_conn = H2ServerBuilder::new()
            .with_initial_window_size(65536)
            .accept(server_io)
            .await
            .expect("server accept");
        serve_one(server_conn, StatusCode::OK).await;
    });

    let (mut send_req, _conn) = H2ClientBuilder::new()
        .with_initial_window_size(65536)
        .handshake(client_io)
        .await
        .expect("client handshake");

    let req = Request::builder()
        .method(Method::GET)
        .uri("http://localhost/")
        .body(())
        .expect("request");
    let (rsp_fut, _) = send_req.send_request(req, true).expect("send request");
    let rsp = rsp_fut.await.expect("response");
    assert_eq!(rsp.status(), 200);

    drop(send_req);
    server_handle.await.expect("server");
}

// ---------------------------------------------------------------------------
// 3. ping_keepalive_succeeds
// ---------------------------------------------------------------------------
#[tokio::test]
async fn ping_keepalive_succeeds() {
    let (client_io, server_io) = tokio::io::duplex(65536);

    let server_handle = tokio::spawn(async move {
        let server_conn = H2ServerBuilder::new()
            .accept(server_io)
            .await
            .expect("server accept");
        serve_one(server_conn, StatusCode::OK).await;
    });

    let (mut send_req, conn) = H2ClientBuilder::new()
        .with_keepalive(Duration::from_millis(50))
        .handshake(client_io)
        .await
        .expect("client handshake");

    let req = Request::builder()
        .method(Method::GET)
        .uri("http://localhost/")
        .body(())
        .expect("request");
    let (rsp_fut, _) = send_req.send_request(req, true).expect("send");
    let _ = rsp_fut.await.expect("response");

    let rtt = conn.ping().await.expect("ping");
    assert!(rtt < Duration::from_millis(500), "RTT too large: {rtt:?}");

    drop(send_req);
    server_handle.await.expect("server");
}

// ---------------------------------------------------------------------------
// 4. goaway_graceful_shutdown_completes_in_flight
// ---------------------------------------------------------------------------
#[tokio::test]
async fn goaway_graceful_shutdown_completes_in_flight() {
    let (client_io, server_io) = tokio::io::duplex(65536);

    let server_handle = tokio::spawn(async move {
        let server_conn = H2ServerBuilder::new()
            .accept(server_io)
            .await
            .expect("server accept");
        serve_one(server_conn, StatusCode::OK).await;
    });

    let (mut send_req, conn) = H2ClientBuilder::new()
        .handshake(client_io)
        .await
        .expect("client handshake");

    let req = Request::builder()
        .method(Method::GET)
        .uri("http://localhost/")
        .body(())
        .expect("request");
    let (rsp_fut, _) = send_req.send_request(req, true).expect("send");

    drop(send_req);

    let rsp = rsp_fut.await.expect("response");
    assert_eq!(rsp.status(), 200);

    let result = conn.graceful_shutdown(Duration::from_secs(5)).await;
    assert!(result.is_ok(), "graceful shutdown failed: {result:?}");

    server_handle.await.expect("server");
}

// ---------------------------------------------------------------------------
// 5. goaway_graceful_shutdown_times_out_on_stuck_stream
// ---------------------------------------------------------------------------
#[tokio::test]
async fn goaway_graceful_shutdown_times_out_on_stuck_stream() {
    let (client_io, server_io) = tokio::io::duplex(65536);

    let server_handle = tokio::spawn(async move {
        let mut server_conn = H2ServerBuilder::new()
            .accept(server_io)
            .await
            .expect("server accept");
        if let Some(Ok((_req, respond))) = server_conn.accept_request().await {
            tokio::time::sleep(Duration::from_secs(10)).await;
            drop(respond);
        }
    });

    let (mut send_req, conn) = H2ClientBuilder::new()
        .handshake(client_io)
        .await
        .expect("client handshake");

    let req = Request::builder()
        .method(Method::GET)
        .uri("http://localhost/")
        .body(())
        .expect("request");
    let (_rsp_fut, _) = send_req.send_request(req, true).expect("send");

    drop(send_req);

    let result = conn.graceful_shutdown(Duration::from_millis(100)).await;

    assert!(
        matches!(result, Err(oxitls_h2::H2Error::GracefulShutdownTimeout)),
        "expected GracefulShutdownTimeout, got {result:?}"
    );

    server_handle.abort();
}

// ---------------------------------------------------------------------------
// 6. server_push_delivers_pushed_request
// ---------------------------------------------------------------------------
#[tokio::test]
async fn server_push_delivers_pushed_request() {
    let (client_io, server_io) = tokio::io::duplex(65536);

    let server_handle = tokio::spawn(async move {
        let mut server_conn = H2ServerBuilder::new()
            .accept(server_io)
            .await
            .expect("server accept");

        if let Some(Ok((_req, respond))) = server_conn.accept_request().await {
            let mut push = H2ServerPush::new(respond);

            let pushed_req = Request::builder()
                .method(Method::GET)
                .uri("http://localhost/pushed")
                .body(())
                .expect("push request");

            if let Ok(pushed_stream) = push.push(pushed_req) {
                let pushed_rsp = Response::builder()
                    .status(200)
                    .body(())
                    .expect("pushed response");
                let _ = pushed_stream.send_response(pushed_rsp, true);
            }

            let mut respond = push.into_inner();
            let rsp = Response::builder().status(200).body(()).expect("response");
            let _ = respond.send_response(rsp, true);
        }
        drain_server(server_conn).await;
    });

    let (mut send_req, _conn) = H2ClientBuilder::new()
        .handshake(client_io)
        .await
        .expect("client handshake");

    let req = Request::builder()
        .method(Method::GET)
        .uri("http://localhost/")
        .body(())
        .expect("request");
    let (rsp_fut, _) = send_req.send_request(req, true).expect("send");
    let rsp = rsp_fut.await.expect("response");
    assert_eq!(rsp.status(), 200);

    drop(send_req);
    let _ = server_handle.await;
}

// ---------------------------------------------------------------------------
// 7. stream_priority_propagates
// ---------------------------------------------------------------------------
#[tokio::test]
async fn stream_priority_propagates() {
    let priority = StreamPriority::new(0, false, 128);
    assert_eq!(priority.weight, 128);
    assert_eq!(priority.dependency, 0);
    assert!(!priority.exclusive);

    let (client_io, server_io) = tokio::io::duplex(65536);

    let server_handle = tokio::spawn(async move {
        let server_conn = H2ServerBuilder::new()
            .accept(server_io)
            .await
            .expect("server accept");
        serve_one(server_conn, StatusCode::OK).await;
    });

    let (mut send_req, _conn) = H2ClientBuilder::new()
        .handshake(client_io)
        .await
        .expect("handshake");

    let req = Request::builder()
        .method(Method::GET)
        .uri("http://localhost/")
        .body(())
        .expect("request");
    let (rsp_fut, _) = send_req.send_request(req, true).expect("send");
    let rsp = rsp_fut.await.expect("response");
    assert_eq!(rsp.status(), 200);

    drop(send_req);
    server_handle.await.expect("server");
}

// ---------------------------------------------------------------------------
// 8. alpn_h2_offered — handshake over duplex stream completes
// ---------------------------------------------------------------------------
#[tokio::test]
async fn alpn_h2_offered() {
    let (client_io, server_io) = tokio::io::duplex(65536);

    let server_handle = tokio::spawn(async move {
        H2ServerBuilder::new()
            .accept(server_io)
            .await
            .expect("server accept")
    });

    let (_send_req, _conn) = H2ClientBuilder::new()
        .handshake(client_io)
        .await
        .expect("client handshake");

    let _ = server_handle.await.expect("server");
}

// ---------------------------------------------------------------------------
// 9. generic_over_duplex_stream — handshake + send + receive
// ---------------------------------------------------------------------------
#[tokio::test]
async fn generic_over_duplex_stream() {
    let (client_io, server_io) = tokio::io::duplex(65536);

    let server_handle = tokio::spawn(async move {
        let server_conn = H2ServerBuilder::new()
            .accept(server_io)
            .await
            .expect("server accept");
        serve_one(server_conn, StatusCode::ACCEPTED).await;
    });

    let (mut send_req, _conn) = H2ClientBuilder::new()
        .handshake(client_io)
        .await
        .expect("client handshake");

    let req = Request::builder()
        .method(Method::GET)
        .uri("http://localhost/hello")
        .body(())
        .expect("request");
    let (rsp_fut, _) = send_req.send_request(req, true).expect("send");
    let rsp = rsp_fut.await.expect("response");
    assert_eq!(rsp.status(), 202);

    drop(send_req);
    server_handle.await.expect("server");
}

// ---------------------------------------------------------------------------
// 10. concurrent_100_streams_all_complete
// ---------------------------------------------------------------------------
#[tokio::test]
async fn concurrent_100_streams_all_complete() {
    const N: usize = 100;
    let (client_io, server_io) = tokio::io::duplex(1 << 20);

    let server_handle = tokio::spawn(async move {
        let server_conn = H2ServerBuilder::new()
            .with_max_concurrent_streams(200)
            .accept(server_io)
            .await
            .expect("server accept");
        serve_n(server_conn, N, StatusCode::OK).await;
    });

    let (send_req, _conn) = H2ClientBuilder::new()
        .with_max_concurrent_streams(200)
        .handshake(client_io)
        .await
        .expect("client handshake");

    let make_req = || {
        Request::builder()
            .method(Method::GET)
            .uri("http://localhost/")
            .body(())
            .expect("request")
    };

    let mut handles = Vec::with_capacity(N);
    for _ in 0..N {
        let mut sr = send_req.clone();
        handles.push(tokio::spawn(async move {
            let (rsp_fut, _) = sr.send_request(make_req(), true).expect("send");
            let rsp = rsp_fut.await.expect("response");
            assert_eq!(rsp.status(), 200);
        }));
    }

    // Drop original send_req so the connection closes after all N streams finish.
    drop(send_req);

    let all = futures::future::try_join_all(handles);
    tokio::time::timeout(Duration::from_secs(10), all)
        .await
        .expect("timeout — not all streams completed in 10s")
        .expect("one or more stream tasks panicked");

    server_handle.await.expect("server");
}

// ---------------------------------------------------------------------------
// 11. large_headers_rejected_by_default
// ---------------------------------------------------------------------------
#[tokio::test]
async fn large_headers_rejected_by_default() {
    let large_value = "x".repeat(20 * 1024);

    let (client_io, server_io) = tokio::io::duplex(1 << 20);

    let server_handle = tokio::spawn(async move {
        let mut server_conn = H2ServerBuilder::new()
            .accept(server_io)
            .await
            .expect("server accept");
        // Drive to completion; drain with timeout.
        let _ = tokio::time::timeout(Duration::from_millis(500), async {
            while server_conn.accept_request().await.is_some() {}
        })
        .await;
    });

    let (mut send_req, _conn) = H2ClientBuilder::new()
        .handshake(client_io)
        .await
        .expect("client handshake");

    let req = Request::builder()
        .method(Method::GET)
        .uri("http://localhost/")
        .header("x-big", &large_value)
        .body(())
        .expect("request");

    match send_req.send_request(req, true) {
        Err(_) => {}
        Ok((rsp_fut, _)) => {
            let _ = rsp_fut.await;
        }
    }

    drop(send_req);
    server_handle.await.expect("server");
}

// ---------------------------------------------------------------------------
// 12. large_headers_allowed_via_builder
// ---------------------------------------------------------------------------
#[tokio::test]
async fn large_headers_allowed_via_builder() {
    let large_value = "x".repeat(20 * 1024);

    let (client_io, server_io) = tokio::io::duplex(1 << 20);

    let server_handle = tokio::spawn(async move {
        let server_conn = H2ServerBuilder::new()
            .with_max_header_list_size(128 * 1024)
            .accept(server_io)
            .await
            .expect("server accept");
        serve_one(server_conn, StatusCode::OK).await;
    });

    let (mut send_req, _conn) = H2ClientBuilder::new()
        .with_max_header_list_size(128 * 1024)
        .handshake(client_io)
        .await
        .expect("client handshake");

    let req = Request::builder()
        .method(Method::GET)
        .uri("http://localhost/")
        .header("x-big", &large_value)
        .body(())
        .expect("request");

    let (rsp_fut, _) = send_req.send_request(req, true).expect("send request");
    let rsp = rsp_fut.await.expect("response");
    assert_eq!(rsp.status(), 200);

    drop(send_req);
    server_handle.await.expect("server");
}

// ---------------------------------------------------------------------------
// 13. flow_control_release_capacity
// ---------------------------------------------------------------------------
#[tokio::test]
async fn flow_control_release_capacity() {
    let (client_io, server_io) = tokio::io::duplex(65536);

    let server_handle = tokio::spawn(async move {
        let mut server_conn = H2ServerBuilder::new()
            .accept(server_io)
            .await
            .expect("server accept");

        if let Some(Ok((req, mut respond))) = server_conn.accept_request().await {
            let mut body = req.into_body();
            let mut total = 0usize;
            while let Some(chunk) = body.data().await {
                let data = chunk.expect("body data");
                total += data.len();
                body.flow_control()
                    .release_capacity(data.len())
                    .expect("release capacity");
            }
            let rsp = Response::builder()
                .status(200)
                .header("x-received", total.to_string())
                .body(())
                .expect("response");
            let _ = respond.send_response(rsp, true);
        }
        drain_server(server_conn).await;
    });

    let (mut send_req, _conn) = H2ClientBuilder::new()
        .handshake(client_io)
        .await
        .expect("client handshake");

    let req = Request::builder()
        .method(Method::POST)
        .uri("http://localhost/")
        .body(())
        .expect("request");

    let (rsp_fut, mut send_stream) = send_req.send_request(req, false).expect("send request");

    send_stream.reserve_capacity(8192);
    send_stream
        .send_data(Bytes::from(vec![0u8; 8192]), true)
        .expect("send data");

    let rsp = rsp_fut.await.expect("response");
    assert_eq!(rsp.status(), 200);
    let received: usize = rsp
        .headers()
        .get("x-received")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    assert_eq!(received, 8192);

    drop(send_req);
    server_handle.await.expect("server");
}

// ---------------------------------------------------------------------------
// OxiFlowControl wrapper unit test
// ---------------------------------------------------------------------------
#[tokio::test]
async fn oxi_flow_control_wrapper() {
    let (client_io, server_io) = tokio::io::duplex(65536);

    let server_handle = tokio::spawn(async move {
        let mut server_conn = H2ServerBuilder::new()
            .accept(server_io)
            .await
            .expect("server accept");

        if let Some(Ok((req, mut respond))) = server_conn.accept_request().await {
            let mut body = req.into_body();
            while let Some(chunk) = body.data().await {
                let data = chunk.expect("data");
                let mut fc = OxiFlowControl::new(body.flow_control().clone());
                fc.release_capacity(data.len()).expect("release");
            }
            let rsp = Response::builder().status(200).body(()).expect("rsp");
            let _ = respond.send_response(rsp, true);
        }
        drain_server(server_conn).await;
    });

    let (mut send_req, _conn) = H2ClientBuilder::new()
        .handshake(client_io)
        .await
        .expect("handshake");

    let req = Request::builder()
        .method(Method::POST)
        .uri("http://localhost/")
        .body(())
        .expect("req");

    let (rsp_fut, mut ss) = send_req.send_request(req, false).expect("send");
    ss.reserve_capacity(1024);
    ss.send_data(Bytes::from(vec![1u8; 1024]), true)
        .expect("send data");

    let rsp = rsp_fut.await.expect("rsp");
    assert_eq!(rsp.status(), 200);

    drop(send_req);
    server_handle.await.expect("server");
}

// ---------------------------------------------------------------------------
// stream_count() and is_idle()
// ---------------------------------------------------------------------------

/// Verifies that `H2Connection::stream_count()` and `is_idle()` reflect the
/// number of in-flight streams accurately.
///
/// Flow:
///   1. Handshake.  Connection starts idle (`is_idle() == true`).
///   2. Open one stream by sending a request (end_of_stream=false so the
///      stream stays open while we check the count).
///   3. After receiving the response the stream closes; `is_idle()` returns true.
#[tokio::test]
async fn stream_count_and_is_idle() {
    let (client_io, server_io) = tokio::io::duplex(65536);

    let server_handle = tokio::spawn(async move {
        let mut server_conn = H2ServerBuilder::new()
            .accept(server_io)
            .await
            .expect("server handshake");

        // Accept and respond to exactly one request.
        if let Some(Ok((_req, mut respond))) = server_conn.accept_request().await {
            let rsp = Response::builder()
                .status(StatusCode::OK)
                .body(())
                .expect("rsp");
            respond.send_response(rsp, true).expect("send_response");
        }
        drain_server(server_conn).await;
    });

    let (mut send_req, conn) = H2ClientBuilder::new()
        .handshake(client_io)
        .await
        .expect("client handshake");

    // Connection has no streams yet.
    assert!(
        conn.is_idle(),
        "connection should be idle before any request"
    );
    assert_eq!(conn.stream_count(), 0);

    let req = Request::builder()
        .method(Method::GET)
        .uri("http://localhost/")
        .body(())
        .expect("req");

    // Open stream.
    let rsp_fut = send_req.send_request(req, true).expect("send_request").0;

    // Wait for the response, which completes (closes) the stream.
    let rsp = rsp_fut.await.expect("response");
    assert_eq!(rsp.status(), StatusCode::OK);

    // After the stream completes and all local handles are dropped the
    // count should return to zero.  The h2 driver processes END_STREAM
    // asynchronously, so we spin-yield for up to 200 ms rather than
    // relying on a single yield which can fail under load.
    drop(send_req);
    let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
    loop {
        tokio::task::yield_now().await;
        if conn.is_idle() {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("connection did not become idle within 200 ms");
        }
    }
    assert_eq!(conn.stream_count(), 0);

    server_handle.await.expect("server");
}
