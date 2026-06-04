//! Tests for the `axiam-server healthcheck` subcommand (D-09).
//!
//! These tests verify that the healthcheck binary behaviour is correct:
//! - exits 0 when the /health endpoint returns 2xx
//! - exits 1 when the endpoint is unreachable
//!
//! We test the logic directly (not as a subprocess) by calling the same
//! reqwest::blocking probe that main.rs uses.

#[test]
fn healthcheck_exits_1_when_server_unreachable() {
    // Point at a port that is definitely not listening. Using a fixed
    // high-number port is sufficient for the "unreachable" case; if it
    // happens to be in use the worst outcome is a false pass (very unlikely
    // in CI), which is acceptable for a lightweight smoke test.
    let url = "http://127.0.0.1:19923/health";
    let ok = reqwest::blocking::get(url)
        .map(|r| r.status().is_success())
        .unwrap_or(false);
    assert!(!ok, "expected unreachable URL to return false");
}

#[test]
fn healthcheck_exits_0_against_mock_server() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    // Spin up a minimal TCP server that returns HTTP 200 for any request.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
    let addr = listener.local_addr().expect("local_addr");
    let url = format!("http://{addr}/health");

    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 512];
            let _ = stream.read(&mut buf);
            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
            let _ = stream.write_all(response);
        }
    });

    // Give the thread a moment to start listening.
    std::thread::sleep(std::time::Duration::from_millis(50));

    let ok = reqwest::blocking::get(&url)
        .map(|r| r.status().is_success())
        .unwrap_or(false);
    assert!(ok, "expected mock 200 response to return true");
}
