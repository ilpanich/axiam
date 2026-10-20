//! #673 (R110W2-05): the gRPC in-process governor's map is swept.
//!
//! Its own test binary, with one test: the sweep registry is process-global, so
//! a second test building governors beside this one would change the counts.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use axiam_api_grpc::middleware::rate_limit::build_grpc_governor_layer;
use axiam_core::limiter_sweep::sweep_all;
use tonic::body::Body;
use tonic::transport::server::TcpConnectInfo;
use tower::{Layer, Service, ServiceExt, service_fn};

#[tokio::test]
async fn a_map_that_saw_n_distinct_peers_holds_none_after_a_sweep() {
    // 100 000 a second replenishes a cell in ten microseconds.
    let layer = build_grpc_governor_layer(100_000);
    let mut service = layer.layer(service_fn(|_: http::Request<Body>| async {
        Ok::<_, Infallible>(http::Response::new(Body::empty()))
    }));

    const N: u8 = 200;
    for i in 0..N {
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, i)), 4000);
        let mut req = http::Request::new(Body::empty());
        req.extensions_mut().insert(TcpConnectInfo {
            local_addr: None,
            remote_addr: Some(peer),
        });
        let response = service.ready().await.unwrap().call(req).await.unwrap();
        assert!(response.status().is_success(), "peer {peer} is admitted");
    }
    let before = sweep_all();
    assert_eq!(before.limiters, 1, "the one governor is registered");

    tokio::time::sleep(Duration::from_millis(50)).await;
    let after = sweep_all();
    assert_eq!(after.limiters, 1, "the limiter is alive while its layer is");
    assert_eq!(after.cells, 0, "{N} replenished cells are not kept");

    // The registry does not keep a map alive: dropping the layer and the
    // service built from it drops the limiter.
    drop(service);
    drop(layer);
    assert_eq!(sweep_all().limiters, 0);
}
