//! #733 (R111W2-03 (b)): each of the four per-family governors the server
//! builds is registered with the sweep, and each one's map empties.
//!
//! `governor_sweep_test.rs` proves it for one `build_grpc_governor_layer`; this
//! proves it for `build_grpc_method_scoped_governor_layer`, which calls it four
//! times, so a family whose registration were dropped would be caught. Its own
//! test binary, with one test: the sweep registry is process-global, so a
//! second test building governors beside this one would change the counts.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use axiam_api_grpc::middleware::rate_limit::{
    GrpcMethodFamily, GrpcRateLimits, build_grpc_method_scoped_governor_layer,
};
use axiam_core::limiter_sweep::sweep_all;
use tonic::body::Body;
use tonic::transport::server::TcpConnectInfo;
use tower::{Layer, Service, ServiceExt, service_fn};

/// One path per family, as `GrpcMethodFamily::classify` reads them.
const PATHS: [(&str, GrpcMethodFamily); 4] = [
    (
        "/axiam.v1.AuthorizationService/CheckAccess",
        GrpcMethodFamily::AuthzCheck,
    ),
    (
        "/axiam.v1.UserInfoService/GetUserInfo",
        GrpcMethodFamily::IdentityRead,
    ),
    ("/axiam.v1.UserService/GetUser", GrpcMethodFamily::Admin),
    ("/grpc.health.v1.Health/Check", GrpcMethodFamily::Infra),
];

#[tokio::test]
async fn every_family_governor_is_registered_and_each_map_empties() {
    for (path, family) in PATHS {
        assert_eq!(GrpcMethodFamily::classify(path), family, "{path}");
    }

    // 100 000 a second replenishes a cell in ten microseconds. The infra
    // family's ceiling is fixed and lower, but is still replenished well within
    // the sleep below.
    let layer = build_grpc_method_scoped_governor_layer(GrpcRateLimits {
        authz_per_sec: 100_000,
        identity_per_sec: 100_000,
        admin_per_sec: 100_000,
    });
    let mut service = layer.layer(service_fn(|_: http::Request<Body>| async {
        Ok::<_, Infallible>(http::Response::new(Body::empty()))
    }));

    const N: u8 = 50;
    for (path, family) in PATHS {
        for i in 0..N {
            let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, i)), 4000);
            let mut req = http::Request::builder()
                .uri(path)
                .body(Body::empty())
                .unwrap();
            req.extensions_mut().insert(TcpConnectInfo {
                local_addr: None,
                remote_addr: Some(peer),
            });
            let response = service.ready().await.unwrap().call(req).await.unwrap();
            assert!(
                response.status().is_success(),
                "{family:?}: peer {peer} is admitted"
            );
        }
    }

    // A sweep right after the requests may already find cells replenished, so
    // the count of cells is asserted only after the pause; the number of
    // limiters is what the registrations contribute.
    tokio::time::sleep(Duration::from_millis(250)).await;
    let after = sweep_all();
    assert_eq!(
        after.limiters, 4,
        "one limiter per family is registered and alive while its layer is"
    );
    assert_eq!(
        after.cells, 0,
        "{N} peers per family, all replenished, are not kept"
    );

    drop(service);
    drop(layer);
    assert_eq!(sweep_all().limiters, 0, "the registry keeps no map alive");
}
