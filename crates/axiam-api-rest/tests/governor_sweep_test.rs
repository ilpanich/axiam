//! #673 (R110W2-05): the in-process governors' maps are swept.
//!
//! Its own test binary, with one test: the sweep registry is process-global, so
//! a second test building governors beside this one would change the counts.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use actix_web::{App, HttpResponse, test, web};
use axiam_api_rest::build_governor;
use axiam_core::limiter_sweep::sweep_all;

#[actix_rt::test]
async fn a_map_that_saw_n_distinct_keys_holds_none_after_a_sweep() {
    // 60 000 a minute replenishes a cell in a millisecond.
    let app = test::init_service(
        App::new().service(
            web::resource("/")
                .wrap(build_governor(60_000))
                .route(web::get().to(|| async { HttpResponse::Ok().finish() })),
        ),
    )
    .await;

    const N: u8 = 200;
    for i in 0..N {
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, i)), 4000);
        let req = test::TestRequest::get()
            .uri("/")
            .peer_addr(peer)
            .to_request();
        assert!(test::call_service(&app, req).await.status().is_success());
    }
    let before = sweep_all();
    assert_eq!(before.limiters, 1, "the one governor is registered");

    tokio::time::sleep(Duration::from_millis(50)).await;
    let after = sweep_all();
    assert_eq!(after.cells, 0, "{N} replenished cells are not kept");

    // The registry does not keep a map alive: dropping the app drops it.
    drop(app);
    assert_eq!(sweep_all().limiters, 0);
}
