//! Drain the request body of a call that a layer above tonic rejected outright.
//!
//! # The bug this exists to prevent (h2 `GOAWAY: ENHANCE_YOUR_CALM`)
//!
//! The rate-limit layers on this listener reject by returning a
//! `RESOURCE_EXHAUSTED` response and **dropping the request** — they never read
//! its body, because they never need it. That is the natural way to write a
//! short-circuiting `tower` layer, and on HTTP/1.1 it would be harmless.
//!
//! On HTTP/2 it is not, because of how `h2` defends itself against DATA-frame
//! floods (the CVE-2019-9513 family). Every inbound DATA frame smaller than
//! `DEFAULT_DATA_FRAME_OVERHEAD_THRESHOLD` (256 B) charges the difference
//! against a per-connection budget of `256 * 100 = 25_600`, and that budget is
//! replenished **only** when the application actually reads the frame
//! (`h2::proto::streams::Streams::poll_data` → `Counts::release_data_frame`).
//! A body that is dropped unread is never refunded.
//!
//! A unary gRPC request body is 5 bytes on the wire (one compression flag plus
//! a four-byte length, with an empty message), so each rejected call costs
//! `256 - 5 = 251` and the budget is gone after `25_600 / 251 = 102` of them.
//! At that point `h2` concludes it is being flooded and kills the whole
//! connection with `GOAWAY(ENHANCE_YOUR_CALM, "too_many_data_frames")`.
//!
//! The `grpc_infra` benchmark cell reproduces this exactly: rejected calls fail
//! with `UNAVAILABLE` at iteration 101, 203, 305, 407, … — one dead connection
//! every 102 rejections, like clockwork.
//!
//! # Why that is a real defect and not a benchmark artifact
//!
//! The listener is answering "you are over your quota" by destroying the
//! caller's connection, which is worse than the rejection itself in three ways:
//!
//!   - **Collateral damage.** HTTP/2 multiplexes, so the `GOAWAY` also kills
//!     every *unrelated* in-flight RPC on that connection. One throttled
//!     method takes down calls that were within their quota.
//!   - **It inverts the cost of rate limiting.** Each `GOAWAY` forces the
//!     client to reconnect, and on this listener that means a fresh TLS
//!     handshake — orders of magnitude more server CPU than the request that
//!     was refused. A cheap client-side flood against the unauthenticated
//!     infrastructure family (reflection / health, which carries the fixed
//!     `INFRA_PER_SEC` ceiling precisely because it is unauthenticated) becomes
//!     an amplified handshake load. The limiter turns into a DoS lever.
//!   - **It is indistinguishable from a server fault.** The client sees
//!     `UNAVAILABLE`, not `RESOURCE_EXHAUSTED`, so a correctly-throttled caller
//!     cannot tell "back off" from "this server is broken".
//!
//! # What this layer does
//!
//! It hands the inner stack a body that reads through a slot it keeps a handle
//! on. If the inner stack answers without consuming that body, the leftover is
//! drained here — which is exactly the `poll_data` that refunds `h2`'s budget.
//! On the admitted path the body has already been consumed by the time the
//! response resolves, so the drain finds nothing and costs a lock and a branch.
//!
//! # Why the drain is gated on a trailers-only response
//!
//! Draining is only correct when nobody else still wants the body. A response
//! that carries `grpc-status` in its **headers** is a trailers-only gRPC error,
//! which is the wire shape produced by `tonic::Status::into_http()` — the one
//! thing both rejection paths on this listener use (this crate's
//! `too_many_requests_response`, and `tower_governor`'s own
//! `From<GovernorError> for Response<tonic::body::Body>`). A request that tonic
//! actually routed answers with `grpc-status` in its *trailers* instead, so the
//! two cannot be confused.
//!
//! That distinction is what keeps this safe if a **streaming** method is ever
//! added. Every RPC on this surface is unary today, but for a client-streaming
//! or bidirectional call the handler goes on reading the request body *after*
//! the response future resolves. Draining unconditionally would consume that
//! stream out from under the handler and hang the call. Gating on the
//! trailers-only shape means this layer only ever touches a request that never
//! reached a handler at all.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use http::{Request, Response};
use http_body::{Body as HttpBody, Frame, SizeHint};
use http_body_util::BodyExt;
use tonic::body::Body;
use tower::{Layer, Service};

/// The request body, parked where [`DrainRejectedBody`] can reclaim whatever
/// the inner stack did not read. `None` means fully consumed.
type BodySlot = Arc<Mutex<Option<Body>>>;

/// Locks `slot`, recovering the guard if a previous holder panicked.
///
/// A poisoned lock here would mean some other task panicked mid-body; that is
/// not a reason to panic this task too, and the worst case is that a body is
/// drained twice (a no-op) or not at all (the pre-existing behaviour).
fn lock(slot: &BodySlot) -> std::sync::MutexGuard<'_, Option<Body>> {
    slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A body that reads through a [`BodySlot`], so the layer keeps a handle on
/// whatever is left when the inner stack drops the request.
struct SlotBody {
    slot: BodySlot,
}

impl HttpBody for SlotBody {
    type Data = bytes::Bytes;
    type Error = tonic::Status;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        // `SlotBody` holds only an `Arc`, so it is `Unpin` and the inner body
        // can be polled in place.
        let mut guard = lock(&self.get_mut().slot);
        let Some(inner) = guard.as_mut() else {
            return Poll::Ready(None);
        };
        let polled = Pin::new(inner).poll_frame(cx);
        // End of stream: empty the slot so the drain below knows there is
        // nothing owing, and so a second poll cannot touch a finished body.
        if matches!(polled, Poll::Ready(None)) {
            *guard = None;
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        lock(&self.slot)
            .as_ref()
            .is_none_or(HttpBody::is_end_stream)
    }

    fn size_hint(&self) -> SizeHint {
        lock(&self.slot)
            .as_ref()
            .map_or_else(|| SizeHint::with_exact(0), HttpBody::size_hint)
    }
}

/// Whether `res` is a trailers-only gRPC response — i.e. one produced without
/// the request ever reaching a handler. See the module docs for why this is
/// the gate.
fn is_trailers_only(res: &Response<Body>) -> bool {
    res.headers().contains_key("grpc-status")
}

/// [`Layer`] producing [`DrainRejectedBody`].
#[derive(Clone, Copy, Debug, Default)]
pub struct DrainRejectedBodyLayer;

impl<S> Layer<S> for DrainRejectedBodyLayer {
    type Service = DrainRejectedBody<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DrainRejectedBody { inner }
    }
}

/// Drains the request body of any call answered without reading it.
///
/// Wire this OUTSIDE the rate-limit layers — on `Server::builder()` that means
/// adding it FIRST, since tonic runs the first-added layer first.
#[derive(Clone, Debug)]
pub struct DrainRejectedBody<S> {
    inner: S,
}

impl<S> Service<Request<Body>> for DrainRejectedBody<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        // Standard clone-and-swap so the returned future owns a ready copy —
        // same convention as the rate-limit services on this listener.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        let (parts, body) = req.into_parts();
        let slot: BodySlot = Arc::new(Mutex::new(Some(body)));
        let req = Request::from_parts(parts, Body::new(SlotBody { slot: slot.clone() }));

        Box::pin(async move {
            let res = inner.call(req).await?;
            if is_trailers_only(&res) {
                // Bound in its own statement so the `MutexGuard` is dropped
                // here rather than living across the await below — holding it
                // would make this future `!Send`, which tonic requires.
                let unread = lock(&slot).take();
                if let Some(unread) = unread {
                    // Reading is the whole point: `poll_data` is what refunds
                    // `h2`'s small-DATA-frame budget. The bytes are discarded,
                    // and a body that errors mid-drain is ignored — the
                    // response is already decided and a failed drain must not
                    // change it.
                    let _ = unread.collect().await;
                }
            }
            Ok(res)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// A body that records whether it was ever polled to end-of-stream.
    struct ProbeBody {
        drained: Arc<AtomicBool>,
        frames: usize,
    }

    impl HttpBody for ProbeBody {
        type Data = bytes::Bytes;
        type Error = tonic::Status;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            if self.frames == 0 {
                self.drained.store(true, Ordering::SeqCst);
                return Poll::Ready(None);
            }
            self.frames -= 1;
            Poll::Ready(Some(Ok(Frame::data(bytes::Bytes::from_static(
                b"\0\0\0\0\0",
            )))))
        }
    }

    fn probe() -> (Arc<AtomicBool>, Body) {
        let drained = Arc::new(AtomicBool::new(false));
        let body = Body::new(ProbeBody {
            drained: drained.clone(),
            frames: 1,
        });
        (drained, body)
    }

    /// The inner service ignores the request body entirely, exactly as the
    /// rate-limit layers do when they reject.
    #[derive(Clone)]
    struct RejectUnread;

    impl Service<Request<Body>> for RejectUnread {
        type Response = Response<Body>;
        type Error = std::convert::Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: Request<Body>) -> Self::Future {
            drop(req); // the body is never read — this is the bug being fixed
            Box::pin(async {
                Ok(tonic::Status::resource_exhausted("rate limit exceeded").into_http())
            })
        }
    }

    /// An inner service that answers like a routed RPC: no `grpc-status`
    /// header, and it leaves the request body alone.
    #[derive(Clone)]
    struct RoutedUnread;

    impl Service<Request<Body>> for RoutedUnread {
        type Response = Response<Body>;
        type Error = std::convert::Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: Request<Body>) -> Self::Future {
            drop(req);
            Box::pin(async { Ok(Response::new(Body::empty())) })
        }
    }

    #[tokio::test]
    async fn drains_the_body_of_a_rejected_call() {
        let (drained, body) = probe();
        let mut svc = DrainRejectedBodyLayer.layer(RejectUnread);
        let res = svc.call(Request::new(body)).await.unwrap();

        assert_eq!(res.headers().get("grpc-status").unwrap(), "8");
        assert!(
            drained.load(Ordering::SeqCst),
            "a rejected call's body must be read to end-of-stream, or h2's \
             small-DATA-frame budget is never refunded and the connection dies \
             after ~102 rejections"
        );
    }

    #[tokio::test]
    async fn leaves_a_routed_call_body_alone() {
        let (drained, body) = probe();
        let mut svc = DrainRejectedBodyLayer.layer(RoutedUnread);
        let _res = svc.call(Request::new(body)).await.unwrap();

        assert!(
            !drained.load(Ordering::SeqCst),
            "a response tonic actually routed carries grpc-status in its \
             trailers, so this layer must not touch the request body — a \
             streaming handler is still reading it"
        );
    }

    #[tokio::test]
    async fn a_body_the_inner_stack_consumed_is_not_drained_twice() {
        let (drained, body) = probe();
        let slot: BodySlot = Arc::new(Mutex::new(Some(body)));
        let wrapped = Body::new(SlotBody { slot: slot.clone() });

        // Consume it the way tonic would on an admitted unary call.
        let _ = wrapped.collect().await;
        assert!(drained.load(Ordering::SeqCst));
        assert!(
            lock(&slot).is_none(),
            "reaching end-of-stream must empty the slot so the drain is a no-op"
        );
    }
}
