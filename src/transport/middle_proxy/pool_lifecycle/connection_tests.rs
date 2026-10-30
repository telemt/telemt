use super::super::ConnRegistry;
use super::super::pool_writer_security_tests::make_pool;
use super::*;
use std::future::{Future, poll_fn};
use std::task::Poll;

#[tokio::test]
async fn shutdown_cancels_registration_waiting_for_cleanup_capacity() {
    let mut pool = make_pool().await;
    Arc::get_mut(&mut Arc::get_mut(&mut pool).unwrap().routing)
        .unwrap()
        .registry = Arc::new(ConnRegistry::with_route_and_cleanup_capacity(8, 1));
    let (lease, _receiver) = pool.register_connection().await.unwrap();
    let mut waiting = Box::pin(pool.register_connection());
    assert!(matches!(
        poll_fn(|cx| Poll::Ready(waiting.as_mut().poll(cx))).await,
        Poll::Pending
    ));
    pool.begin_shutdown();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .is_none()
    );
    lease.unregister().await;
    assert!(pool.shutdown_until(Duration::from_secs(1)).await);
    assert!(pool.register_connection().await.is_none());
}
