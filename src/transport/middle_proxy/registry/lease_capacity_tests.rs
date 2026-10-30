use super::*;
use std::future::{Future, poll_fn};
use std::task::Poll;
use std::time::Duration;

#[tokio::test]
async fn finite_cleanup_capacity_waits_until_dropped_route_is_received() {
    let registry = Arc::new(ConnRegistry::with_route_and_cleanup_capacity(8, 128));
    let mut cleanup = registry.take_cleanup_receiver().unwrap();
    let mut clients = Vec::new();
    for _ in 0..128 {
        clients.push(registry.register_leased().await.unwrap());
    }
    assert_eq!(registry.routing.map.len(), 128);
    assert_eq!(registry.cleanup_tx.capacity(), 0);
    assert!(matches!(
        cleanup.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    let mut waiting = Box::pin(registry.register_leased());
    assert!(matches!(
        poll_fn(|cx| Poll::Ready(waiting.as_mut().poll(cx))).await,
        Poll::Pending
    ));
    let retired = clients.last().unwrap().0.conn_id();
    drop(clients.pop().unwrap());
    assert!(!registry.routing.map.contains_key(&retired));
    assert!(matches!(
        poll_fn(|cx| Poll::Ready(waiting.as_mut().poll(cx))).await,
        Poll::Pending
    ));
    assert_eq!(cleanup.recv().await, Some(retired));
    registry.unregister(retired).await;
    let (lease, _) = tokio::time::timeout(Duration::from_secs(1), waiting)
        .await
        .unwrap()
        .unwrap();
    lease.unregister().await;
    for (lease, _) in clients {
        lease.unregister().await;
    }
    assert!(registry.routing.map.is_empty());
    assert!(registry.routing.byte_budget.is_empty());
    assert_eq!(registry.cleanup_tx.capacity(), 128);
}

#[tokio::test]
async fn cancelled_registration_leaks_neither_route_nor_cleanup_permit() {
    let registry = Arc::new(ConnRegistry::with_route_and_cleanup_capacity(8, 1));
    let _cleanup = registry.take_cleanup_receiver().unwrap();
    let (lease, _receiver) = registry.register_leased().await.unwrap();
    for _ in 0..64 {
        let mut waiting = Box::pin(registry.register_leased());
        assert!(matches!(
            poll_fn(|cx| Poll::Ready(waiting.as_mut().poll(cx))).await,
            Poll::Pending
        ));
        drop(waiting);
        assert_eq!(registry.routing.map.len(), 1);
        assert_eq!(registry.cleanup_tx.capacity(), 0);
    }
    lease.unregister().await;
    assert!(registry.routing.map.is_empty());
    assert_eq!(registry.cleanup_tx.capacity(), 1);
    let (lease, _) = tokio::time::timeout(Duration::from_secs(1), registry.register_leased())
        .await
        .unwrap()
        .unwrap();
    lease.unregister().await;
    assert_eq!(registry.cleanup_tx.capacity(), 1);
}
