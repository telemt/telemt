use super::*;

/// Owns the registered ME connection and its relay-idle bookkeeping.
pub(super) struct RelayConnLease {
    connection: Option<ConnLease>,
    conn_id: u64,
    shared: Arc<ProxySharedState>,
}

impl RelayConnLease {
    /// Pins connection ownership to the relay scope.
    pub(super) fn new(connection: ConnLease, shared: Arc<ProxySharedState>) -> Self {
        let conn_id = connection.conn_id();
        Self {
            connection: Some(connection),
            conn_id,
            shared,
        }
    }

    /// Returns the pinned connection identifier.
    pub(super) fn conn_id(&self) -> u64 {
        self.conn_id
    }

    /// Clears relay bookkeeping before explicitly unregistering the connection.
    pub(super) async fn unregister(mut self) {
        let Some(connection) = self.connection.take() else {
            return;
        };
        clear_relay_idle_candidate_in(self.shared.as_ref(), connection.conn_id());
        connection.unregister().await;
    }
}

impl Drop for RelayConnLease {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.as_ref() {
            clear_relay_idle_candidate_in(self.shared.as_ref(), connection.conn_id());
        }
    }
}

pub(super) struct RelayChildTasks {
    pub(super) c2me_sender: AbortOnDropHandle<Result<()>>,
    pub(super) me_writer: AbortOnDropHandle<Result<()>>,
    pub(super) flow_cancel: CancellationToken,
    pub(super) stop_tx: Option<oneshot::Sender<()>>,
}

impl Drop for RelayChildTasks {
    fn drop(&mut self) {
        self.flow_cancel.cancel();
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct DropSignal(Arc<AtomicUsize>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }

    async fn pending_child(signal: DropSignal) -> Result<()> {
        let _signal = signal;
        std::future::pending::<()>().await;
        Ok(())
    }

    #[tokio::test]
    async fn relay_child_scope_drop_aborts_both_children() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let flow_cancel = CancellationToken::new();
        let (stop_tx, stop_rx) = oneshot::channel();
        let child_tasks = RelayChildTasks {
            c2me_sender: AbortOnDropHandle::new(tokio::spawn(pending_child(DropSignal(
                Arc::clone(&dropped),
            )))),
            me_writer: AbortOnDropHandle::new(tokio::spawn(pending_child(DropSignal(Arc::clone(
                &dropped,
            ))))),
            flow_cancel: flow_cancel.clone(),
            stop_tx: Some(stop_tx),
        };

        drop(child_tasks);
        assert!(flow_cancel.is_cancelled());
        assert!(stop_rx.await.is_ok());
        tokio::time::timeout(Duration::from_secs(1), async {
            while dropped.load(Ordering::Acquire) != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("both relay child futures must be dropped after scope cancellation");
    }
}
