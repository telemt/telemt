use super::*;

/// Owns relay tasks and their cancellation signals through bounded cleanup.
pub(super) struct RelayChildTasks {
    /// Serializes client frames into the ME route.
    pub(super) c2me_sender: AbortOnDropHandle<Result<()>>,
    /// Delivers ME responses to the client.
    pub(super) me_writer: AbortOnDropHandle<Result<()>>,
    /// Interrupts downstream quota and transport waits during cleanup.
    pub(super) flow_cancel: CancellationToken,
    /// Stops the downstream task after the sender has drained or timed out.
    pub(super) stop_tx: Option<oneshot::Sender<()>>,
}

impl RelayChildTasks {
    /// Reuses consumed join results and preserves sender-first bounded shutdown.
    pub(super) async fn finish(
        &mut self,
        c2me_completed: Option<std::result::Result<Result<()>, tokio::task::JoinError>>,
        writer_completed: Option<std::result::Result<Result<()>, tokio::task::JoinError>>,
        stats: &Stats,
    ) -> (Result<()>, Result<()>) {
        // A JoinHandle whose output was selected must never be polled again.
        let c2me_join = match c2me_completed {
            Some(joined) => Ok(joined),
            None => timeout(ME_CHILD_JOIN_TIMEOUT, &mut self.c2me_sender).await,
        };
        let c2me_result = match c2me_join {
            Ok(joined) => joined
                .unwrap_or_else(|e| Err(ProxyError::Proxy(format!("ME sender join error: {e}")))),
            Err(_) => {
                stats.increment_me_child_join_timeout_total();
                stats.increment_me_child_abort_total();
                self.c2me_sender.abort();
                Err(ProxyError::Proxy("ME sender join timeout".into()))
            }
        };

        self.flow_cancel.cancel();
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
        let writer_join = match writer_completed {
            Some(joined) => Ok(joined),
            None => timeout(ME_CHILD_JOIN_TIMEOUT, &mut self.me_writer).await,
        };
        let writer_result = match writer_join {
            Ok(joined) => joined
                .unwrap_or_else(|e| Err(ProxyError::Proxy(format!("ME writer join error: {e}")))),
            Err(_) => {
                stats.increment_me_child_join_timeout_total();
                stats.increment_me_child_abort_total();
                self.me_writer.abort();
                Err(ProxyError::Proxy("ME writer join timeout".into()))
            }
        };
        (c2me_result, writer_result)
    }
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
