use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::sync::mpsc::error::TrySendError;
use tracing::debug;

use crate::error::Result;
use crate::protocol::constants::{RPC_CLOSE_CONN_U32, RPC_CLOSE_EXT_U32};

use super::super::MePool;
use super::super::codec::{WriterCommand, build_control_payload};
use super::{WriterCommandReserveError, reserve_writer_command_slot};

const ME_CLOSE_SIGNAL_SEND_TIMEOUT: Duration = Duration::from_millis(50);

impl MePool {
    /// Sends an extended close signal for a client-bound ME connection.
    pub async fn send_close(self: &Arc<Self>, conn_id: u64) -> Result<()> {
        if let Some(w) = self.registry.get_writer(conn_id).await {
            let payload = build_control_payload(RPC_CLOSE_EXT_U32, conn_id);
            match w.tx.try_send(WriterCommand::ControlAndFlush(payload)) {
                Ok(()) => {}
                Err(TrySendError::Full(cmd)) => {
                    match reserve_writer_command_slot(&w.tx, Some(ME_CLOSE_SIGNAL_SEND_TIMEOUT))
                        .await
                    {
                        Ok(permit) => {
                            permit.send(cmd);
                        }
                        Err(WriterCommandReserveError::TimedOut) => {
                            debug!(conn_id, "ME close skipped: writer command channel is full");
                        }
                        Err(WriterCommandReserveError::Closed) => {
                            debug!(
                                conn_id,
                                "ME close skipped: writer command channel is closed"
                            );
                            self.remove_writer_and_close_clients(w.writer_id).await;
                        }
                    }
                }
                Err(TrySendError::Closed(_)) => {
                    debug!(
                        conn_id,
                        "ME close skipped: writer command channel is closed"
                    );
                    self.remove_writer_and_close_clients(w.writer_id).await;
                }
            }
        } else {
            debug!(conn_id, "ME close skipped (writer missing)");
        }

        self.registry.unregister(conn_id).await;
        Ok(())
    }

    /// Sends the compact close signal used by ME-side forced connection teardown.
    pub async fn send_close_conn(self: &Arc<Self>, conn_id: u64) -> Result<()> {
        if let Some(w) = self.registry.get_writer(conn_id).await {
            let payload = build_control_payload(RPC_CLOSE_CONN_U32, conn_id);
            match w.tx.try_send(WriterCommand::ControlAndFlush(payload)) {
                Ok(()) => {}
                Err(TrySendError::Full(cmd)) => {
                    let _ = reserve_writer_command_slot(&w.tx, Some(ME_CLOSE_SIGNAL_SEND_TIMEOUT))
                        .await
                        .map(|permit| permit.send(cmd));
                }
                Err(TrySendError::Closed(_)) => {
                    debug!(conn_id, "ME close_conn skipped: writer channel closed");
                }
            }
        } else {
            debug!(conn_id, "ME close_conn skipped (writer missing)");
        }

        self.registry.unregister(conn_id).await;
        Ok(())
    }

    /// Sends close signals for all currently registered ME-bound connections during shutdown.
    pub async fn shutdown_send_close_conn_all(self: &Arc<Self>) -> usize {
        let conn_ids = self.registry.active_conn_ids().await;
        let total = conn_ids.len();
        for conn_id in conn_ids {
            let _ = self.send_close_conn(conn_id).await;
        }
        total
    }

    /// Returns the current number of active ME writers tracked by the pool.
    pub fn connection_count(&self) -> usize {
        self.conn_count.load(Ordering::Relaxed)
    }
}
