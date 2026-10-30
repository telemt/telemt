use super::*;

impl QuotaStateOwner {
    /// Removes an absent account's old checkpoint before CREATE commits its config.
    /// Returns the same gate so config persistence and admission remain serialized.
    pub(crate) async fn prepare_user_creation_locked(
        &self,
        user: &str,
        guard: tokio::sync::OwnedMutexGuard<()>,
    ) -> std::io::Result<tokio::sync::OwnedMutexGuard<()>> {
        let Some(mut state) = read_state_file(&self.path).await? else {
            return Ok(guard);
        };
        state.users.remove(user);
        // Recommit even an absent row: a previous rename may have succeeded while
        // directory sync failed. CREATE needs a confirmed durable barrier on retry.
        let path = self.path.clone();
        let task = tokio::task::spawn_blocking(move || {
            write_state_file_blocking(&path, &state)?;
            Ok(guard)
        });
        wait_for_blocking_io(task).await
    }
}
