use super::*;

pub(super) async fn supervise_me_task<F, Fut>(task_name: &'static str, mut task: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    loop {
        let result = AbortOnDropHandle::new(tokio::spawn(task())).await;
        match result {
            Ok(()) => warn!(
                task = task_name,
                "Middle-End supervisor task exited unexpectedly, restarting"
            ),
            Err(error) => {
                error!(task = task_name, error = %error, "Middle-End supervisor task panicked, restarting in 1s");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

pub(super) fn spawn_me_supervisors(
    task_scope: RuntimeTaskScope,
    pool: Arc<MePool>,
    rng: Arc<SecureRandom>,
    min_connections: usize,
) {
    let health_pool = pool.clone();
    let health_rng = rng;
    task_scope.spawn(supervise_me_task("health_monitor", move || {
        let pool = health_pool.clone();
        let rng = health_rng.clone();
        async move {
            crate::transport::middle_proxy::me_health_monitor(pool, rng, min_connections).await;
        }
    }));

    let drain_pool = pool.clone();
    task_scope.spawn(supervise_me_task("drain_timeout_enforcer", move || {
        let pool = drain_pool.clone();
        async move {
            crate::transport::middle_proxy::me_drain_timeout_enforcer(pool).await;
        }
    }));

    task_scope.spawn(supervise_me_task("zombie_writer_watchdog", move || {
        let pool = pool.clone();
        async move {
            crate::transport::middle_proxy::me_zombie_writer_watchdog(pool).await;
        }
    }));
}
