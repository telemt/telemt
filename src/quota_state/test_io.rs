//! Path-scoped deterministic I/O barriers; absent from production builds.
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};

fn hooks() -> &'static Mutex<HashMap<PathBuf, Arc<Hook>>> {
    static HOOKS: OnceLock<Mutex<HashMap<PathBuf, Arc<Hook>>>> = OnceLock::new();
    HOOKS.get_or_init(Mutex::default)
}

pub(super) struct Hook {
    path: PathBuf,
    started: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    released: Mutex<bool>,
    wake: Condvar,
    pub(super) writes: AtomicUsize,
    pub(super) fail_after: AtomicBool,
}

pub(super) struct HookGuard(Arc<Hook>);

impl std::ops::Deref for HookGuard {
    type Target = Hook;
    fn deref(&self) -> &Hook {
        &self.0
    }
}

impl Drop for HookGuard {
    fn drop(&mut self) {
        self.0.remove();
    }
}

impl Hook {
    pub(super) fn install(
        path: &Path,
        block: bool,
    ) -> (HookGuard, tokio::sync::oneshot::Receiver<()>) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let hook = Arc::new(Self {
            path: path.into(),
            started: Mutex::new(Some(tx)),
            released: Mutex::new(!block),
            wake: Condvar::new(),
            writes: AtomicUsize::new(0),
            fail_after: AtomicBool::new(false),
        });
        assert!(
            hooks()
                .lock()
                .unwrap()
                .insert(path.into(), hook.clone())
                .is_none()
        );
        (HookGuard(hook), rx)
    }

    pub(super) fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }

    pub(super) fn remove(&self) {
        self.release();
        hooks().lock().unwrap().remove(&self.path);
    }
}

pub(super) fn before(path: &Path) {
    let hook = hooks().lock().unwrap().get(path).cloned();
    if let Some(hook) = hook {
        hook.writes.fetch_add(1, Ordering::Relaxed);
        if let Some(tx) = hook.started.lock().unwrap().take() {
            let _ = tx.send(());
        }
        let mut released = hook.released.lock().unwrap();
        while !*released {
            released = hook.wake.wait(released).unwrap();
        }
    }
}

pub(super) fn after(path: &Path) -> std::io::Result<()> {
    if hooks()
        .lock()
        .unwrap()
        .get(path)
        .is_some_and(|hook| hook.fail_after.load(Ordering::Relaxed))
    {
        return Err(std::io::Error::other(
            "injected failure after durable replacement",
        ));
    }
    Ok(())
}
