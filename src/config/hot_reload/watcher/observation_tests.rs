use super::*;
use crate::config::observation::{ConfigProvenance, WatchObservation};

#[tokio::test]
async fn watcher_outcomes_follow_actual_publication_retention_and_rejection() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(&path, "").unwrap();
    let loaded = ProxyConfig::load_prepared(path.clone()).await.unwrap();
    let mut initial = loaded.config.with_publication_epoch();
    let observer = Arc::new(WatchObservation::default());
    initial.watcher_observation = Some(observer.clone());
    let (sender, mut receiver) = watch::channel(Arc::new(initial));
    let (log, _) = watch::channel(sender.borrow().general.log_level.clone());
    let mut state = ReloadState::new(Some(loaded.rendered_hash));
    for (text, phase, changed) in [
        ("[general]\nlog_level='debug'", "published", true),
        (
            "[general]\nlog_level='debug'\ndisable_colors=true",
            "retained",
            false,
        ),
        (
            "[general]\nlog_level='verbose'\ndisable_colors=true",
            "published_partial",
            true,
        ),
        (
            "[general]\nlog_level='verbose'\ndisable_colors=true",
            "unchanged",
            false,
        ),
        (
            "[general]\nlog_level='private-invalid-log-level'",
            "rejected",
            false,
        ),
    ] {
        let old = receiver.borrow_and_update().clone();
        let sequence = observer.snapshot().map_or(0, |value| value.sequence);
        std::fs::write(&path, text).unwrap();
        preparation::reload(
            &path, &sender, &log, None, None, &mut state, None, false, None, None,
        )
        .await;
        let outcome = observer.snapshot().unwrap();
        assert!(outcome.sequence > sequence);
        assert_eq!(outcome.phase, phase);
        assert_eq!(receiver.has_changed().unwrap(), changed);
        if changed {
            assert!(receiver.borrow().runtime_config_epoch > old.runtime_config_epoch);
            assert_eq!(
                outcome.published_config_epoch,
                Some(receiver.borrow().runtime_config_epoch)
            );
            if phase == "published_partial" {
                assert!(matches!(
                    &receiver.borrow().provenance,
                    ConfigProvenance::Mixed
                ));
            } else {
                assert_eq!(
                    outcome.source_revision.as_deref(),
                    receiver.borrow().provenance.revision()
                );
            }
        } else {
            assert!(Arc::ptr_eq(&old, &receiver.borrow()));
        }
        assert!(
            !serde_json::to_string(&*outcome)
                .unwrap()
                .contains("private-invalid-log-level")
        );
    }
    let rejected = observer.snapshot().unwrap();
    assert_eq!(rejected.error_code, Some("source_invalid_or_unreadable"));
    assert_eq!(rejected.published_config_epoch, None);
}

#[tokio::test]
async fn lost_receivers_never_report_successful_publication() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(&path, "").unwrap();
    let mut initial = ProxyConfig::load_prepared(path.clone())
        .await
        .unwrap()
        .config;
    let observer = Arc::new(WatchObservation::default());
    initial.watcher_observation = Some(observer.clone());
    let (sender, receiver) = watch::channel(Arc::new(initial.with_publication_epoch()));
    let (log, _) = watch::channel(sender.borrow().general.log_level.clone());
    let original = sender.borrow().clone();
    drop(receiver);
    std::fs::write(&path, "[general]\nlog_level='debug'").unwrap();
    preparation::reload(
        &path,
        &sender,
        &log,
        None,
        None,
        &mut ReloadState::default(),
        None,
        false,
        None,
        None,
    )
    .await;
    assert!(Arc::ptr_eq(&sender.borrow(), &original));
    let outcome = observer.snapshot().unwrap();
    assert_eq!(outcome.phase, "publication_failed");
    assert_eq!(outcome.published_config_epoch, None);
    assert_eq!(outcome.error_code, Some("publication_closed"));
}

#[tokio::test]
async fn rejection_totals_and_restart_pending_follow_watcher_outcomes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(&path, "").unwrap();
    let loaded = ProxyConfig::load_prepared(path.clone()).await.unwrap();
    let mut initial = loaded.config.with_publication_epoch();
    let observer = Arc::new(WatchObservation::default());
    initial.watcher_observation = Some(observer.clone());
    let (sender, _receiver) = watch::channel(Arc::new(initial));
    let (log, _) = watch::channel(sender.borrow().general.log_level.clone());
    let mut state = ReloadState::new(Some(loaded.rendered_hash));
    let rejected = |observer: &WatchObservation| {
        observer
            .rejected_totals()
            .find(|(code, _)| *code == "source_invalid_or_unreadable")
            .unwrap()
            .1
    };
    for (text, phase, pending, rejections) in [
        ("[general]\nlog_level='debug'", "published", false, 0),
        (
            "[general]\nlog_level='debug'\ndisable_colors=true",
            "retained",
            true,
            0,
        ),
        ("[general]\nlog_level='invalid'", "rejected", true, 1),
        ("[general]\nlog_level='invalid'", "rejected", true, 2),
        ("[general]\nlog_level='debug'", "unchanged", false, 2),
    ] {
        std::fs::write(&path, text).unwrap();
        preparation::reload(
            &path, &sender, &log, None, None, &mut state, None, false, None, None,
        )
        .await;
        assert_eq!(observer.snapshot().unwrap().phase, phase);
        assert_eq!(observer.restart_pending(), pending, "{text}");
        assert_eq!(rejected(&observer), rejections, "{text}");
    }
    assert_eq!(
        observer
            .rejected_totals()
            .map(|(_, total)| total)
            .sum::<u64>(),
        2
    );
}

#[test]
fn only_rejected_phases_count_and_every_listed_code_has_a_series() {
    let observer = WatchObservation::default();
    observer.record("publication_failed", None, None, Some("publication_closed"));
    for code in crate::config::observation::WATCH_REJECTION_CODES {
        observer.record("rejected", None, None, Some(code));
    }
    let totals: Vec<_> = observer.rejected_totals().collect();
    assert_eq!(
        totals.len(),
        crate::config::observation::WATCH_REJECTION_CODES.len()
    );
    assert!(totals.iter().all(|(_, total)| *total == 1));
}
