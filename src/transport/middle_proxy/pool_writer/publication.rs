use super::*;

impl MePool {
    /// Publishes a connected writer only while its generation owns the requested role.
    pub(super) async fn publish_connected_writer(
        self: &Arc<Self>,
        prepared: PreparedWriter<'_>,
    ) -> Result<()> {
        let PreparedWriter {
            writer,
            tx,
            byte_budget,
            task_registration,
            mut writer_task,
            intent,
        } = prepared;
        let writer_id = writer.id;
        let mut writers = self.writers.write().await;
        let mut registry_registration = self.registry.prepare_writer_registration().await;
        let coordinator = self.reinit.coordinator.lock();
        let contour = self.authorize_writer_publication(&writer, &coordinator)?;
        self.authorize_writer_publication_capacity(&writer, contour, intent, writers.as_slice())?;
        writer.contour.store(contour.as_u8(), Ordering::Release);
        registry_registration.install_with_lifetime(
            writer_id,
            tx,
            byte_budget,
            writer_task.lifetime.clone(),
        );
        writers.push(writer);
        self.conn_count.fetch_add(1, Ordering::Relaxed);
        drop(writer_task.opening.take());
        self.lifecycle
            .spawn_registered_writer(task_registration, writer_task);
        drop(coordinator);
        drop(registry_registration);
        drop(writers);
        self.notify_writer_epoch();
        Ok(())
    }

    /// Resolves the writer role against the linearized reinitialization authority.
    pub(super) fn authorize_writer_publication(
        &self,
        writer: &MeWriter,
        coordinator: &crate::transport::middle_proxy::pool::ReinitCoordinatorState,
    ) -> Result<WriterContour> {
        let endpoint_is_current = self
            .endpoint_snapshot
            .load()
            .contains_dc_endpoint(writer.writer_dc, writer.addr);
        if !endpoint_is_current {
            return Err(ProxyError::Proxy(
                "ME writer target changed before publication".into(),
            ));
        }

        let requested = WriterContour::from_u8(writer.contour.load(Ordering::Acquire));
        if writer.generation == coordinator.active_generation
            && matches!(requested, WriterContour::Active | WriterContour::Warm)
        {
            return Ok(WriterContour::Active);
        }
        if requested == WriterContour::Warm
            && coordinator.pending.is_some_and(|pending| {
                pending.generation == writer.generation
                    && pending.map_hash == coordinator.desired_map_hash
                    && pending.endpoint_revision == coordinator.endpoint_revision
            })
        {
            return Ok(WriterContour::Warm);
        }
        Err(ProxyError::Proxy(
            "ME writer generation lost publication authority".into(),
        ))
    }

    /// Revalidates role-local capacity at the serialized publication boundary.
    pub(in crate::transport::middle_proxy) fn authorize_writer_publication_capacity(
        &self,
        writer: &MeWriter,
        contour: WriterContour,
        intent: WriterOpenIntent,
        writers: &[MeWriter],
    ) -> Result<()> {
        let family = if writer.addr.is_ipv4() {
            crate::network::IpFamily::V4
        } else {
            crate::network::IpFamily::V6
        };
        let now_epoch_secs = Self::now_epoch_secs();
        let configured = match family {
            crate::network::IpFamily::V4 => self.decision.ipv4_me,
            crate::network::IpFamily::V6 => self.decision.ipv6_me,
        };
        // Recovery coverage must remain publishable during suppression; the serialized
        // per-group floor check below still bounds it and generation authority is unchanged.
        let recovery_coverage =
            contour == WriterContour::Active && intent == WriterOpenIntent::Coverage;
        if !configured
            || (self.is_family_temporarily_suppressed(family, now_epoch_secs) && !recovery_coverage)
        {
            return Err(ProxyError::Proxy(
                "ME writer family lost publication authority".into(),
            ));
        }
        if intent == WriterOpenIntent::Replacement || contour == WriterContour::Draining {
            return Ok(());
        }
        let endpoint_snapshot = self.endpoint_snapshot.load();
        if !endpoint_snapshot.contains_dc_endpoint(writer.writer_dc, writer.addr) {
            return Err(ProxyError::Proxy(
                "ME writer target changed before publication".into(),
            ));
        }
        if contour == WriterContour::Active && intent == WriterOpenIntent::Normal {
            let current = writers
                .iter()
                .filter(|candidate| {
                    !candidate.draining.load(Ordering::Acquire)
                        && WriterContour::from_u8(candidate.contour.load(Ordering::Acquire))
                            == WriterContour::Active
                })
                .count();
            if current >= self.adaptive_floor_active_cap_configured_total() {
                return Err(ProxyError::Proxy(
                    "ME active writer cap was reached before publication".into(),
                ));
            }
            return Ok(());
        }
        let endpoints = endpoint_snapshot.endpoints_for_dc_family(writer.writer_dc, family);
        let required = self.required_writers_for_dc(endpoints.len());
        let current = writers
            .iter()
            .filter(|candidate| {
                !candidate.draining.load(Ordering::Acquire)
                    && candidate.writer_dc == writer.writer_dc
                    && candidate.generation == writer.generation
                    && WriterContour::from_u8(candidate.contour.load(Ordering::Acquire)) == contour
                    && candidate.addr.is_ipv4() == writer.addr.is_ipv4()
                    && endpoint_snapshot.contains_dc_endpoint(candidate.writer_dc, candidate.addr)
            })
            .count();
        if current >= required {
            return Err(ProxyError::Proxy(
                "ME writer floor was restored before publication".into(),
            ));
        }
        Ok(())
    }

    /// Commits writer visibility and lifecycle ownership after all cancellation points.
    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub(in crate::transport::middle_proxy) async fn publish_prepared_writer<F>(
        self: &Arc<Self>,
        writer: MeWriter,
        tx: mpsc::Sender<WriterCommand>,
        byte_budget: Arc<tokio::sync::Semaphore>,
        task_registration: MeTaskRegistration<'_>,
        writer_task: F,
    ) where
        F: Future<Output = ()> + Send + 'static,
    {
        // Writer publication follows the global writers -> registry binding lock order.
        let mut writers = self.writers.write().await;
        let mut registry_registration = self.registry.prepare_writer_registration().await;
        registry_registration.install(writer.id, tx, byte_budget);
        writers.push(writer);
        self.conn_count.fetch_add(1, Ordering::Relaxed);
        self.lifecycle
            .spawn_registered_writer(task_registration, writer_task);
        drop(writers);
        drop(registry_registration);
        self.notify_writer_epoch();
    }
}
