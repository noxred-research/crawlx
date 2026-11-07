//! Delegate resources enter native extraction and publication, never a synthetic HTTP transport.

use super::*;
use crawlx_core::protocol::ProtocolRouteV1;

impl UrlPlaneRunner {
    pub(super) async fn process_protocol_entry(
        &self,
        entry: &FrontierEntry,
        route: &ProtocolRouteV1,
        label: &str,
        discovery: Option<&DenialReason>,
        cancel: &CancellationToken,
    ) -> Result<(), WorkerError> {
        let runtime = match &self.protocol_runtime {
            Ok(Some(runtime)) => runtime,
            _ => {
                return self
                    .fail(
                        entry,
                        "protocol_capability_unavailable",
                        "protocol_capability_unavailable",
                        Attempt::Failed,
                        serde_json::json!({"reason":"approved protocol runtime unavailable"}),
                    )
                    .await
            }
        };
        let run = self.deps.runs.get(self.run).await?;
        let mut policy = self.crawl.acquisition.clone().unwrap_or_default();
        policy.max_decoded_bytes = policy.max_decoded_bytes.min(u64::from(route.max_body_bytes));
        policy.max_elapsed_ms = policy.max_elapsed_ms.min(route.max_elapsed_ms);
        let mut budget = crate::acquisition::AcquisitionBudgetV1::new(&policy)?;
        let remaining = budget.reserve(cancel)?;
        let mut route = route.clone();
        route.max_body_bytes = route
            .max_body_bytes
            .min(u32::try_from(budget.remaining_bytes()).unwrap_or(u32::MAX));
        route.max_elapsed_ms = route
            .max_elapsed_ms
            .min(u32::try_from(remaining.as_millis()).unwrap_or(u32::MAX));
        let requests = budget
            .options(&FetchOptions::default(), self.fetcher.config().max_body_bytes)
            .request_allowance
            .ok_or_else(|| WorkerError::Config("protocol request allowance unavailable".to_owned()))?;
        let fence = self
            .held
            .lock()
            .get(&entry.id)
            .copied()
            .ok_or(StoreError::LeaseLost)?;
        let attempt = format!("{}:{fence}", entry.id);
        let resource = match runtime.acquire(&route, &entry.url.url, self.run, run.tenant, &attempt,
            self.crawl.retention.mode == crawlx_core::config::RetentionMode::Zdr, &requests, cancel).await {
            Ok(resource) => resource,
            Err(crawlx_fetch::protocol::ProtocolError::Cancelled) => {
                self.finish(entry, FrontierStatus::Abandoned, Some("protocol_acquisition_cancelled".to_owned())).await?;
                self.counters.attempt(Plane::Urls, Attempt::Abandoned);
                return Ok(());
            }
            Err(error) => return self.fail(entry, "protocol_acquisition_failed", "protocol_acquisition_failed",
                Attempt::Failed, serde_json::json!({"reason":error.to_string(),"route":route.id,"policyRevision":route.policy_revision})).await,
        };
        budget.charge_bytes(resource.decoded_bytes);
        let base = resource
            .final_url
            .clone()
            .unwrap_or_else(|| entry.url.url.clone());
        let mut metadata =
            crate::protocol::resource_metadata(&resource, &route, &entry.url.url, self.run, run.tenant);
        let context = crate::acquisition::context(&policy, resource.target_status, false);
        let body = crate::acquisition::extraction_body(
            &resource.body,
            &self.fetcher.config().controls,
            &self.extract,
        );
        let validation = crate::acquisition::validate_body(
            body,
            base.clone(),
            resource.media_type.clone(),
            Vec::new(),
            context,
            self.extract.clone(),
            &self.cpu_pool,
            &self.fetcher.config().controls,
            self.captcha_secrets.as_ref(),
        );
        let (validation, mut document) =
            tokio::time::timeout_at(budget.render_allowance(cancel).deadline, validation)
                .await
                .map_err(|_| WorkerError::Config("protocol parsing deadline exhausted".to_owned()))??;
        metadata.validation = validation;
        if let Some(article) = document.as_mut().and_then(|document| document.article.as_mut()) {
            article.acquisition_request_digest = Some(metadata.request_digest);
        }
        budget.record(
            &metadata.backend.backend_id,
            metadata.target_status,
            metadata.validation.category,
        );
        budget.stamp(&mut metadata);
        metadata.bound().map_err(|e| WorkerError::Config(e.to_string()))?;
        if resource
            .target_status
            .is_some_and(|status| !(200..=299).contains(&status))
            || (policy.validation.on_content_mismatch
                == crawlx_core::acquisition::ContentMismatchActionV1::Fail
                && !metadata.validation.content_accepted)
        {
            return self
                .fail(
                    entry,
                    "protocol_target_rejected",
                    "protocol_target_rejected",
                    Attempt::Failed,
                    serde_json::json!({"acquisition":metadata}),
                )
                .await;
        }
        let Some(status) = resource.target_status else {
            return self.fail(entry, "protocol_status_unavailable", "protocol_status_unavailable", Attempt::Failed,
                serde_json::json!({"acquisition":metadata,"reason":"non-HTTP or supplied-content resources use the operator protocol resource command, not HTTP page storage"})).await;
        };
        let mut record = PageRecord {
            run: self.run,
            frontier_id: entry.id,
            url: entry.url.clone(),
            status,
            content_type: resource.media_type,
            content_digest: crawlx_core::hash::Digest::of("crawlx/page-body/v1", &resource.body),
            title: None,
            markdown: None,
            html: None,
            metadata: serde_json::json!({"acquisition":metadata}),
            links: Vec::new(),
            fetched_at: self.deps.clock.now(),
            lane: TrustLane::Diagnostic,
        };
        let mut accepted = Vec::new();
        let mut outbox = Vec::new();
        let mut links = Vec::new();
        if let Some(mut doc) = document {
            record.metadata["acquisition"]["extractionSucceeded"] = serde_json::json!(true);
            links = doc.links.iter().map(|link| link.url.clone()).collect();
            if self.crawl.extensions.configured() {
                let pipeline = self.crawl.extensions.clone();
                let label = label.to_owned();
                let token = cancel.clone();
                let (returned, candidate) = self
                    .cpu_pool
                    .run(move || {
                        let result = if doc.validation.as_ref().is_some_and(|v| !v.content_accepted) {
                            Err(crawlx_core::extensions::ExtensionError::Rejected)
                        } else {
                            doc.article
                                .as_ref()
                                .map(|article| {
                                    crate::extensions::transform_document(&pipeline, &label, article, &token)
                                })
                                .transpose()
                                .map(Option::flatten)
                        };
                        (doc, result)
                    })
                    .await
                    .map_err(|_| WorkerError::Config("protocol item pipeline unavailable".to_owned()))?;
                doc = returned;
                match candidate {
                    Ok(Some(candidate)) => {
                        let captcha = self.captcha_secrets.as_ref().ok_or_else(|| {
                            WorkerError::Config("protocol secret registry unavailable".to_owned())
                        })?;
                        let (content, batch, delivery) = crate::extensions::store_candidate(
                            self.deps.artifacts.as_ref(),
                            &run,
                            entry.id,
                            &candidate,
                            "approved-protocol-service",
                            &self.fetcher.config().controls,
                            captcha,
                        )
                        .await?;
                        accepted.extend(batch);
                        outbox.extend(delivery);
                        record.metadata["extensions"] = serde_json::json!({"version":1,"content":content});
                    }
                    Ok(None) if !self.crawl.extensions.requires_document() => {}
                    _ => {
                        return self
                            .fail(
                                entry,
                                "extension_item_rejected",
                                "extension_item_rejected",
                                Attempt::Failed,
                                serde_json::json!({"reason":"protocol item rejected"}),
                            )
                            .await
                    }
                }
            }
            let extension = record
                .metadata
                .as_object_mut()
                .and_then(|metadata| metadata.remove("extensions"));
            self.fill_record(&mut record, &doc, &base).await;
            if let Some(extension) = extension {
                record.metadata["extensions"] = extension;
            }
            let acquisition_accepted = doc
                .validation
                .as_ref()
                .is_some_and(|validation| validation.content_accepted)
                && doc.article.as_ref().is_some_and(|article| {
                    article.quality.status == crawlx_core::extraction::QualityStatusV1::Accepted
                });
            let (_, article_items, article_delivery) = crate::delivery::prepare_article_acceptance(
                self.deps.artifacts.as_ref(),
                &self.cpu_pool,
                &run,
                entry.id,
                doc,
                acquisition_accepted,
            )
            .await?;
            accepted.extend(article_items);
            outbox.extend(article_delivery);
        } else if self.crawl.extensions.requires_document() {
            return self
                .fail(
                    entry,
                    "extension_document_unavailable",
                    "extension_document_unavailable",
                    Attempt::Failed,
                    serde_json::json!({"reason":"protocol document unavailable"}),
                )
                .await;
        }
        if resource.final_url.is_none() {
            record.metadata["final_url"] = serde_json::Value::Null;
            record.metadata["final_url_evidence"] = serde_json::json!("unavailable");
        }
        record.metadata["protocolRoute"] =
            serde_json::json!({"id":route.id,"policyRevision":route.policy_revision,"lane":"diagnostic"});
        self.finish_protocol_page(
            entry,
            record,
            discovery,
            resource.final_url.as_ref(),
            &links,
            (accepted, outbox),
        )
        .await
    }

    async fn finish_protocol_page(
        &self,
        entry: &FrontierEntry,
        record: PageRecord,
        discovery: Option<&DenialReason>,
        final_url: Option<&Url>,
        links: &[Url],
        publication: (
            Vec<crawlx_core::dataset::AcceptedBatchV1>,
            Vec<crawlx_core::dataset::DeliveryBatchV1>,
        ),
    ) -> Result<(), WorkerError> {
        // Child appends require this parent's still-live lease fence. A parse base is not final URL evidence.
        let leaf_only = matches!(
            self.scope.decide(&entry.url, entry.depth),
            ScopeVerdict::Admitted { leaf_only: true }
        );
        if let Some(final_url) =
            final_url.filter(|_| !leaf_only && self.crawl.scope.sitemap != SitemapMode::Only)
        {
            self.follow_page(entry, final_url, links, Vec::new()).await?;
        }
        if let Some(reason) = discovery {
            self.finish_discovery_only(entry, reason).await?;
        } else {
            self.finish_with_results(
                entry,
                FrontierStatus::Succeeded,
                None,
                publication.0,
                Vec::new(),
                (publication.1, Some(record)),
            )
            .await?;
            *self.pages_written.lock() += 1;
            self.counters.attempt(Plane::Urls, Attempt::Succeeded);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::repo::CrawlRun;

    #[tokio::test]
    async fn protocol_children_append_under_live_parent_fence_before_terminal_commit() {
        let directory = tempfile::tempdir().unwrap();
        let clock: Arc<dyn Clock> = Arc::new(crawlx_core::time::ManualClock::new(
            "2026-11-01T00:00:00Z".parse().unwrap(),
        ));
        let memory = Arc::new(crawlx_storage::MemoryStore::with_clock(Arc::clone(&clock)));
        let stores = crate::Stores::over_memory(memory, directory.path())
            .await
            .unwrap();
        let base = Url::parse("https://protocol-fixture.invalid/").unwrap();
        let child = base.join("child").unwrap();
        let mut crawl = CreateCrawl::new(base.clone());
        crawl.mode = CrawlMode::Static;
        crawl.seed = Some(42);
        crawl.safety.respect_robots_txt = false;
        crawl.scope.sitemap = SitemapMode::Skip;
        let run = CrawlRun {
            id: CrawlRunId::new(),
            tenant: stores.tenant,
            status: RunStatus::Running,
            terminal_reason: None,
            config_digest: crawl.digest().unwrap(),
            seed: crawl.effective_seed(),
            policy_version: 1,
            counters: Default::default(),
            created_at: clock.now(),
            started_at: Some(clock.now()),
            finished_at: None,
            trace_id: None,
            config: crawl.clone(),
        };
        stores.runs.create(&run, None).await.unwrap();
        let canonical =
            Canonicalizer::canonicalize(base.as_str(), &base, &CanonicalizeOptions::default()).unwrap();
        stores
            .frontier
            .discover(run.id, &canonical, 0, None, None)
            .await
            .unwrap();
        let worker = WorkerId::new();
        let (entry, fence) = stores
            .frontier
            .lease_batch_fenced(run.id, worker, 1)
            .await
            .unwrap()
            .pop()
            .unwrap();
        let fetcher = Arc::new(
            Fetcher::new(
                crawlx_fetch::FetchConfig::default(),
                Arc::new(crawlx_policy::EgressPolicy::default()),
                Arc::new(crawlx_fetch::StaticResolver::new()),
            )
            .unwrap(),
        );
        let deps = UrlPlaneDeps {
            runs: stores.runs.clone(),
            frontier: stores.frontier.clone(),
            request_commits: stores.request_commits.clone(),
            leases: stores.leases.clone(),
            pages: stores.pages.clone(),
            events: stores.events.clone(),
            artifacts: stores.artifacts.clone(),
            archives: stores.archives.clone(),
            clock: clock.clone(),
        };
        let counters = RunCounters::default();
        counters.discovery_with_reason(Plane::Urls, DiscoveryOutcome::Admitted, "seed");
        let runner = UrlPlaneRunner::new(
            run.id,
            crawl,
            worker,
            deps,
            fetcher,
            counters,
            CanonicalizeOptions::default(),
        )
        .unwrap();
        runner.held.lock().insert(entry.id, fence);
        let record = PageRecord {
            run: run.id,
            frontier_id: entry.id,
            url: canonical,
            status: 200,
            content_type: Some("text/html".into()),
            content_digest: crawlx_core::hash::Digest::of("fixture", b"page"),
            title: None,
            markdown: None,
            html: None,
            metadata: serde_json::json!({}),
            links: vec![child.to_string()],
            fetched_at: clock.now(),
            lane: TrustLane::Diagnostic,
        };
        runner
            .finish_protocol_page(
                &entry,
                record,
                None,
                Some(&base),
                std::slice::from_ref(&child),
                (Vec::new(), Vec::new()),
            )
            .await
            .unwrap();
        let rows = stores.frontier.list(run.id).await.unwrap();
        assert_eq!(
            rows.iter().find(|row| row.id == entry.id).unwrap().status,
            FrontierStatus::Succeeded
        );
        let discovered = rows.iter().find(|row| row.url.url == child).unwrap();
        assert_eq!(discovered.status, FrontierStatus::Pending);
        assert_eq!(discovered.discovered_from, Some(entry.id));
        assert!(!runner.held.lock().contains_key(&entry.id));
        assert_eq!(stores.pages.list(run.id).await.unwrap().len(), 1);
        let next = Canonicalizer::canonicalize(
            "https://protocol-fixture.invalid/too-late",
            &base,
            &CanonicalizeOptions::default(),
        )
        .unwrap();
        let mut late = crawlx_core::orchestration::RequestBatchV1::new(
            run.tenant,
            run.id,
            "anonymous".into(),
            crawlx_core::hash::Digest::of("late-batch", b"after-terminal"),
            vec![crawlx_core::request::RequestEnvelopeV1::get(
                next,
                1,
                Some(entry.id),
            )],
        );
        late.parent_fence = Some((entry.id, fence));
        assert!(
            stores.frontier.append_batch(late).await.is_err(),
            "terminal parent cannot authorize later children"
        );
    }
}
