//! Delegate resources enter native extraction and publication, never a synthetic HTTP transport.

use super::RequestPublication;
use super::*;
use crawlx_core::protocol::ProtocolRouteV1;

fn protocol_item_summary(
    candidate: &Result<Option<serde_json::Value>, crawlx_core::extensions::ExtensionError>,
) -> Option<serde_json::Value> {
    match candidate {
        Ok(Some(_)) => Some(serde_json::json!({"accepted":1,"rejected":0})),
        Err(crawlx_core::extensions::ExtensionError::Rejected) => Some(serde_json::json!({
            "accepted":0,"rejected":1,"reason":"extension_item_rejected",
        })),
        _ => None,
    }
}

impl UrlPlaneRunner {
    pub(super) fn process_protocol_entry<'a>(
        &'a self,
        entry: &'a FrontierEntry,
        route: &'a ProtocolRouteV1,
        label: &'a str,
        discovery: Option<&'a DenialReason>,
        cancel: &'a CancellationToken,
    ) -> impl Future<Output = Result<(), WorkerError>> + Send + 'a {
        Box::pin(self.process_protocol_entry_inner(entry, route, label, discovery, cancel))
    }

    async fn process_protocol_entry_inner(
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
        let mut scoped_extract = self.extract.clone();
        if scoped_extract
            .content
            .as_ref()
            .is_some_and(|policy| policy.dedupe.is_some())
        {
            let queued = self.deps.frontier.get_request(self.run, entry.id).await?;
            let representation = crawlx_core::hash::Digest::of_value(
                "crawlx/extraction-representation/v1",
                &(
                    queued.envelope.header_control.as_ref(),
                    queued.envelope.session_generation,
                    route.delegate_id.as_ref(),
                    &route.id,
                    &route.policy_revision,
                    crawlx_core::protocol::protocol_origin(&entry.url.url),
                ),
            )
            .map_err(|error| WorkerError::Config(error.to_string()))?;
            let namespace = if self.durable_dedupe {
                format!("{}:{}", self.run, entry.id)
            } else {
                self.run.to_string()
            };
            let scope = crawlx_core::extraction::DedupeScopeV1::new(
                &run.tenant.to_string(),
                &namespace,
                &representation.to_hex(),
            )?;
            let cache = if self.durable_dedupe {
                Arc::new(std::sync::Mutex::new(crawlx_core::extraction::DedupeCache::new(
                    65_536,
                )?))
            } else {
                Arc::clone(&self.content_dedupe)
            };
            scoped_extract.dedupe_cache = Some(crawlx_extract::DedupeHandle::new(scope, cache));
        }
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
        let mut resource = match runtime.acquire(&route, &entry.url.url, self.run, run.tenant, &attempt,
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
        crate::acquisition::admit_external_body(&mut resource.body)?;
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
            &scoped_extract,
        )?;
        let validation = crate::acquisition::validate_body(
            body,
            base.clone(),
            resource.media_type.clone(),
            Vec::new(),
            context,
            scoped_extract.clone(),
            &self.cpu_pool,
            &self.fetcher.config().controls,
            self.captcha_secrets.as_ref(),
            cancel,
        );
        let (validation, mut document) =
            tokio::time::timeout_at(budget.render_allowance(cancel).deadline, validation)
                .await
                .map_err(|_| WorkerError::Config("protocol parsing deadline exhausted".to_owned()))??;
        metadata.validation = validation;
        if let Some(article) = document
            .as_mut()
            .and_then(|document| document.value_mut().article.as_mut())
        {
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
        // The delegate's resource is the response of this attempt; the boundary runs before any
        // page, item or link is derived from it.
        if let Some(stop) = self.dispatch(
            entry.id,
            crawlx_core::extensions::ExtensionEventV1::Response,
            cancel,
        ) {
            return self.stop_request(entry, stop).await;
        }
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
        let mut content_dedupe = None;
        let mut local_dedupe = None;
        if document.is_some() {
            if let Some(stop) = self.dispatch_many(
                entry.id,
                [
                    crawlx_core::extensions::ExtensionEventV1::Html,
                    crawlx_core::extensions::ExtensionEventV1::Parse,
                ],
                cancel,
            ) {
                return self.stop_request(entry, stop).await;
            }
        }
        let mut document_hold = None;
        if let Some(budgeted) = document {
            let (document, permit) = budgeted.into_parts();
            document_hold = Some(permit);
            let mut doc = document;
            if self.durable_dedupe {
                content_dedupe = super::content_dedupe_claim(
                    run.tenant,
                    self.run,
                    scoped_extract.dedupe_cache.as_ref(),
                    &doc,
                )?;
            } else {
                local_dedupe = doc.dedupe_commit.take();
            }
            record.metadata["acquisition"]["extractionSucceeded"] = serde_json::json!(true);
            links = doc.links.iter().map(|link| link.url.clone()).collect();
            if self.crawl.extensions.configured()
                || doc
                    .item
                    .as_ref()
                    .is_some_and(|item| !item.valid || item.schema_valid == Some(false))
            {
                let pipeline = self.crawl.extensions.clone();
                let label = label.to_owned();
                let token = cancel.clone();
                let (returned, candidate) = self
                    .cpu_pool
                    .run(move || {
                        let result = if doc
                            .item
                            .as_ref()
                            .is_some_and(|item| !item.valid || item.schema_valid == Some(false))
                            || (pipeline.configured()
                                && doc.validation.as_ref().is_some_and(|v| !v.content_accepted))
                        {
                            Err(crawlx_core::extensions::ExtensionError::Rejected)
                        } else if pipeline.configured() {
                            doc.article
                                .as_ref()
                                .map(|article| {
                                    crate::extensions::transform_document(&pipeline, &label, article, &token)
                                })
                                .transpose()
                                .map(Option::flatten)
                        } else {
                            Ok(None)
                        };
                        (doc, result)
                    })
                    .await
                    .map_err(|_| WorkerError::Config("protocol item pipeline unavailable".to_owned()))?;
                doc = returned;
                if let Some(summary) = protocol_item_summary(&candidate) {
                    record.metadata["itemPipeline"] = summary;
                }
                match candidate {
                    Ok(Some(candidate)) => {
                        if let Some(stop) =
                            self.dispatch(entry.id, crawlx_core::extensions::ExtensionEventV1::Item, cancel)
                        {
                            return self.stop_request(entry, stop).await;
                        }
                        let captcha = self.captcha_secrets.as_ref().ok_or_else(|| {
                            WorkerError::Config("protocol secret registry unavailable".to_owned())
                        })?;
                        let (content, batch, delivery) = crate::extensions::store_candidate(
                            self.deps.artifacts.as_ref(),
                            &self.cpu_pool,
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
                    Err(crawlx_core::extensions::ExtensionError::Rejected) => {
                        record.metadata["extensions"] = serde_json::json!({"version":1,"outcome":"rejected"});
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
        let finished = self
            .finish_protocol_page(
                entry,
                discovery,
                resource.final_url.as_ref(),
                &links,
                (
                    accepted,
                    RequestPublication {
                        outbox,
                        page: Some(record),
                        content_dedupe,
                        local_dedupe,
                        ..RequestPublication::default()
                    },
                ),
            )
            .await;
        // Released only after the terminal commit settled every owner of the document's bytes.
        drop(document_hold);
        finished
    }

    /// Acquire the target through the run's operator-registered acquisition service, under the
    /// parent's lease, scope, robots and shared allowance. The service result is mapped to a
    /// response without fabricating evidence: its metadata is kept verbatim (a missing final URL
    /// stays missing there), and a result without a target status is refused, never defaulted.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn fetch_via_service(
        &self,
        entry: &FrontierEntry,
        queued: &crawlx_core::orchestration::QueuedRequestV1,
        service: &str,
        policy: &crawlx_core::acquisition::AcquisitionPolicyV1,
        budget: &mut crate::acquisition::AcquisitionBudgetV1,
        options: &FetchOptions,
        extract: &crawlx_extract::ExtractOptions,
        cancel: &CancellationToken,
        tenant: crawlx_core::TenantId,
        binding: Option<&crawlx_core::session_binding::SessionBindingV1>,
    ) -> Result<
        (
            FetchResponse,
            crawlx_core::acquisition::AcquisitionResultV1,
            Option<crawlx_core::parser_memory::Budgeted<Box<Document>>>,
        ),
        FetchError,
    > {
        use crawlx_fetch::acquisition_service::AcquisitionServiceScopeV1;
        let runtime = match &self.protocol_runtime {
            Ok(Some(runtime)) => runtime,
            _ => return Err(FetchError::AcquisitionUnavailable),
        };
        let (adapter, egress, resolver, governor) = runtime
            .acquisition_service(service)
            .ok_or(FetchError::AcquisitionUnavailable)?;
        let fence = self
            .held
            .lock()
            .get(&entry.id)
            .copied()
            .ok_or(FetchError::AcquisitionCancelled)?;
        let digest = |domain: &'static str, bytes: &[u8]| crawlx_core::hash::Digest::of(domain, bytes);
        let policy_digest =
            crawlx_core::hash::Digest::of_value("crawlx/acquisition-service-policy/v1", policy)
                .map_err(|_| FetchError::AcquisitionUnavailable)?;
        let mut scope = AcquisitionServiceScopeV1::new(
            tenant,
            self.run,
            digest("crawlx/acquisition-principal/v1", queued.principal.as_bytes()),
            format!("{}:{fence}", entry.id),
            policy_digest,
            digest("crawlx/canonical-url/v1", entry.url.url.as_str().as_bytes()),
        );
        scope.session = binding.map(|binding| binding.identity.session);
        scope.session_generation = binding.map(|binding| binding.generation);
        scope.external_processing_approved = runtime.external_processing_approved(tenant);
        scope.zdr = self.crawl.retention.mode == crawlx_core::config::RetentionMode::Zdr;
        let admission = NativeHopAdmission::new(self, entry)?.with_session(binding.cloned());
        let served = crate::acquisition_service::fetch_service(
            adapter,
            &scope,
            &entry.url.url,
            options,
            policy,
            budget,
            egress,
            resolver,
            governor,
            &self.fetcher.config().controls,
            extract,
            &self.cpu_pool,
            cancel,
            &admission,
            self.captcha_secrets.as_ref(),
        )
        .await?;
        let crate::acquisition_service::ServiceAcquisition { acquired, document } = served;
        let status = acquired
            .metadata
            .target_status
            .and_then(|status| http::StatusCode::from_u16(status).ok())
            .ok_or(FetchError::AcquisitionUnavailable)?;
        let response = FetchResponse {
            final_url: acquired
                .metadata
                .final_url
                .clone()
                .unwrap_or_else(|| entry.url.url.clone()),
            status,
            headers: http::HeaderMap::new(),
            body: acquired.body,
            body_permit: Some(acquired.body_permit),
            wire_bytes: None,
            dns_report: None,
            negotiated_protocol: None,
            truncated: false,
            redirects: Vec::new(),
            hops: Vec::new(),
            resolved_ip: std::net::IpAddr::from([0, 0, 0, 0]),
            peer_observed: false,
            content_type: acquired.metadata.content_type.clone(),
            attempts: acquired.network_requests,
            duration: std::time::Duration::from_millis(acquired.metadata.elapsed_ms),
        };
        Ok((response, acquired.metadata, document))
    }
    async fn finish_protocol_page(
        &self,
        entry: &FrontierEntry,
        discovery: Option<&DenialReason>,
        final_url: Option<&Url>,
        links: &[Url],
        publication: (Vec<crawlx_core::dataset::AcceptedBatchV1>, RequestPublication),
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
                publication.1,
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

    #[test]
    fn protocol_item_counts_do_not_turn_failures_or_cancellation_into_rejections() {
        use crawlx_core::extensions::ExtensionError;
        assert_eq!(
            protocol_item_summary(&Ok(Some(serde_json::json!({})))),
            Some(serde_json::json!({"accepted":1,"rejected":0}))
        );
        assert_eq!(
            protocol_item_summary(&Err(ExtensionError::Rejected)),
            Some(serde_json::json!({"accepted":0,"rejected":1,"reason":"extension_item_rejected"}))
        );
        assert_eq!(protocol_item_summary(&Ok(None)), None);
        for error in [
            ExtensionError::Failed,
            ExtensionError::Cancelled,
            ExtensionError::Limit,
            ExtensionError::Deadline,
            ExtensionError::PolicyDenied,
            ExtensionError::Task,
        ] {
            assert_eq!(protocol_item_summary(&Err(error)), None);
        }
    }

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
            source_memo: stores.source_memo.clone(),
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
                None,
                Some(&base),
                std::slice::from_ref(&child),
                (
                    Vec::new(),
                    RequestPublication {
                        page: Some(record),
                        ..RequestPublication::default()
                    },
                ),
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
