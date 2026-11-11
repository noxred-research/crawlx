//! Bounded keyset recovery of committed feed intents, including terminal runs.
use super::DeliveryAuthority;
use crate::{stores::Stores, WorkerConfig};
use crawlx_core::{Clock, CrawlRunId};
use std::{collections::BTreeMap, sync::Arc};
use tokio_util::sync::CancellationToken;

pub(crate) async fn recover_once(
    stores: &Stores,
    cfg: &WorkerConfig,
    clock: &Arc<dyn Clock>,
    cancel: &CancellationToken,
    governors: &mut BTreeMap<CrawlRunId, Arc<crawlx_fetch::OriginGovernor>>,
    after: &mut Option<CrawlRunId>,
) -> Result<(), crate::WorkerError> {
    let facts = cfg.data_capabilities()?;
    let runs = stores.delivery.ready_runs(*after, 16).await?;
    if runs.is_empty() {
        *after = None;
        return Ok(());
    }
    let mut failure = None;
    for id in runs {
        *after = Some(id);
        if cancel.is_cancelled() {
            break;
        }
        let result = tokio::select! {
            ()=cancel.cancelled()=>break,
            result=recover_run(stores,cfg,clock,cancel,governors,id,&facts)=>result,
        };
        // One unavailable tenant/run must not prevent recovery of other committed batches.
        if let Err(error) = result {
            if failure.is_none() {
                failure = Some(error);
            }
        }
    }
    failure.map_or(Ok(()), Err)
}

async fn recover_run(
    stores: &Stores,
    cfg: &WorkerConfig,
    clock: &Arc<dyn Clock>,
    cancel: &CancellationToken,
    governors: &mut BTreeMap<CrawlRunId, Arc<crawlx_fetch::OriginGovernor>>,
    id: CrawlRunId,
    facts: &crawlx_core::data_capabilities::WorkerDataCapabilitiesV1,
) -> Result<(), crate::WorkerError> {
    stores.delivery.maintain(id).await?;
    let mut run = Box::new(stores.runs.get(id).await?);
    let required = crawlx_core::data_capabilities::WorkerDataRequirementsV1::from_config(&run.config)?;
    if !facts.supports(&required) {
        return Ok(());
    }
    cfg.delivery.validate(&run)?;
    if let Some(reason) = stores.request_commits.begin_feed_finalization(id, None).await? {
        Box::pin(super::finalize_feeds(stores, &run, reason, &cfg.cpu_pool)).await?;
        stores.artifacts.erase_run_credentials(id).await?;
        *run = stores.runs.get(id).await?;
    }
    if let Some(authority) = cfg.delivery.active_authority(id) {
        cfg.delivery
            .drain_once(stores, &run, cfg.worker_id, clock.as_ref(), &authority)
            .await?;
        return Ok(());
    }
    let guard = crate::run::local_authorization(&run, None, stores, cfg, clock).await?;
    let record = guard.as_ref().map(|guard| guard.record());
    let governor = if let Some(governor) = governors.get(&id) {
        Arc::clone(governor)
    } else {
        if governors.len() >= 16 {
            if let Some(oldest) = governors.keys().next().copied() {
                governors.remove(&oldest);
            }
        }
        let cap = stores.origin_cap(
            cfg,
            id,
            usize::from(run.config.politeness.max_in_flight_per_origin),
        );
        let governor = Arc::new(crawlx_fetch::OriginGovernor::with_global_cap(
            crawlx_fetch::GovernorConfig::from_politeness(&run.config.politeness, run.seed),
            cap,
        ));
        governors.insert(id, Arc::clone(&governor));
        governor
    };
    let authority = DeliveryAuthority {
        policy: Arc::new(cfg.egress.policy_for_run(&run.config, record)),
        resolver: cfg.egress.resolver_for(&run.config)?,
        governor,
        cancel: cancel.clone(),
    };
    cfg.delivery
        .drain_once(stores, &run, cfg.worker_id, clock.as_ref(), &authority)
        .await?;
    Ok(())
}
