//! OTLP export, confined to this one module (the OpenTelemetry Rust
//! trace API's stability differs from its metrics and logs).
//!
//! * **Feature `otlp` disabled (default):** [`install`] is a no-op. A configured
//!   endpoint is ignored and [`install`] returns `Ok(None)`; `init` records a
//!   `warn` event so the operator can see that export is not active.
//! * **Feature `otlp` enabled:** [`install`] validates the endpoint, builds a
//!   gRPC (`tonic`) span exporter behind a batch processor and a periodic
//!   metric exporter, and returns an [`OtlpHandle`]. The handle's
//!   [`OtlpHandle::layer`] bridges `tracing` spans into OpenTelemetry; the
//!   metric bridge reads the in-process [`Metrics`](crate::Metrics) registry
//!   through observable instruments on every export tick, so the catalog is
//!   exported once, from one source of truth. Export is best-effort:
//!   a collector outage never affects a crawl.

use crate::TelemetryError;

/// OTLP export settings.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OtlpConfig {
    /// Collector endpoint, e.g. `http://otel-collector:4317`.
    pub endpoint: String,
    /// Value of the `service.name` resource attribute.
    pub service_name: String,
    /// Extra resource attributes attached to every exported span and metric point, e.g.
    /// `tenant_id` / `run_id` for a worker dedicated to one run. Keys are
    /// exported verbatim; an empty list exports `service.name` only.
    pub resource: Vec<(String, String)>,
}

/// Whether this build can export over OTLP.
#[must_use]
pub const fn enabled() -> bool {
    cfg!(feature = "otlp")
}

fn validate_endpoint(config: &OtlpConfig) -> Result<(), TelemetryError> {
    let ok = ["http://", "https://"]
        .iter()
        .any(|p| config.endpoint.starts_with(p))
        && config.endpoint.len() > 8;
    if ok {
        Ok(())
    } else {
        Err(TelemetryError::InvalidOtlpEndpoint(config.endpoint.clone()))
    }
}

#[cfg(not(feature = "otlp"))]
mod imp {
    use super::{validate_endpoint, OtlpConfig, TelemetryError};

    /// Placeholder handle; this build never exports.
    #[derive(Debug)]
    pub struct OtlpHandle {
        _private: (),
    }

    /// Validate the endpoint and do nothing else (`Ok(None)`): the `otlp`
    /// feature is disabled, so a typo in the endpoint still fails early
    /// while a valid configuration is silently ignored.
    ///
    /// # Errors
    /// [`TelemetryError::InvalidOtlpEndpoint`] for a malformed endpoint.
    pub fn install(config: &OtlpConfig) -> Result<Option<OtlpHandle>, TelemetryError> {
        validate_endpoint(config)?;
        Ok(None)
    }
}

#[cfg(feature = "otlp")]
mod imp {
    use super::{validate_endpoint, OtlpConfig, TelemetryError};
    use crate::metrics::{MetricKind, Metrics, SeriesValue, Unit};
    use opentelemetry::metrics::MeterProvider as _;
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry::KeyValue;
    use opentelemetry_otlp::{MetricExporter, SpanExporter, WithExportConfig as _};
    use opentelemetry_sdk::metrics::SdkMeterProvider;
    use opentelemetry_sdk::trace::SdkTracerProvider;
    use opentelemetry_sdk::Resource;
    use tracing::Subscriber;
    use tracing_subscriber::registry::LookupSpan;
    use tracing_subscriber::Layer;

    /// Keeps the exporters alive; dropping it shuts both providers down and
    /// flushes pending spans and metric points.
    pub struct OtlpHandle {
        tracer: SdkTracerProvider,
        meter: SdkMeterProvider,
        // Observable instruments live as long as their callbacks are wanted.
        _instruments: Vec<Instrument>,
    }

    impl std::fmt::Debug for OtlpHandle {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("OtlpHandle").finish_non_exhaustive()
        }
    }

    enum Instrument {
        Counter(opentelemetry::metrics::ObservableCounter<u64>),
        GaugeF64(opentelemetry::metrics::ObservableGauge<f64>),
    }

    impl OtlpHandle {
        /// A `tracing` layer that forwards spans and events to the OTLP
        /// tracer. Span names and fields map one-to-one.
        #[must_use]
        pub fn layer<S>(&self) -> impl Layer<S>
        where
            S: Subscriber + for<'span> LookupSpan<'span>,
        {
            tracing_opentelemetry::layer().with_tracer(self.tracer.tracer("crawlx"))
        }
    }

    impl Drop for OtlpHandle {
        fn drop(&mut self) {
            if let Err(e) = self.tracer.shutdown() {
                tracing::debug!(error = %e, "otlp tracer shutdown");
            }
            if let Err(e) = self.meter.shutdown() {
                tracing::debug!(error = %e, "otlp meter shutdown");
            }
        }
    }

    fn attrs(labels: &[(&'static str, String)]) -> Vec<KeyValue> {
        labels.iter().map(|(k, v)| KeyValue::new(*k, v.clone())).collect()
    }

    fn unit_str(unit: Unit) -> &'static str {
        match unit {
            Unit::None => "",
            Unit::Seconds => "s",
        }
    }

    /// Register one observable instrument per catalogued metric. Counters and
    /// gauges map directly; a histogram is exported as its `.count` and
    /// `.sum` counters plus a `.bucket{le}` cumulative counter so no
    /// observation is lost in translation.
    fn bridge(meter: &SdkMeterProvider, registry: &'static Metrics) -> Vec<Instrument> {
        let m = meter.meter("crawlx");
        let mut out = Vec::new();
        for def in registry.definitions() {
            let name = def.name;
            match def.kind {
                MetricKind::Counter => {
                    let inst = m
                        .u64_observable_counter(name)
                        .with_description(def.help)
                        .with_unit(unit_str(def.unit))
                        .with_callback(move |o| {
                            for s in registry.snapshot_family(name).unwrap_or_default() {
                                if let SeriesValue::Counter(c) = s.value {
                                    o.observe(c, &attrs(&s.labels));
                                }
                            }
                        })
                        .build();
                    out.push(Instrument::Counter(inst));
                }
                MetricKind::Gauge => {
                    let inst = m
                        .f64_observable_gauge(name)
                        .with_description(def.help)
                        .with_unit(unit_str(def.unit))
                        .with_callback(move |o| {
                            for s in registry.snapshot_family(name).unwrap_or_default() {
                                if let SeriesValue::Gauge(g) = s.value {
                                    o.observe(g, &attrs(&s.labels));
                                }
                            }
                        })
                        .build();
                    out.push(Instrument::GaugeF64(inst));
                }
                MetricKind::Histogram => {
                    let count = m
                        .u64_observable_counter(format!("{name}.count"))
                        .with_description(def.help)
                        .with_callback(move |o| {
                            for s in registry.snapshot_family(name).unwrap_or_default() {
                                if let SeriesValue::Histogram(h) = s.value {
                                    o.observe(h.count, &attrs(&s.labels));
                                }
                            }
                        })
                        .build();
                    let sum = m
                        .f64_observable_gauge(format!("{name}.sum"))
                        .with_description(def.help)
                        .with_unit(unit_str(def.unit))
                        .with_callback(move |o| {
                            for s in registry.snapshot_family(name).unwrap_or_default() {
                                if let SeriesValue::Histogram(h) = s.value {
                                    o.observe(h.sum, &attrs(&s.labels));
                                }
                            }
                        })
                        .build();
                    let bucket = m
                        .u64_observable_counter(format!("{name}.bucket"))
                        .with_description(def.help)
                        .with_callback(move |o| {
                            for s in registry.snapshot_family(name).unwrap_or_default() {
                                if let SeriesValue::Histogram(h) = s.value {
                                    for (le, c) in h.buckets {
                                        let mut a = attrs(&s.labels);
                                        a.push(KeyValue::new("le", le.to_string()));
                                        o.observe(c, &a);
                                    }
                                }
                            }
                        })
                        .build();
                    out.push(Instrument::Counter(count));
                    out.push(Instrument::GaugeF64(sum));
                    out.push(Instrument::Counter(bucket));
                }
            }
        }
        out
    }

    /// Start OTLP export (feature `otlp`): traces and the metrics catalog.
    ///
    /// # Errors
    /// [`TelemetryError::InvalidOtlpEndpoint`] for a malformed endpoint,
    /// [`TelemetryError::OtlpExporter`] when an exporter cannot be built.
    pub fn install(config: &OtlpConfig) -> Result<Option<OtlpHandle>, TelemetryError> {
        validate_endpoint(config)?;
        let mut resource = Resource::builder().with_service_name(config.service_name.clone());
        if !config.resource.is_empty() {
            resource = resource.with_attributes(
                config
                    .resource
                    .iter()
                    .map(|(k, v)| KeyValue::new(k.clone(), v.clone())),
            );
        }
        let resource = resource.build();
        let span_exporter = SpanExporter::builder()
            .with_tonic()
            .with_endpoint(&config.endpoint)
            .build()
            .map_err(|e| TelemetryError::OtlpExporter(Box::new(e)))?;
        let tracer = SdkTracerProvider::builder()
            .with_resource(resource.clone())
            .with_batch_exporter(span_exporter)
            .build();
        let metric_exporter = MetricExporter::builder()
            .with_tonic()
            .with_endpoint(&config.endpoint)
            .build()
            .map_err(|e| TelemetryError::OtlpExporter(Box::new(e)))?;
        let meter = SdkMeterProvider::builder()
            .with_resource(resource)
            .with_periodic_exporter(metric_exporter)
            .build();
        let instruments = bridge(&meter, Metrics::global());
        Ok(Some(OtlpHandle {
            tracer,
            meter,
            _instruments: instruments,
        }))
    }
}

pub use imp::{install, OtlpHandle};

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn cfg(endpoint: &str) -> OtlpConfig {
        OtlpConfig {
            endpoint: endpoint.to_owned(),
            service_name: "crawlx".to_owned(),
            resource: vec![("tenant_id".to_owned(), "t".to_owned())],
        }
    }

    #[test]
    fn endpoint_validation() {
        assert!(validate_endpoint(&cfg("http://collector:4317")).is_ok());
        assert!(validate_endpoint(&cfg("https://c")).is_ok());
        assert!(matches!(
            validate_endpoint(&cfg("nope")),
            Err(TelemetryError::InvalidOtlpEndpoint(_))
        ));
        assert!(matches!(
            validate_endpoint(&cfg("http://")),
            Err(TelemetryError::InvalidOtlpEndpoint(_))
        ));
    }

    #[cfg(not(feature = "otlp"))]
    #[test]
    fn disabled_feature_is_a_noop_but_validates() {
        assert!(!enabled());
        assert!(install(&cfg("http://collector:4317")).unwrap().is_none());
        assert!(matches!(
            install(&cfg("not a url")),
            Err(TelemetryError::InvalidOtlpEndpoint(_))
        ));
    }

    #[cfg(feature = "otlp")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn enabled_feature_builds_exporters_without_a_collector() {
        assert!(enabled());
        assert!(matches!(
            install(&cfg("nope")),
            Err(TelemetryError::InvalidOtlpEndpoint(_))
        ));
        // Building the pipeline does not connect; an unreachable collector
        // only surfaces as dropped batches (a telemetry gap, not a bug).
        let handle = install(&cfg("http://127.0.0.1:1")).unwrap();
        assert!(handle.is_some());
        tokio::task::spawn_blocking(move || drop(handle)).await.unwrap();
    }
}
