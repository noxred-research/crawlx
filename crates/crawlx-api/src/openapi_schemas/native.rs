//! Native acquisition schemas, composed with the existing article schema mirror.

use super::{scrape::ContentPolicy, Schemas};
use serde_json::{json, Map, Value};

fn acquisition() -> Value {
    let backend = json!({"type":"string", "enum":["native_http", "native_browser"]});
    json!({
        "type":"object", "additionalProperties":false,
        "properties": {
            "schemaVersion":{"type":"integer", "const":1, "default":1},
            "profileId":{"type":"string", "minLength":1, "maxLength":128, "default":"native-v1"},
            "backendIds":{"type":"array", "minItems":1, "maxItems":4, "items":backend, "default":["native_http"]},
            "fallbackBackendIds":{"type":"array", "maxItems":4, "items":backend, "default":[]},
            "maxAttempts":{"type":"integer", "minimum":1, "maximum":8, "default":2},
            "maxElapsedMs":{"type":"integer", "minimum":1, "maximum":300000, "default":60000},
            "maxDecodedBytes":{"type":"integer", "minimum":1, "maximum":67108864, "default":16777216},
            "maxNetworkRequests":{"type":"integer", "minimum":1, "maximum":512, "default":64},
            "retryOn":{"type":"array", "maxItems":5, "items":{"type":"string", "enum":["transport", "target5xx", "rate_limit", "challenge", "content_mismatch"]}, "default":["transport"]},
            "validation":{
                "type":"object", "additionalProperties":false,
                "properties":{
                    "ruleSetVersion":{"type":"integer", "const":1, "default":1},
                    "expectedContentTypes":{"type":"array", "maxItems":16, "items":{"type":"string", "minLength":1, "maxLength":128, "pattern":"/"}},
                    "requiredSelectors":{"type":"array", "maxItems":16, "items":{"type":"string", "minLength":1, "maxLength":2048}, "description":"CSS syntax is compiled before native admission."},
                    "minimumTextBytes":{"type":"integer", "minimum":0, "maximum":67108864, "default":0},
                    "onContentMismatch":{"type":"string", "enum":["report", "fail"], "default":"report"}
                }
            }
        }
    })
}

fn source_discovery() -> Value {
    let lastmod = json!({
        "type":"object", "additionalProperties":false,
        "description":"Inclusive UTC URL-entry lastmod bounds, never publication dates or index-file traversal bounds. At least one non-null bound is required; native admission rejects lower after upper.",
        "anyOf":[
            {"required":["lower"],"properties":{"lower":{"type":"string","format":"date-time"}}},
            {"required":["upper"],"properties":{"upper":{"type":"string","format":"date-time"}}}
        ],
        "properties":{
            "lower":{"type":["string","null"],"format":"date-time"},
            "upper":{"type":["string","null"],"format":"date-time"},
            "missingOrUnparseable":{"type":"string","enum":["include","exclude"],"default":"include"}
        }
    });
    json!({
        "type":"object", "additionalProperties":false,
        "properties":{
            "version":{"type":"integer","const":1,"default":1},
            "mode":{"type":"string","enum":["explore","probe"],"default":"explore"},
            "maxSourceDocuments":{"type":"integer","minimum":1,"maximum":64,"default":16},
            "maxFeedBytes":{"type":"integer","minimum":1,"maximum":8388608,"default":2097152},
            "maxEntries":{"type":"integer","minimum":1,"maximum":10000,"default":1000},
            "maxNesting":{"type":"integer","minimum":1,"maximum":64,"default":32},
            "maxSourceDepth":{"type":"integer","minimum":1,"maximum":16,"default":5},
            "conventionalPaths":{"type":"array","maxItems":16,"items":{"type":"string","maxLength":2048},"default":[]},
            "maxCategoryLinks":{"type":"integer","minimum":0,"maximum":256,"default":32},
            "maxFocusedLinks":{"type":"integer","minimum":0,"maximum":1000,"default":64},
            "minSitemapArticles":{"type":"integer","minimum":1,"maximum":1000,"default":1},
            "sitemapLastmod":{"anyOf":[lastmod,{"type":"null"}],"default":null},
            "sufficientMainChars":{"type":"integer","minimum":1,"maximum":1000000,"default":300},
            "readMoreHops":{"type":"integer","minimum":0,"maximum":4,"default":0},
            "mediaProbes":{"type":"integer","minimum":0,"maximum":16,"default":0},
            "mediaHeaderBytes":{"type":"integer","minimum":24,"maximum":65536,"default":65536},
            "maxMediaPixels":{"type":"integer","minimum":1,"maximum":100000000,"default":40000000},
            "connectors":{"type":"array","maxItems":8,"default":[],"items":{
                "type":"object","additionalProperties":false,"required":["provider","endpoint"],
                "properties":{
                    "provider":{"type":"string","enum":["news_search","trends_search","web_archive_index"]},
                    "endpoint":{"type":"string","format":"uri","maxLength":4096},
                    "archiveBase":{"type":["string","null"],"format":"uri","maxLength":4096}
                }
            }}
        }
    })
}

fn archive_config() -> Value {
    json!({"type":"object","additionalProperties":false,
    "description":"Opt-in retained-resource export. ZDR and unavailable require_complete capture are refused before acquisition.",
    "properties":{
        "version":{"type":"integer","const":1,"default":1},
        "format":{"type":"string","enum":["warc","wacz"],"default":"wacz"},
        "capture":{"type":"string","enum":["available","require_complete"],"default":"available"},
        "maxBytes":{"type":"integer","minimum":1,"maximum":1073741824,"default":1073741824},
        "maxRecordBytes":{"type":"integer","minimum":1,"maximum":16777216,"default":16777216},
        "maxRecords":{"type":"integer","minimum":1,"maximum":10000,"default":10000}
    }})
}

fn archive_artifact() -> Value {
    json!({"type":"object","additionalProperties":false,"required":["id","digest"],
        "properties":{"id":{"type":"string","format":"uuid"},
            "digest":{"type":"string","pattern":"^[0-9a-f]{64}$","description":"Stored artifact BLAKE3 identity, not original wire bytes."}}})
}

fn archive_dependency() -> Value {
    json!({"type":"object","additionalProperties":false,"required":["export","ordinal"],
        "properties":{"export":{"type":"string","format":"uuid"},
            "ordinal":{"type":"integer","minimum":0,"maximum":9223372036854775807i64}},
        "description":"Committed same-tenant source record; deletion revokes the dependent closure."})
}

fn archive_facts() -> Value {
    json!({"type":"object","additionalProperties":false,
    "required":["captureSource","sourceProtocol","representation","bodyState","redactionRevision","transformations","sourceEvent","capturedAt"],
    "properties":{
        "captureSource":{"type":"string"},"sourceProtocol":{"type":["string","null"]},
        "representation":{"type":"string","enum":["wire_http","normalized_http","rendered_dom","screenshot","extracted_text","protocol_resource"]},
        "bodyState":{"type":"string","enum":["complete","prefix","unknown"]},
        "redactionRevision":{"type":"string"},"transformations":{"type":"array","items":{"type":"string"}},
        "sourceEvent":{"type":"string"},"capturedAt":{"type":"string","format":"date-time"}
    }})
}

fn archive_manifest() -> Value {
    json!({"type":"object","additionalProperties":false,
    "required":["schemaVersion","tenant","run","created","complete","records","omissions"],
    "properties":{
        "schemaVersion":{"type":"integer","const":1},"tenant":{"type":"string","format":"uuid"},
        "run":{"type":"string","format":"uuid"},"created":{"type":"string","format":"date-time"},
        "complete":{"type":"boolean","const":false,"description":"Current retained-resource producers cannot establish complete original-wire capture."},
        "records":{"type":"integer","minimum":0,"maximum":10000},
        "omissions":{"type":"array","items":{"type":"object","additionalProperties":false,
            "required":["sourceEvent","reason"],"properties":{"sourceEvent":{"type":"string"},"reason":{"type":"string"}}}}
    }})
}

fn archive_export() -> Value {
    json!({"type":"object","additionalProperties":false,
    "required":["id","tenant","run","config","state","createdAt","expiresAt","fence","leaseUntil",
        "records","bytes","artifact","index","manifest","terminalReason","failure"],
    "properties":{
        "id":{"type":"string","format":"uuid"},"tenant":{"type":"string","format":"uuid"},
        "run":{"type":"string","format":"uuid"},"config":archive_config(),
        "state":{"type":"string","enum":["recording","published","failed","deleted"],
            "description":"Deleted exports return 404 rather than exposing this catalog payload."},
        "createdAt":{"type":"string","format":"date-time"},"expiresAt":{"type":["string","null"],"format":"date-time"},
        "fence":{"type":"integer","minimum":0},"leaseUntil":{"type":"string","format":"date-time"},
        "records":{"type":"integer","minimum":0,"maximum":10000},"bytes":{"type":"integer","minimum":0,"maximum":1073741824},
        "artifact":{"anyOf":[archive_artifact(),{"type":"null"}],"description":"Final object, available only after publication."},
        "index":{"anyOf":[archive_artifact(),{"type":"null"}],
            "description":"Adjacent application/cdxj artifact for WARC. WACZ keeps its index inside the package."},
        "manifest":{"anyOf":[archive_manifest(),{"type":"null"}]},
        "terminalReason":{"type":"string","enum":["frontier_exhausted","limit_reached","deadline_reached","policy_stopped",
            "cancelled","fatal_error","recovery_exhausted","authorization_revoked"]},
        "failure":{"type":["string","null"],"enum":[null,"capture_unavailable","limit_exceeded","invalid_capture"]}
    }})
}

fn archive_record() -> Value {
    json!({"type":"object","additionalProperties":false,
    "required":["export","ordinal","recordId","artifact","offset","length","payloadDigest","target","facts","mime","dependency"],
    "properties":{
        "export":{"type":"string","format":"uuid"},"ordinal":{"type":"integer","minimum":0,"maximum":9223372036854775807i64},
        "recordId":{"type":"string"},"artifact":archive_artifact(),"offset":{"type":"integer","minimum":0},
        "length":{"type":"integer","minimum":1},"payloadDigest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
        "target":{"type":"string","format":"uri"},"facts":archive_facts(),"mime":{"type":"string"},
        "dependency":{"anyOf":[archive_dependency(),{"type":"null"}]}
    }})
}

fn archive_response(operation: &mut Value, schema: Value, description: &str) {
    operation["responses"]["200"] = json!({"description":description,
        "content":{"application/json":{"schema":schema}}});
    operation["responses"]["410"]["description"] =
        json!("Source retention expired; no content-bearing archive metadata is returned.");
}

fn create(schemas: &mut Schemas) -> Value {
    let mut properties = Map::new();
    // These existing groups still enforce their detailed runtime admission contracts.
    for name in [
        "crawl",
        "limits",
        "scope",
        "dynamic",
        "safety",
        "capture",
        "retention",
        "politeness",
        "fetch",
        "extensions",
        "datasets",
        "protocol",
    ] {
        properties.insert(name.into(), json!({"type":"object"}));
    }
    properties.insert("scope".into(), json!({
        "type":"object",
        "properties":{
            "discovery":{"anyOf":[source_discovery(),{"type":"null"}],"default":null},
            "sources":{"type":"array","items":{"type":"string","enum":[
                "html","feeds","sitemap","categories","conventional","news_search","trends_search","archive"
            ]},"default":[]},
            "maxKnownUrls":{"type":"integer","minimum":1,"default":100000}
        }
    }));
    properties.insert(
        "output".into(),
        json!({
            "type":"object",
            "properties":{
                "archive":{"anyOf":[{"type":"null"},archive_config()],"default":null}
            }
        }),
    );
    properties.insert("seedUrl".into(), json!({"type":"string", "format":"uri"}));
    properties.insert(
        "mode".into(),
        json!({"type":"string", "enum":["static", "dynamic", "hybrid"], "default":"hybrid"}),
    );
    properties.insert("seed".into(), json!({"type":["integer", "null"], "minimum":0}));
    properties.insert("roles".into(), json!({"type":"array", "items":{"type":"object"}}));
    properties.insert("runsPerRole".into(), json!({"type":"integer", "minimum":0, "maximum":255, "description":"Admission clamps to 1..=10 and caps roles times runs at 64."}));
    properties.insert("roleOrder".into(), json!({"type":"string"}));
    properties.insert("targetIsolation".into(), json!({"type":"string"}));
    properties.insert(
        "crossPrincipalAttribution".into(),
        json!({"type":"boolean", "default":true}),
    );
    properties.insert(
        "acquisition".into(),
        json!({"anyOf":[acquisition(), {"type":"null"}]}),
    );
    properties.insert("cache".into(), json!({
        "type":["object", "null"], "additionalProperties":false,
        "properties":{
            "schemaVersion":{"type":"integer", "const":1, "default":1},
            "mode":{"type":"string", "enum":["read_write", "bypass", "disabled", "read_only", "write_only"], "default":"read_write"},
            "maxAgeMs":{"type":"integer", "minimum":0, "maximum":31536000000u64, "default":172800000},
            "developmentReplay":{"type":"boolean", "default":false},
            "freshness":{"type":"string", "enum":["retained", "head", "conditional_get"], "default":"retained"}
        }
    }));
    properties.insert("orchestration".into(), json!({"type":["object", "null"], "description":"Bounded queue, producer and recrawl policy; validated during admission."}));
    properties.insert("scrape".into(), json!({"type":["object", "null"]}));
    let content = schemas.req.subschema_for::<ContentPolicy>();
    properties.insert(
        "extract".into(),
        json!({
            "type":"object", "additionalProperties":false,
            "properties":{
                "content":{"anyOf":[content, {"type":"null"}]},
                "customFields":{"type":"array", "items":{"type":"object"}},
                "detectSecrets":{"type":"boolean", "default":false},
                "forms":{"type":"boolean", "default":true},
                "pageType":{"type":"boolean", "default":true},
                "xhr":{"type":"boolean", "default":false},
                "knowledgeBase":{"type":"boolean", "default":false},
                "kbEndpoints":{"type":"boolean", "default":false},
                "validateSecrets":{"type":"boolean", "default":false},
                "formFill":{"type":"object"}
            }
        }),
    );
    json!({"type":"object", "additionalProperties":false, "required":["seedUrl"], "properties":properties})
}

fn request_body(operation: &mut Value, schema: Value, description: &str) {
    operation["requestBody"] = json!({
        "required":true, "description":description,
        "content":{"application/json":{"schema":schema}}
    });
}

fn required_header(operation: &mut Value, name: &str, description: &str) {
    if let Some(parameters) = operation["parameters"].as_array_mut() {
        parameters.push(json!({
            "name":name, "in":"header", "required":true, "description":description,
            "schema":{"type":"string", "minLength":1, "maxLength":128}
        }));
    }
}

fn cursor() -> Value {
    json!({"type":["object","null"], "additionalProperties":false,
        "required":["source","sourceDigest","position"],
        "properties":{
            "source":{"type":"string","minLength":1,"maxLength":128},
            "sourceDigest":{"type":"string","pattern":"^[0-9a-f]{64}$"},
            "position":{"type":"integer","minimum":0}
        }
    })
}

pub(super) fn apply(schemas: &mut Schemas, operation: &mut Value, id: &str) {
    match id {
        "listArchives" => archive_response(operation, json!({"type":"object","required":["archives"],
            "properties":{"archives":{"type":"array","maxItems":100,"items":archive_export()}}}),
            "Retained same-tenant export progress; expired/deleted exports are excluded."),
        "getArchive" => archive_response(operation, archive_export(), "Retained progress, terminal failure or published manifest."),
        "listArchiveRecords" => {
            archive_response(operation, json!({"type":"object","required":["records","next"],
                "properties":{"records":{"type":"array","maxItems":64,"items":archive_record()},
                    "next":{"type":["integer","null"],"minimum":0,"maximum":9223372036854775807i64}}}),
                "Bounded committed shard descriptors, never uncommitted offsets.");
            if let Some(parameters) = operation["parameters"].as_array_mut() {
                parameters.push(json!({"name":"after","in":"query","required":false,
                    "schema":{"type":"integer","minimum":0,"maximum":9223372036854775807i64}}));
                parameters.push(json!({"name":"limit","in":"query","required":false,
                    "schema":{"type":"integer","minimum":1,"maximum":64,"default":64}}));
            }
        }
        "eraseArchive" => archive_response(operation, json!({"type":"object","required":["id","deleted"],
            "properties":{"id":{"type":"string","format":"uuid"},"deleted":{"type":"boolean","const":true}}}),
            "Archive/dependent catalog revoked and physical artifact erasure acknowledged. Repeating resumes cleanup."),
        "downloadArchive" => {
            operation["responses"]["200"] = json!({"description":"Published retained object streamed with bounded memory; no live fallback.",
                "headers":{"Cache-Control":{"schema":{"type":"string","const":"private, no-store"}}},
                "content":{"application/warc":{"schema":{"type":"string","format":"binary"}},
                    "application/wacz+zip":{"schema":{"type":"string","format":"binary"}}}});
            operation["responses"]["409"]["description"] = json!("Archive is recording or failed; no published manifest exists.");
            operation["responses"]["410"]["description"] = json!("Archive source or dependency expired.");
        }
        "getArtifact" => {
            for mime in ["application/warc","application/wacz+zip","application/cdxj"] {
                operation["responses"]["200"]["content"][mime] = json!({"schema":{"type":"string","format":"binary"}});
            }
        }
        "createCrawl" => {
            operation["requestBody"] = json!({
                "required":true,
                "description":"Native crawl configuration. Acquisition and article policies are opt-in. Nested legacy groups retain their detailed runtime admission contracts.",
                "content":{"application/json":{"schema":create(schemas)}}
            });
        }
        "appendRequests" | "importRequests" => {
            let input = if id == "appendRequests" {
                json!({"type":"array","maxItems":1000,"items":{
                    "type":"object","additionalProperties":false,"required":["url"],
                    "properties":{
                        "url":{"type":"string","format":"uri"},
                        "method":{"type":"string","const":"GET","default":"GET"},
                        "route":{"type":"string","maxLength":128,"default":"default"},
                        "metadata":{"type":"object","maxProperties":64},
                        "depth":{"type":"integer","minimum":0,"maximum":65535},
                        "priority":{"type":"integer","minimum":-2147483648,"maximum":2147483647}
                    }
                }})
            } else {
                json!({"type":"object","description":"Pinned declarative source export; source-specific fields are strictly validated."})
            };
            let name = if id == "appendRequests" { "requests" } else { "export" };
            let mut properties = Map::new();
            properties.insert(name.to_owned(), input);
            properties.insert("producerEpoch".into(), json!({"type":"integer","minimum":1}));
            properties.insert("expectedCursor".into(), cursor());
            properties.insert("nextCursor".into(), cursor());
            request_body(operation, json!({"type":"object","additionalProperties":false,
                "required":[name,"producerEpoch"],"properties":properties}),
                "Server derives tenant and principal; body authority fields are not accepted.");
            required_header(operation, "Idempotency-Key", "Stable printable batch receipt key.");
        }
        "sealRequests" => request_body(operation, json!({
            "type":"object","additionalProperties":false,"required":["producerEpoch"],
            "properties":{"producerEpoch":{"type":"integer","minimum":1}}
        }), "Seal only the matching current producer epoch."),
        "captureAdaptiveSelector" => request_body(operation, json!({
            "type":"object","additionalProperties":false,"required":["page","node","source","schema"],
            "properties":{
                "page":{"type":"integer"},"node":{"type":"integer","minimum":0},
                "source":{"type":"string"},"schema":{"type":"string"},
                "expiresAt":{"type":["string","null"],"format":"date-time"},
                "threshold":{"type":["integer","null"],"minimum":0,"maximum":1000},
                "runnerUpMargin":{"type":["integer","null"],"minimum":1,"maximum":1000},
                "maxCandidates":{"type":["integer","null"],"minimum":1,"maximum":10000}
            }
        }), "Capture from retained authorized HTML; the server assigns identity and scope."),
        "relocateAdaptiveSelector" => request_body(operation, json!({
            "type":"object","additionalProperties":false,"required":["page","source","schema"],
            "properties":{"page":{"type":"integer"},"source":{"type":"string"},"schema":{"type":"string"}}
        }), "Relocation reads retained content only and never sends a network request."),
        "putKvValue" | "deleteKvValue" => {
            required_header(operation, "If-Match", "Exact quoted value version; use \"0\" for creation.");
        }
        "dropKvStore" => {
            operation["responses"]["200"] = json!({
                "description":"Namespace permanently dropped.",
                "content":{"application/json":{"schema":{
                    "type":"object","additionalProperties":false,"required":["dropped"],
                    "properties":{"dropped":{"type":"boolean","const":true}}
                }}}
            });
        }
        "getAcquisitionCapabilities" => {
            let backend = json!({
                "type":"object",
                "required":["backendId", "implementation", "version", "buildDigest", "browser", "available", "limitations"],
                "properties":{
                    "backendId":{"type":"string"}, "implementation":{"type":"string"}, "version":{"type":"string"},
                    "buildDigest":{"type":["string", "null"]}, "browser":{"type":["object", "null"]},
                    "available":{"type":"boolean"}, "limitations":{"type":"array", "items":{"type":"string"}}
                }
            });
            let worker = json!({
                "type":"object", "required":["schemaVersion", "worker", "heartbeatAt", "backends", "data"],
                "properties":{
                    "schemaVersion":{"type":"integer", "const":1},
                    "worker":{"type":"string", "format":"uuid"},
                    "heartbeatAt":{"type":"string", "format":"date-time"},
                    "data":{"type":"object","additionalProperties":false,
                        "required":["destinations","languageBundles"],
                        "properties":{
                            "destinations":{"type":"object","maxProperties":64,"additionalProperties":{"type":"boolean"}},
                            "languageBundles":{"type":"array","maxItems":8,"uniqueItems":true,"items":{"type":"string","pattern":"^[0-9a-f]{64}$"}}
                        }},
                    "backends":{"type":"array", "maxItems":4, "items":backend}
                }
            });
            let schema = json!({
                "type":"object", "required":["schemaVersion", "scope", "observedAt", "maxWorkerAgeMs", "maxWorkers", "truncated", "workers"],
                "properties":{
                    "schemaVersion":{"type":"integer", "const":1},
                    "scope":{"type":"string", "const":"live_worker_registry"},
                    "observedAt":{"type":"string", "format":"date-time"},
                    "maxWorkerAgeMs":{"type":"integer", "const":90000},
                    "maxWorkers":{"type":"integer", "const":256},
                    "truncated":{"type":"boolean"},
                    "workers":{"type":"array", "maxItems":256, "items":worker}
                }
            });
            operation["responses"]["200"] = json!({
                "description":"Fresh, bounded worker-reported capabilities. A heartbeat is evidence, not a future worker-health guarantee.",
                "content":{"application/json":{"schema":schema}}
            });
        }
        _ => {}
    }
}
