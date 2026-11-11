//! Native acquisition schemas, composed with the existing article schema mirror.

use super::{scrape::ContentPolicy, Schemas};
use serde_json::{json, Map, Value};

fn acquisition() -> Value {
    let backend = json!({"type":"string", "enum":["native_http", "native_browser", "acquisition_service"]});
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
            "articleMemo":{"type":"object","additionalProperties":false,
                "description":"Explicit bounded repeat suppression after current admission; hashes never grant authority.",
                "properties":{
                    "enabled":{"type":"boolean","default":false},
                    "maxEntries":{"type":"integer","minimum":1,"maximum":100000,"default":20000}
                }},
            "categoryCache":{"type":"object","additionalProperties":false,
                "description":"Representation and role-scoped proposals expire by worker clock; current admission remains authoritative.",
                "properties":{
                    "enabled":{"type":"boolean","default":true},
                    "ttlSeconds":{"type":"integer","minimum":1,"maximum":604800,"default":86400}
                }},
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
        "dedupe":{"type":"string","enum":["none","collection","tenant"],"default":"none",
            "description":"Optional revisit deduplication: none disables matching and is omitted when serialized; collection reuses committed compatible sources within this export; tenant also permits complete native bodies from opted-in published sources with local package closure. Retained DOM and text reuse stays within the same run."},
        "maxBytes":{"type":"integer","minimum":1,"maximum":1073741824,"default":1073741824,
            "description":"Total encoded-byte ceiling; must be at least maxRecordBytes. Lowering this below the default 16 MiB record ceiling requires an explicit smaller maxRecordBytes."},
        "rolloverBytes":{"type":"integer","minimum":1,"maximum":1073741824,
            "description":"Hard encoded-byte cap per WARC member; no larger than maxBytes. Only WACZ exports support rollover."},
        "maxRecordBytes":{"type":"integer","minimum":1,"maximum":16777216,"default":16777216},
        "maxRecords":{"type":"integer","minimum":1,"maximum":10000,"default":10000}
    },
    "allOf":[
        {"if":{"required":["rolloverBytes"]},
            "then":{"properties":{"format":{"const":"wacz"}}}},
        {"if":{"not":{"required":["maxRecordBytes"]}},
            "then":{"properties":{"maxBytes":{"minimum":16777216}}}}
    ]})
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

fn archive_custody() -> Value {
    json!({"type":"object","additionalProperties":false,"required":["sensitivity","expiresAt"],
        "description":"Inherited source classification and earliest deadline; packaging cannot weaken either. Sensitive archive content requires artifacts:read_sensitive; progress metadata is redacted for other callers.",
        "properties":{
            "sensitivity":{"type":"string","enum":["content","sensitive"]},
            "expiresAt":{"type":["string","null"],"format":"date-time"}
        },
        "allOf":[{"if":{"properties":{"sensitivity":{"const":"sensitive"}}},
            "then":{"properties":{"expiresAt":{"type":"string","format":"date-time"}}}}]
    })
}

fn archive_payload_key() -> Value {
    json!({"type":"object","additionalProperties":false,
        "required":["principal","variant","representation","redactionRevision","mime"],
        "description":"Exact approved reuse domain, not authorization to access source bytes.",
        "properties":{
            "principal":{"type":"string"},"variant":{"type":"string","pattern":"^[0-9a-f]{64}$"},
            "representation":{"type":"string","enum":["wire_http","normalized_http","rendered_dom","screenshot","extracted_text","protocol_resource"]},
            "redactionRevision":{"type":"string"},"mime":{"type":"string"}
        }
    })
}

fn archive_manifest() -> Value {
    json!({"type":"object","additionalProperties":false,
    "required":["schemaVersion","tenant","run","created","complete","records","omissions","custody"],
    "properties":{
        "schemaVersion":{"type":"integer","const":1},"tenant":{"type":"string","format":"uuid"},
        "run":{"type":"string","format":"uuid"},"created":{"type":"string","format":"date-time"},
        "complete":{"type":"boolean","const":false,"description":"Current retained-resource producers cannot establish complete original-wire capture."},
        "records":{"type":"integer","minimum":0,"maximum":10000},
        "custody":archive_custody(),
        "materializedDependencies":{"type":"integer","minimum":1,
            "description":"Standalone committed source records embedded to close cross-export revisit dependencies; omitted when zero."},
        "omissions":{"type":"array","items":{"type":"object","additionalProperties":false,
            "required":["sourceEvent","reason"],"properties":{"sourceEvent":{"type":"string"},"reason":{"type":"string"}}}}
    }})
}

fn archive_export() -> Value {
    json!({"type":"object","additionalProperties":false,
    "required":["id","tenant","run","config","state","createdAt","expiresAt","fence","leaseUntil",
        "records","bytes","artifact","index","manifest","terminalReason","failure","custody"],
    "properties":{
        "id":{"type":"string","format":"uuid"},"tenant":{"type":"string","format":"uuid"},
        "run":{"type":"string","format":"uuid"},"config":archive_config(),
        "state":{"type":"string","enum":["recording","published","failed","deleted"],
            "description":"Deleted exports return 404 rather than exposing this catalog payload."},
        "createdAt":{"type":"string","format":"date-time"},"expiresAt":{"type":["string","null"],"format":"date-time"},
        "custody":archive_custody(),
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
    "required":["export","ordinal","recordId","artifact","offset","length","payloadDigest","target","facts","mime","dependency","custody"],
    "properties":{
        "export":{"type":"string","format":"uuid"},"ordinal":{"type":"integer","minimum":0,"maximum":9223372036854775807i64},
        "recordId":{"type":"string"},"artifact":archive_artifact(),"offset":{"type":"integer","minimum":0},
        "sourceArtifact":archive_artifact(),
        "custody":archive_custody(),
        "payloadKey":archive_payload_key(),
        "length":{"type":"integer","minimum":1},"payloadDigest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
        "target":{"type":"string","format":"uri"},"facts":archive_facts(),"mime":{"type":"string"},
        "dependency":{"anyOf":[archive_dependency(),{"type":"null"}]}
    },
    "allOf":[{"if":{"properties":{"custody":{"properties":{"sensitivity":{"const":"sensitive"}}}}},
        "then":{"required":["sourceArtifact"]}}]})
}

fn archive_response(operation: &mut Value, schema: Value, description: &str) {
    operation["responses"]["200"] = json!({"description":description,
        "content":{"application/json":{"schema":schema}}});
    operation["responses"]["410"]["description"] =
        json!("Source retention expired; no content-bearing archive metadata is returned.");
}

fn browser_capture() -> Value {
    let records = json!({"type":"integer","minimum":1,"maximum":5000});
    let bytes = json!({"type":"integer","minimum":1,"maximum":8388608});
    json!({
        "type":"object", "additionalProperties":false,
        "description":"Opt-in browser evidence. Static mode cannot enable browser capture. MHTML, PDF, phase resources and downloads require retained content, not zero data retention.",
        "properties":{
            "xhr":{"anyOf":[{"type":"null"}, {
                "type":"object","additionalProperties":false,
                "required":["urlPatterns","maxRecords","maxBytes"],
                "properties":{
                    "urlPatterns":{"type":"array","minItems":1,"maxItems":128,
                        "items":{"type":"string","minLength":1,"maxLength":8192,
                            "description":"URL pattern with * as the only wildcard."}},
                    "maxRecords":records,"maxBytes":bytes
                }
            }]},
            "diagnostics":{"anyOf":[{"type":"null"}, {
                "type":"object","additionalProperties":false,"required":["maxRecords","maxBytes"],
                "properties":{"maxRecords":records,"maxBytes":bytes}
            }]},
            "mhtml":{"type":"boolean","default":false},
            "pdf":{"type":"boolean","default":false},
            "phaseResources":{"type":"boolean","default":false},
            "downloads":{"type":"array","maxItems":32,"default":[],"items":{
                "type":"object","additionalProperties":false,"required":["url","maxBytes","timeoutMs"],
                "properties":{
                    "url":{"type":"string","format":"uri","pattern":"^https?://",
                        "description":"HTTP(S) URL without credentials or fragments; runtime egress and navigation policy still applies."},
                    "maxBytes":{"type":"integer","minimum":1,"maximum":16777216},
                    "timeoutMs":{"type":"integer","minimum":1,"maximum":120000}
                }
            }}
        }
    })
}

fn fetch_controls() -> Value {
    let mime = json!({
        "type":"string","minLength":3,"maxLength":100,
        "pattern":"^[-A-Za-z0-9!#$&^_.+]+/[-A-Za-z0-9!#$&^_.+]+$"
    });
    let statuses = json!({
        "type":"array","items":{"type":"integer","minimum":100,"maximum":599},"default":[]
    });
    json!({
        "type":"object",
        "properties":{
            "preflight":{"anyOf":[{"type":"null"},{
                "type":"object","additionalProperties":false,
                "properties":{
                    "maxContentLength":{"type":["integer","null"],"minimum":1,"maximum":67108864},
                    "contentTypes":{"type":"array","maxItems":16,"items":mime,"default":[]}
                }
            }]},
            "declaration":{"anyOf":[{"type":"null"},{
                "type":"object","additionalProperties":false,
                "properties":{
                    "contentType":{"anyOf":[{"type":"null"},mime]},
                    "charset":{"type":["string","null"],"minLength":1,"maxLength":128,
                        "pattern":"^[ -~]*[!-~][ -~]*$"},
                    "statuses":{"type":"object","additionalProperties":false,
                        "description":"Disjoint allow and deny sets. Conflicts fail runtime admission.",
                        "properties":{"allow":statuses,"deny":statuses}}
                }
            }]},
            "oversize":{"type":["string","null"],"enum":[null,"truncate","refuse"]},
            "identityProfile":{"type":["string","null"],"pattern":"^[0-9a-f]{64}$",
                "description":"Digest of the installed native HTTP identity profile. Requires URL-only static mode without custom TLS, User-Agent, headers, preflight, skip-TLS or acquisitionService."},
            "acquisitionService":{"type":["string","null"],"minLength":1,"maxLength":128,
                "description":"Operator registry id of an approved HTML acquisition service, never an endpoint. Requires URL-only static mode without headers, cookies, User-Agent, proxy, preflight or skip-TLS, and couples acquisition.backendIds to [acquisition_service]."}
        }
    })
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
        "extensionRecipe",
        "datasets",
        "protocol",
    ] {
        properties.insert(name.into(), json!({"type":"object"}));
    }
    properties.insert("fetch".into(), fetch_controls());
    properties.insert("dynamic".into(), json!({
        "type":"object",
        "properties":{
            "maxPageRevisits":{
                "type":"integer","minimum":0,"maximum":128,"default":8,
                "description":"Additional observed renditions retained per canonical URL, keyed by observation epoch and explicit revisit generation. The first rendition remains canonical. Zero keeps only the first and marks later observations revisit_cap_reached; omission preserves existing specification hashes."
            },
            "browserProfile":{
                "type":["object","null"],
                "properties":{
                    "name":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_-]+$"},
                    "saveChanges":{"type":"boolean","default":true},
                    "generation":{"type":"integer","minimum":0,"maximum":9_223_372_036_854_775_807_i64,"default":0,
                        "description":"Exact retained generation to restore. 0 creates the namespace and is refused when one exists; N >= 1 restores that generation or fails, never an empty profile. With saveChanges the run commits generation N + 1."}
                },
                "required":["name"]
            }
        }
    }));
    properties.insert(
        "datasets".into(),
        json!({
            "type":"object",
            "properties":{"feeds":{"type":"array","maxItems":64,"items":super::datasets::feed_declaration()}}
        }),
    );
    properties.insert(
        "capture".into(),
        json!({
            "type":"object",
            "properties":{"browser":browser_capture()}
        }),
    );
    properties.insert("scope".into(), json!({
        "type":"object",
        "properties":{
            "strategy":{
                "type":"string",
                "enum":["breadth_first","depth_first","priority","bfs","breadth-first","dfs","depth-first"],
                "default":"breadth_first",
                "description":"URL frontier ordering: breadth_first visits shallowest URLs first (the default), depth_first visits the deepest, most recently discovered URL first, and priority uses surface scores. bfs and breadth-first are aliases for breadth_first; dfs and depth-first are aliases for depth_first. Stored configurations use canonical names."
            },
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
    properties.insert(
        "scrape".into(),
        json!({
            "type":["object", "null"],
            "properties":{"options":native_scrape_options()}
        }),
    );
    let content = schemas.req.subschema_for::<ContentPolicy>();
    let outputs = schemas
        .req
        .subschema_for::<super::outputs::ContentOutputOptions>();
    let decode = schemas.req.subschema_for::<super::outputs::DecodeOptions>();
    let markup = schemas.req.subschema_for::<super::outputs::MarkupRetention>();
    properties.insert(
        "extract".into(),
        json!({
            "type":"object", "additionalProperties":false,
            "properties":{
                "content":{"anyOf":[content, {"type":"null"}]},
                "outputs":{"anyOf":[outputs, {"type":"null"}]},
                "decode":{"anyOf":[decode, {"type":"null"}]},
                "markup":{"anyOf":[markup, {"type":"null"}]},
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

fn native_scrape_options() -> Value {
    json!({
        "type":"object",
        "properties":{
            "archiveBehavior":{"anyOf":[{"type":"null"},{
                "type":"object","additionalProperties":false,"required":["id","version","digest","phase"],
                "description":"Exact immutable operator registration, executed after checked initial navigation. Requires a browser; never accepts recipe contents or executable sources.",
                "properties":{
                    "id":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_.-]+$"},
                    "version":{"type":"integer","minimum":1,"maximum":4294967295u64},
                    "digest":{"type":"string","pattern":"^[0-9a-f]{64}$"},
                    "phase":{"type":"string","const":"post_navigation"}
                }
            }]},
            "actions":{"type":"array","maxItems":50,"items":{
                "type":"object","required":["type"],"properties":{"type":{"type":"string"}},
                "allOf":[{"if":{"properties":{"type":{"const":"fill"}}},
                    "then":{"required":["selector","text"],"properties":{
                        "selector":{"type":"string"},"text":{"type":"string"}
                    }}}]
            }}
        },
        "allOf":[{
            "if":{"required":["archiveBehavior"],"properties":{"archiveBehavior":{"type":"object"}}},
            "then":{"properties":{
                "actions":{"maxItems":0},"mobile":{"const":false},
                "location":{"type":"null"},"waitForMs":{"const":0}
            }}
        }]
    })
}

fn dataset_import() -> Value {
    let identifier = json!({"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_.-]+$"});
    let backend =
        json!({"type":"string","enum":["memory","filesystem","postgre_sql","sqlite","maria_db","redis"]});
    json!({
        "type":"object","additionalProperties":false,
        "required":["version","source","policy","dataset","schemaVersion","batch","items"],
        "description":"Strict JSON export, at most 1 MiB total and 64 KiB canonical JSON per item. Source provenance never selects storage authority. Duplicate item keys fail admission.",
        "properties":{
            "version":{"type":"integer","const":1},
            "source":{"type":"object","additionalProperties":false,
                "required":["backend","version","experimental","dedupe"],
                "properties":{"backend":backend,"version":identifier,
                    "experimental":{"type":"boolean"},"dedupe":{"type":"string","enum":["exact","approximate"]}},
                "allOf":[{"if":{"properties":{"backend":{"enum":["sqlite","maria_db","redis"]}}},
                    "then":{"properties":{"experimental":{"const":true}}}}]},
            "policy":{"type":"object","additionalProperties":false,
                "required":["purgeOnStart","sharedFilesystemQueue","authoritativeBackend"],
                "description":"Unsupported policies are reported, never silently applied.",
                "properties":{"purgeOnStart":{"type":"boolean"},"sharedFilesystemQueue":{"type":"boolean"},
                    "authoritativeBackend":backend}},
            "dataset":identifier,
            "schemaVersion":{"type":"string","const":"json_object_v1"},
            "batch":identifier,
            "items":{"type":"array","minItems":1,"maxItems":1000,"items":{
                "type":"object","additionalProperties":false,"required":["key","value"],
                "properties":{"key":identifier,"value":{"type":"object"}}
            }}
        }
    })
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
        "listOperationalReports" | "searchOperationalReport" => {
            super::reports::apply(schemas, operation, id);
        }
        "importDataset" => {
            request_body(operation, dataset_import(),
                "Import bounded safe JSON into a running admitted crawl under an existing live request fence.");
            if let Some(parameters) = operation["parameters"].as_array_mut() {
                for name in ["requestId", "fence"] {
                    parameters.push(json!({"name":name,"in":"query","required":true,
                        "schema":{"type":"integer","minimum":1,"maximum":9223372036854775807i64}}));
                }
                parameters.push(json!({"name":"stateVersion","in":"query","required":true,
                    "schema":{"type":"integer","minimum":1,"maximum":18446744073709551615u64}}));
            }
            operation["responses"]["200"] = json!({
                "description":"Typed artifacts accepted through the existing live request fence; no frontier coverage claim is made.",
                "content":{"application/json":{"schema":{
                    "type":"object","additionalProperties":false,"required":["data"],
                    "properties":{"data":{"type":"object","additionalProperties":false,
                        "required":["requestId","itemCount","completeCoverage","possibleOmissions"],
                        "properties":{"requestId":{"type":"integer","minimum":1},
                            "itemCount":{"type":"integer","minimum":1,"maximum":1000},
                            "completeCoverage":{"type":"boolean","const":false},
                            "possibleOmissions":{"type":"boolean"}}}}
                }}}
            });
            operation["responses"]["422"] = json!({
                "description":"Export policy is incompatible with native authority; no import was committed.",
                "content":{"application/json":{"schema":{
                    "type":"object","additionalProperties":false,"required":["data"],
                    "properties":{"data":{"type":"object","additionalProperties":false,
                        "required":["sourceBackend","sourceVersion","experimental","possibleOmissions","completeCoverage","itemCount","incompatibilities"],
                        "properties":{
                            "sourceBackend":{"type":"string","enum":["memory","filesystem","postgre_sql","sqlite","maria_db","redis"]},
                            "sourceVersion":{"type":"string"},
                            "experimental":{"type":"boolean"},"possibleOmissions":{"type":"boolean"},
                            "completeCoverage":{"type":"boolean","const":false},
                            "itemCount":{"type":"integer","minimum":1,"maximum":1000},
                            "incompatibilities":{"type":"array","minItems":1,"maxItems":3,
                                "items":{"type":"string","enum":["destructive_purge_on_start","shared_filesystem_queue","alternate_authority"]}}
                        }}}
                }}}
            });
        }
        "resetSourceMemo" => {
            operation["responses"]["200"] = json!({
                "description":"Article-seen and category scopes reset for this tenant-owned run. Frontier identities and queued work remain unchanged.",
                "headers":{"Cache-Control":{"schema":{"type":"string","const":"private, no-store"}}},
                "content":{"application/json":{"schema":{
                    "type":"object","additionalProperties":false,"required":["reset","frontierUnchanged"],
                    "properties":{"reset":{"type":"boolean","const":true},
                        "frontierUnchanged":{"type":"boolean","const":true}}
                }}}
            });
        }
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
                        "method":{"type":"string","enum":["GET","HEAD"],"default":"GET"},
                        "route":{"type":"string","maxLength":128,"default":"default"},
                        "metadata":{"type":"object","maxProperties":64},
                        "depth":{"type":"integer","minimum":0,"maximum":65535},
                        "priority":{"type":"integer","minimum":-2147483648,"maximum":2147483647}
                    }
                }})
            } else {
                json!({"type":"object","description":"Pinned declarative source export. checkpoint_export_v1 uses the strict wrapper {version, source, producerEpoch, expectedCursor, endPosition, export}, with a pinned source export nested under export; source-specific fields are strictly validated."})
            };
            let name = if id == "appendRequests" { "requests" } else { "export" };
            let mut properties = Map::new();
            properties.insert(name.to_owned(), input);
            properties.insert("producerEpoch".into(), json!({"type":"integer","minimum":1}));
            properties.insert("expectedCursor".into(), cursor());
            properties.insert("nextCursor".into(), cursor());
            if id == "importRequests" {
                properties.insert("format".into(), json!({
                    "type":"string",
                    "enum":["request_export_v1","checkpoint_export_v1"],
                    "default":"request_export_v1",
                    "description":"Checkpoint exports own their cursor transition; omit outer expectedCursor and nextCursor."
                }));
            }
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
