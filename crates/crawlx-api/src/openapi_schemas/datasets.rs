//! Native feed declaration bounds and non-executable selection policies.

use serde_json::{json, Value};

pub(super) fn feed_declaration() -> Value {
    let identifier = json!({"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_.-]+$"});
    json!({
        "type":"object","additionalProperties":false,
        "required":["id","source","serializer","serializerVersion","destination","maxBatchItems","maxBatchBytes"],
        "properties":{
            "id":identifier,"source":identifier,"serializer":identifier,"destination":identifier,
            "serializerVersion":{"type":"integer","const":1},
            "maxBatchItems":{"type":"integer","minimum":1,"maximum":1000},
            "maxBatchBytes":{"type":"integer","minimum":1,"maximum":16777216},
            "compression":{"type":"string","enum":["none","gzip","bzip2","xz"],"default":"none"},
            "batching":{"type":"string","enum":["per_request","terminal"],"default":"per_request"},
            "emptyPolicy":{"type":"string","enum":["skip","emit"],"default":"skip"},
            "itemFilter":{"type":"object","additionalProperties":false,
                "description":"At most sixteen predicates over privacy-approved top-level fields. An empty conjunction selects every approved item.",
                "properties":{"all":{"type":"array","maxItems":16,"default":[],"items":{"oneOf":[
                    {"type":"object","additionalProperties":false,"required":["kind","field"],
                        "properties":{"kind":{"const":"present"},"field":identifier}},
                    {"type":"object","additionalProperties":false,"required":["kind","field","value"],
                        "properties":{"kind":{"const":"equals"},"field":identifier,
                            "value":{"type":["null","boolean","number","string"],"maxLength":256}}}
                ]}}}},
            "parameters":{"type":"object","additionalProperties":false,
                "description":"Bounded serializer parameters, never plugin, command, path or destination settings.",
                "properties":{
                    "csvColumns":{"type":"array","maxItems":64,"uniqueItems":true,"default":[],"items":identifier},
                    "jsonIndent":{"type":"integer","minimum":0,"maximum":8,"default":0}
                }}
        },
        "allOf":[
            {"if":{"properties":{"serializer":{"not":{"const":"csv"}}}},
                "then":{"properties":{"parameters":{"properties":{"csvColumns":{"maxItems":0}}}}}},
            {"if":{"properties":{"serializer":{"not":{"const":"json"}}}},
                "then":{"properties":{"parameters":{"properties":{"jsonIndent":{"const":0}}}}}}
        ]
    })
}
