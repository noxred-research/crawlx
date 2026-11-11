//! The JSON column contract: what a repository writes into a JSON column is what it reads
//! back, on every engine (`jsonb` on PostgreSQL, compact text with a validity check on
//! SQLite and MariaDB), including non-ASCII text, `null` members at any depth and values of
//! a mebibyte. MariaDB additionally refuses a statement larger than `max_allowed_packet`:
//! that must surface as a typed error and leave the pool usable.

use crate::rig::Rig;
use crawlx_core::StoreError;
use crawlx_storage::sql::StatementTooLarge;
use crawlx_storage::BackendKind;
use serde_json::{json, Value};

conformance! { databases:
    unicode_and_nested_null_round_trip,
    a_mebibyte_value_round_trips,
    an_oversized_value_is_a_typed_error_and_the_pool_survives,
}

/// JSON text without NUL (PostgreSQL `jsonb` rejects `\u0000`).
fn unicode_samples() -> Vec<Value> {
    vec![
        json!({"plain": "text", "accents": "é è ü ñ", "astral": "𝄞 😀 🧪", "rtl": "שלום مرحبا"}),
        json!({"escapes": "quote \" backslash \\ slash / newline \n tab \t", "separators": "\u{2028}\u{2029}"}),
        json!({"keys é𝄞": {"nested": ["ö", "😀"]}}),
        json!({"numbers": [0, -1, 9_007_199_254_740_991_i64, 0.5, 1.25e3]}),
        json!({"empty": {"object": {}, "array": [], "string": ""}}),
    ]
}

fn nested_null_samples() -> Vec<Value> {
    vec![
        Value::Null,
        json!({"a": null, "b": [null, {"c": null}], "d": {"e": {"f": null}}}),
        json!([null, [null, [null]], {"x": null}]),
        json!({"present": 1, "absent": null}),
    ]
}

async fn unicode_and_nested_null_round_trip(rig: &Rig) {
    rig.migrate().await;
    for value in unicode_samples().into_iter().chain(nested_null_samples()) {
        let back = rig.json_round_trip(&value).await.unwrap();
        assert_eq!(back, value, "round trip changed {value}");
    }
}

async fn a_mebibyte_value_round_trips(rig: &Rig) {
    rig.migrate().await;
    let mebibyte = 1 << 20;
    let single: Value = json!({ "blob": "é".repeat(mebibyte / 2) });
    let wide: Value = Value::Array(
        (0..2048)
            .map(|index| json!({"index": index, "text": format!("{index:04}-{}", "𝄞".repeat(120)), "none": null}))
            .collect(),
    );
    for value in [single, wide] {
        let size = value.to_string().len();
        assert!(size >= mebibyte, "{size}");
        assert_eq!(rig.json_round_trip(&value).await.unwrap(), value);
    }
}

async fn an_oversized_value_is_a_typed_error_and_the_pool_survives(rig: &Rig) {
    rig.migrate().await;
    if rig.kind() != Some(BackendKind::MariaDb) {
        // only MariaDB has a packet ceiling below what the other engines accept
        return;
    }
    let pool = rig.database().mariadb_pool().unwrap();
    let limit: u64 = sqlx::query_scalar("SELECT CAST(@@max_allowed_packet AS UNSIGNED)")
        .fetch_one(pool)
        .await
        .unwrap();
    let size = usize::try_from(limit).unwrap() + (1 << 20);
    let huge = json!({ "blob": "x".repeat(size) });
    let error = rig.json_round_trip(&huge).await.unwrap_err();
    let StoreError::Database { source, retryable } = &error else {
        panic!("an oversized statement must be a typed database error: {error:?}");
    };
    assert!(
        !retryable,
        "an oversized statement must not be retried: {error:?}"
    );
    let too_large = source
        .downcast_ref::<StatementTooLarge>()
        .unwrap_or_else(|| panic!("the refusal must carry StatementTooLarge: {error:?}"));
    assert!(too_large.limit <= limit);
    assert!(too_large.size > limit);
    // the same pool still works afterwards
    let small = json!({"after": ["the", "refusal"]});
    assert_eq!(rig.json_round_trip(&small).await.unwrap(), small);
}
