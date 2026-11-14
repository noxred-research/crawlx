# Backends

CrawlX keeps different kinds of data in different kinds of stores. This page lists what each
family is used for, which engines are supported, how a deployment stays in its own namespace so
several deployments (or CrawlX next to other services) can share one set of instances, and what
was left out and why.

A family is supported only where CrawlX has data of that kind. There are no pass-through stubs
and no configuration keys that are parsed and ignored: a registry entry or setting an engine
cannot honor is refused when it is loaded.

## Support matrix

| Family | Engines | What CrawlX stores there | Namespace | Setting |
|---|---|---|---|---|
| Relational (system of record) | SQLite, PostgreSQL, MariaDB | runs, frontier, pages, journal, datasets, audit chain, catalogs | PostgreSQL schema; MariaDB database; SQLite file | `database.url_file`, `database.schema` ([storage backends](storage-backends.md)) |
| Object store | S3 API: profile `standard` (the original S3 service), `edge` (an edge object store with an S3 API), `self-hosted` (RustFS and MinIO, both verified; similar servers), `compatible` (any other S3 API) | artifacts, archives, exports, audit objects | bucket plus key prefix | `CRAWLX_S3_*` ([object storage](object-storage.md)), `CRAWLX_S3_PREFIX` |
| Cache and coordination | Valkey, Redis | secret registry (volatile run secrets), zero-data-retention delivery buffer | key prefix, database index in the URL | `CRAWLX_SECRET_REDIS_URL`, `CRAWLX_ZDR_REDIS_URL`, `CRAWLX_REDIS_KEY_PREFIX` |
| Search | OpenSearch, Elasticsearch | one document per delivered feed batch (search projections of crawled content) | index prefix | delivery registry kinds `opensearch`, `elasticsearch` |
| Analytics | ClickHouse | one row per delivered feed batch (the serialized feed content) | database | delivery registry kind `clickhouse` |
| Event stream | Kafka, RabbitMQ (AMQP 0-9-1) | one record or message per delivered feed batch | topic prefix; vhost plus exchange and queue prefix | delivery registry kinds `kafka`, `amqp` |

Search, analytics and event-stream stores are **delivery destinations**: they receive the data of
dataset feeds (`datasets.feeds[].destination`) from the existing durable outbox, so delivery keeps
its claim, retry, deadline, cancellation and zero-data-retention rules. They are chosen by id in
the operator registry file (`CRAWLX_DELIVERY_REGISTRY`); a crawl names only the id, and nothing a
page contains can pick an endpoint or a credential.

### Why each family is, or is not, here

* **Relational, object store, Valkey/Redis:** already the core of CrawlX; this page documents
  their namespacing.
* **Search:** crawled content is the product, and a search index is the natural place to query it.
  The existing generic search-index destination speaks the bulk API to any endpoint; the native
  sinks add engine detection, a versioned index template and an index prefix.
* **ClickHouse:** feed batches are append-only and high volume; ClickHouse is where they are
  queried in bulk. Per-request traffic and crawl events are **not** streamed there: they stay in
  the relational store, which is their system of record. A continuous event exporter would be a
  separate feature.
* **Kafka and RabbitMQ:** outbound export to other systems, with broker-level acknowledgement.
  Work distribution between CrawlX nodes is **not** moved to a broker: leases, fencing and
  scheduling already live in the relational store and must stay transactional with it.

## Namespacing on shared instances

Every deployment picks its own names; none of them touches anything outside its names.

| Family | Namespace key | Default | Notes |
|---|---|---|---|
| PostgreSQL | `database.schema` | the role's search path | The schema is created by `crawlx migrate`; each schema has its own tables **and** migration table. Refused for MariaDB and SQLite. The request-login role needs `USAGE` on the schema. |
| MariaDB | the database in the URL path | as given | one database per deployment |
| SQLite | the file path | as given | one file per deployment |
| Object store | `CRAWLX_S3_PREFIX` | empty (legacy layout) | `a/b` or `a/b/`; letters, digits and `. _ -`, no empty or dot segments. Reads, lists and deletes stay inside the prefix; listings return keys without it. One bucket can hold several deployments. |
| Valkey/Redis | `CRAWLX_REDIS_KEY_PREFIX` | `crawlx:` | Keys are `<prefix>secrets:{tenant:run}` and `<prefix>zdr:{delivery}:...`. CrawlX deletes only keys it names, never uses `KEYS`, and never flushes a database. The logical database index, ACL user and password, and TLS (`rediss://`) come from the URL. |
| Search | `indexPrefix` | `crawlx-` | Indices are `<indexPrefix><index>`; the template covers exactly `<indexPrefix>*`. CrawlX never deletes an index. |
| ClickHouse | `database` | `crawlx` | tables are created by versioned migrations recorded in `<database>.crawlx_migrations` |
| Kafka | `namePrefix` | `crawlx.` | topics are `<namePrefix><topic>`; the sink is a producer, so there is no consumer group |
| RabbitMQ | the vhost in the endpoint path, `namePrefix` | `crawlx.` | exchange and queue are `<namePrefix><queue>` |

The object-store prefix defaults to empty so existing deployments keep reading the objects they
wrote. Set `CRAWLX_S3_PREFIX=crawlx/` (and move existing objects) before sharing a bucket.

Secrets (database URLs, S3 credentials, registry credentials) come from files, environment
variables or credential references, never from the registry file itself.

## Delivery registry entries

The registry file is the strict JSON document described in the [operations
guide](README.md). New `kind` values (all fields are camelCase; a field a kind does not use is
refused):

```json
{
  "version": 1,
  "destinations": [
    { "id": "pages-search", "kind": "opensearch", "endpoint": "https://search.internal:9200",
      "headers": { "authorization": "env://SEARCH_AUTHORIZATION" },
      "indexPrefix": "crawlx-", "index": "pages" },
    { "id": "pages-warehouse", "kind": "clickhouse", "endpoint": "http://clickhouse.internal:8123",
      "headers": { "x-clickhouse-user": "env://CH_USER", "x-clickhouse-key": "env://CH_PASSWORD" },
      "database": "crawlx", "table": "pages" },
    { "id": "pages-stream", "kind": "kafka", "brokers": ["kafka-1.internal:9092"],
      "namePrefix": "crawlx.", "topic": "pages", "partitions": 3, "replicationFactor": 3, "tls": true,
      "credentials": { "username": "env://KAFKA_USER", "password": "env://KAFKA_PASSWORD" } },
    { "id": "pages-queue", "kind": "amqp", "endpoint": "amqps://mq.internal:5671/%2f",
      "namePrefix": "crawlx.", "topic": "pages",
      "credentials": { "username": "env://AMQP_USER", "password": "env://AMQP_PASSWORD" } }
  ]
}
```

| Kind | Required | Optional | Behavior |
|---|---|---|---|
| `opensearch`, `elasticsearch` | `endpoint`, `index` | `indexPrefix`, `headers` | Detects the engine and version with `GET /` and refuses a mismatch with the configured kind; supports Elasticsearch 7.8 or newer and OpenSearch 1.0 or newer (composable templates); installs the template `<indexPrefix>crawlx` (version 1) once; indexes with `_bulk` under a stable document id, so a retry overwrites; a tombstone projection deletes one document. Only the API subset both engines share is used. |
| `clickhouse` | `endpoint`, `table` | `database`, `headers` | Creates the database, `crawlx_migrations` and the feed table (`MergeTree`, monthly partitions, deduplication window of 10,000 blocks) on first use; inserts one `JSONEachRow` row per batch with the batch key as `insert_deduplication_token`, so a retry inside the window stores once. Payloads must be UTF-8. |
| `kafka` | `brokers`, `topic` | `namePrefix`, `partitions`, `replicationFactor`, `tls`, `credentials` | Creates the topic when missing; produces one record keyed by the batch key to the partition the key hashes to and returns after the broker acknowledged it (`acks=all`). SASL/PLAIN with `credentials`. The client has no idempotent-producer mode: a retry after an unacknowledged send can store the batch twice, the sink reports `duplicate_possible`, and consumers deduplicate on the record key. |
| `amqp` | `endpoint` (with an explicit vhost), `topic` | `namePrefix`, `credentials` | Declares a durable direct exchange and queue and binds them; publishes one persistent message per batch with `message_id` set to the batch key, `mandatory`, and publisher confirms; unroutable or negatively acknowledged messages are rejected. Reconnects after a failure. At-least-once: deduplicate on `message_id`. |

Common rules: none of these destinations accepts zero-data-retention content; a connection or
broker failure is retried later by the delivery outbox; a rejected batch is not. Endpoints are
trusted infrastructure (like the database and the object store), so the crawl egress policy does
not apply to them and `addresses` is refused; use the network policy of the deployment to limit
where the workers can connect. Responses are read up to 4 MiB with a 30 second deadline, and
redirects and ambient proxies are off.

## Shared-instance setup

One PostgreSQL server, one bucket, one Valkey, one search cluster, one ClickHouse and one broker
can serve all deployments:

1. Give each deployment its own names: `database.schema = "crawlx"` (PostgreSQL),
   `CRAWLX_S3_PREFIX=crawlx/`, `CRAWLX_REDIS_KEY_PREFIX=crawlx:`, and `indexPrefix`, `database`
   and `namePrefix` in the registry. Other products on the same instances use their own values.
2. Grant each deployment's database role access to its schema only. On PostgreSQL the migration
   role needs `CREATE` on the database for `crawlx migrate` to create the schema.
3. Use per-deployment credentials for the object store and the Redis ACL, limited to the prefix.
   CrawlX's own isolation is by name, not by permission.
4. The volatile Redis instance must keep persistence off and `maxmemory-policy noeviction`
   (rechecked before every operation); share it only with services that accept those settings.

## Tests

The relational, object-store (against an in-process S3 and any S3 server named by
`CRAWLX_TEST_S3_ENDPOINT`) and Valkey tests are described in [storage
backends](storage-backends.md); the namespace tests there run two prefixes or schemas on one
instance and assert they do not see each other. The search, ClickHouse, Kafka and RabbitMQ sinks
run against real services in throwaway containers:

```sh
eval "$(ci/backend-services.sh up opensearch elasticsearch clickhouse kafka rabbitmq rustfs minio)"
cargo test -p crawlx-worker --lib delivery::backends
CRAWLX_TEST_S3_ENDPOINT="$CRAWLX_TEST_RUSTFS_ENDPOINT" cargo test -p crawlx-storage --test s3
CRAWLX_TEST_S3_ENDPOINT="$CRAWLX_TEST_MINIO_ENDPOINT" cargo test -p crawlx-storage --test s3
ci/backend-services.sh down
```

The object-store contract (path-style addressing, put, get, ranged read, list pagination, delete,
presigned reads, and prefix isolation between two deployments in one bucket) runs against the
`self-hosted` profile on **RustFS** (image pinned by digest in `ci/backend-services.sh`) and on a
**MinIO**-compatible server (the upstream MinIO images are no longer published, so the legacy
repackaged image is used).

`ci/backend-services.sh` starts each service with a unique container name, a loopback-only port
and its data in tmpfs, and removes it on `down`. Without the `CRAWLX_TEST_*` variables the service
tests skip.
