# Object storage

The library backend stores artifacts, archives, exports and audit objects in an S3-compatible
bucket (`crawlx_storage::s3::S3Blobs`). The services that speak the S3 API differ in addressing,
region handling, encryption, object lock and checksum support, so the backend has one
**profile** per family of services. A profile sets the defaults, and the configuration is
checked against what the profile can do **when it is built**: an unsupported option is a
typed error at startup, never a silently dropped header or a failed request later.

Every command that opens a database uses the same settings for runtime artifacts, on every
database engine: `crawlx serve`, `crawlx worker`, `crawlx crawl --database-url`, and the
read-and-replay commands `crawlx export RUN_ID` and `crawlx replay`. When `CRAWLX_S3_BUCKET` is
set they write and read artifacts through the bucket (with the database index, the ephemeral
delivery buffer, the upload spool and encrypted custody, as on the filesystem) and write nothing
under `--artifacts-dir`; without it they use `--artifacts-dir`. The two modes without a database
always use the filesystem: `crawlx serve` without a database (in-memory API) and `crawlx crawl`
without `--database-url` ignore `CRAWLX_S3_BUCKET`. `crawlx config check` validates the profile
and settings and prints the effective bucket and prefix. Serve and worker must point at the same
bucket.

Select the profile with `CRAWLX_S3_PROFILE`. The default is `standard`, which keeps the
behavior from before profiles existed.

## Selecting the backend

Profiles configure an S3 client. The artifact backend of a process is chosen at startup:

| Command | `CRAWLX_S3_BUCKET` set | Not set |
|---|---|---|
| `serve --database-url ...` | bucket | `--artifacts-dir` |
| `worker` | bucket | `--artifacts-dir` |
| `crawl --database-url ...`, `export RUN_ID`, `replay` | bucket | `--artifacts-dir` |
| `serve` and `crawl` without a database | `--artifacts-dir` (the variable is ignored) | `--artifacts-dir` |

A blank value counts as not set. A bucket with invalid S3 settings is a startup error, never a
fallback to the filesystem. Without `CRAWLX_S3_BUCKET`, API and worker processes must share the
same filesystem artifact directory. Library embeddings can also supply `S3ArtifactStore`
explicitly.

The CLI selects S3 for `admin audit-export --s3-bucket BUCKET`, `inspect trail
--s3-bucket BUCKET`, and the artifact verification/retention commands with
`--s3-bucket BUCKET`. Object delivery destinations also use the configured S3 client.
Configure the same profile, endpoint and bucket when reading or cleaning those objects.


## Profiles

| | `standard` | `compatible` | `edge` | `self-hosted` |
|---|---|---|---|---|
| Service | The original hosted service | Any other S3-compatible service | Edge-hosted service with an account-scoped endpoint | Server you run yourself; verified against RustFS and MinIO |
| `CRAWLX_S3_ENDPOINT` | Optional (regional endpoint when unset) | **Required** | **Required**, https | **Required** |
| Default region | `us-east-1` | `us-east-1` | `auto` | `us-east-1` |
| Default addressing | Virtual-hosted (`bucket.host/key`) | Path-style (`host/bucket/key`) | Path-style | Path-style |
| Plain `http` endpoint | Any (unchanged) | Loopback, private and local-network hosts; other hosts need `CRAWLX_S3_ALLOW_HTTP=1` | Refused unless `CRAWLX_S3_ALLOW_HTTP=1` | Same as `compatible` |
| SSE `aes256` | Yes | Yes | Refused | Yes |
| SSE `kms` | Yes | Refused unless `CRAWLX_S3_ALLOW_KMS=1` | Refused | Yes |
| Object lock (`CRAWLX_S3_OBJECT_LOCK=1`, WORM audit bucket) | Yes | Yes | **Refused** | Yes |
| `CRAWLX_S3_CHECKSUM` | `when_required` (default) or `when_supported` | `when_required` only | `when_required` only | `when_required` only |
| Presigned `GET` | Yes | Yes | Yes | Yes |
| Largest object | 5 GiB (single `PutObject`) | 5 GiB | 5 GiB | 5 GiB |

An explicit variable overrides a profile default wherever the table does not refuse it. For
example `CRAWLX_S3_PATH_STYLE=0` switches `compatible` to virtual-hosted addressing (the
service needs wildcard DNS for the bucket name), and `CRAWLX_S3_REGION` replaces the default
region of any profile.

Notes on the rows:

* **Plain `http`.** "Private" means loopback addresses, RFC 1918 ranges, link-local and
  unique-local IPv6 addresses, `localhost`, single-label names and the suffixes `.localhost`,
  `.local`, `.lan`, `.internal` and `.home.arpa`. A presigned URL is a bearer credential for its
  lifetime; on a plain-`http` endpoint it travels unencrypted.
* **Checksums.** `when_required` sends no CRC trailer on uploads and validates none on
  downloads, which every implementation accepts. Artifact integrity does not depend on it: the
  blake3 digest in the artifact row is verified on read. `when_supported` adds a CRC32 trailer to
  every upload and is accepted only where the service is known to handle it.
* **Object lock.** `CRAWLX_S3_OBJECT_LOCK=1` declares that the bucket is under object lock
  (point the audit export at such a bucket: the first write of a key wins and a replacement is
  refused by the bucket). Every upload then carries a CRC32 checksum, which a locked bucket
  requires. CrawlX never sets retention itself; the retention rules belong to the bucket.
  The `edge` profile refuses the flag: keep audit exports on a bucket of another profile.
* **Uploads.** Every object is one `PutObject`. Multipart upload is not implemented, so an object
  above 5 GiB is refused with a typed error before any request is sent (archives are capped at
  1 GiB by policy). No conditional write (`If-None-Match`) and no ACL is ever sent.
* **Presigned URLs.** SigV4 query-string `GET`, at most 7 days (the signature limit; a longer
  request is a typed error, not a clamp). The artifact store itself hands out content URLs for at
  most 60 seconds.

## Environment

| Variable | Meaning |
|---|---|
| `CRAWLX_S3_BUCKET` | Bucket name. Required |
| `CRAWLX_S3_PROFILE` | `standard` (default), `compatible`, `edge` or `self-hosted` |
| `CRAWLX_S3_ENDPOINT` | Endpoint url, `http(s)://host[:port][/prefix]` without credentials, query or fragment |
| `CRAWLX_S3_REGION` | Signing region; the profile default when unset |
| `CRAWLX_S3_PATH_STYLE` | `1`/`true`/`yes`/`on` or `0`/`false`/`no`/`off`; the profile default when unset |
| `CRAWLX_S3_SSE` | `aes256` or `kms`; unset leaves the bucket default in force |
| `CRAWLX_S3_KMS_KEY_ID` | Key id for `kms`; setting it without `CRAWLX_S3_SSE=kms` is an error |
| `CRAWLX_S3_ALLOW_KMS` | Opt in to `kms` on `compatible` |
| `CRAWLX_S3_ALLOW_HTTP` | Opt in to plain `http` to any host |
| `CRAWLX_S3_CHECKSUM` | `when_required` (default) or `when_supported` |
| `CRAWLX_S3_OBJECT_LOCK` | The bucket is under object lock (WORM) |
| `CRAWLX_S3_PREFIX` | Key prefix that confines this deployment inside a shared bucket (`crawlx/` or `a/b`); empty (the default) keeps the legacy layout. See [backends.md](backends.md) and [Sharing a bucket](#sharing-a-bucket) |
| `CRAWLX_S3_ALLOW_SHARED_PREFIX` | Unsafe override: skip the deployment marker guard and let several deployments write one prefix |

Blank values count as unset; any other unrecognized value is an error that names the variable.
Credentials are not part of this configuration: the SDK reads its standard environment
credential variables (access key id, secret access key, optional session token).

## Sharing a bucket

One bucket can serve several deployments, one prefix each (`CRAWLX_S3_PREFIX`). A deployment is
one relational database: every worker, API and CLI process that uses the database belongs to it.
Two deployments writing the same prefix are not isolated from each other: the orphan sweep of
each sees the other's objects as unreferenced and deletes them, after which the other
deployment's `verify-artifacts` reports every artifact missing. A guard makes that impossible by
accident:

* The first write under a prefix creates the marker object `<prefix>.crawlx-deployment`
  (`.crawlx-deployment` at the bucket root for the legacy empty prefix). It is a small JSON
  document with a format version, the id of the deployment and who wrote it. The id is a random
  UUID kept under `deployment.id` in the database's `cluster_settings` table and created on first
  use, so all processes of one deployment, and every restart, hold the same id.
* The marker is written with `If-None-Match: *`, so when several deployments start at once exactly
  one claims the prefix. A server that answers `501` to a conditional write gets a plain write
  followed by a read back of the marker; a claimer that reads another id refuses.
* Objects that are already under the prefix when no marker exists are adopted by the first
  deployment that writes.
* Any write, delete or orphan sweep (the whole-prefix listing) by a deployment that finds another
  deployment's marker is refused with `s3 prefix "<prefix>" in bucket "<bucket>" is claimed by
  another crawlx deployment`. The message names the prefix, never the other deployment's id.
  Reads, existence checks, partial listings, presigned URLs and `verify-artifacts` are never
  refused, and a read-only command does not create the marker.
* The marker is never listed, so a sweep cannot collect it, and no write or delete may name it.
* A process that has no database (an in-memory crawl with a bucket) cannot know the deployment
  id. It writes a marker that any such process shares, so a restart can still delete what it
  wrote; it may write under a deployment's marker but its deletes and sweeps are refused. A
  deployment replaces a marker of that kind when it first writes.

To give a prefix to another deployment (a database rebuilt from scratch has a new id), make sure
nothing else writes it, then delete the marker object with the store's own tooling; the next
writer claims the prefix. To run the guard off, set `CRAWLX_S3_ALLOW_SHARED_PREFIX=1`. That is
unsafe: it removes the protection above, writes no marker, and every deployment sharing the
prefix then deletes the others' live objects when it sweeps orphans. Use it only for a bucket
whose prefix is shared by design and never swept (`sweep-retention` without an orphan grace).

## Refusals

Every refusal is raised when the configuration is built from the environment and again when the
backend is created from a hand-built configuration. The message names the profile and the option.

| Refusal | Cause | Fix |
|---|---|---|
| `CRAWLX_S3_BUCKET is not set` | No bucket | Set `CRAWLX_S3_BUCKET` |
| `unknown s3 profile` | Label is not one of the four | Use a label from the table |
| `... requires CRAWLX_S3_ENDPOINT` | `compatible`, `edge` or `self-hosted` without an endpoint | Set the endpoint |
| `s3 endpoint is invalid` | Not an `http(s)` url with a host, or it carries credentials, a query or a fragment | Pass a bare endpoint url |
| `... refuses plain http to <host>` | `http` endpoint the profile does not trust | Use `https`, or set `CRAWLX_S3_ALLOW_HTTP=1` for a network you control |
| `... does not support server-side encryption <aes256\|kms>` | `edge` with `CRAWLX_S3_SSE` | Unset `CRAWLX_S3_SSE`; encryption at rest is then the service's own setting |
| `... accepts kms encryption only with CRAWLX_S3_ALLOW_KMS=1` | `compatible` with `CRAWLX_S3_SSE=kms` | Confirm the service supports it, then set the opt-in |
| `CRAWLX_S3_KMS_KEY_ID is set but CRAWLX_S3_SSE is not kms` | Key id with no kms encryption | Set `CRAWLX_S3_SSE=kms` or drop the key id |
| `... does not support object lock` | `edge` with `CRAWLX_S3_OBJECT_LOCK=1` | Use a bucket of another profile for the audit export |
| `... supports only the when_required checksum mode` | `compatible`, `edge` or `self-hosted` with `when_supported` | Use `when_required` |
| `s3 prefix "<prefix>" in bucket "<bucket>" is claimed by another crawlx deployment` | A write, delete or orphan sweep under a prefix whose marker names another deployment | Give this deployment its own `CRAWLX_S3_PREFIX`; see [Sharing a bucket](#sharing-a-bucket) |
| `<variable> has an invalid value` | Unrecognized boolean, checksum mode or encryption label | Use a documented spelling |

## Example environments

Credentials come from the SDK's standard environment variables in every example.

`standard` (the default; every variable except the bucket is optional):

```sh
CRAWLX_S3_BUCKET=crawlx-artifacts
CRAWLX_S3_REGION=eu-central-1
CRAWLX_S3_SSE=kms
CRAWLX_S3_KMS_KEY_ID=0000aaaa-00aa-00aa-00aa-000000aaaaaa
```

`compatible`:

```sh
CRAWLX_S3_PROFILE=compatible
CRAWLX_S3_BUCKET=crawlx-artifacts
CRAWLX_S3_ENDPOINT=https://objects.example.net
# path-style addressing and checksum mode when_required are the defaults
```

`edge`:

```sh
CRAWLX_S3_PROFILE=edge
CRAWLX_S3_BUCKET=crawlx-artifacts
CRAWLX_S3_ENDPOINT=https://0123456789abcdef.edge.example.net
# region defaults to auto; encryption and object lock are refused on this profile
```

`self-hosted`:

```sh
CRAWLX_S3_PROFILE=self-hosted
CRAWLX_S3_BUCKET=crawlx-artifacts
CRAWLX_S3_ENDPOINT=http://objects.lan:9000
# plain http is accepted because the host is on a local network; use
# CRAWLX_S3_ALLOW_HTTP=1 for any other host you reach over http
```

Audit export on an object-lock bucket (any profile except `edge`):

```sh
CRAWLX_S3_OBJECT_LOCK=1
```

## Lifecycle rules

The sweeper (`crawlx admin sweep-retention`) is the authority on retention: it deletes an artifact
when its run's retention ends and the database says so. The bucket's own expiry rules are a
**backstop** for objects the sweeper could not reach (a long outage, a lost database row), so each
rule expires later than the longest retention its prefix can legally carry. The repository ships a
rule template, [`deploy/object-store/lifecycle.json`](../../deploy/object-store/lifecycle.json), in
the standard S3 lifecycle-configuration shape:

| Prefix | Backstop expiry | Why |
|---|---|---|
| `credential_bearing/` | 2 days | stored for at most one day |
| `zdr/` | 2 days | zero-retention delivery files live one hour |
| `content/` | 400 days | `extended` retention is at most 365 days |
| `sensitive/` | 400 days | same bound |
| `_index/` | 400 days | index records follow their artifact |

Two prefixes have **no rule on purpose**. `metadata/` lives until the run is purged, so only the
database knows when it may go. `audit/` holds the daily Merkle exports of the audit chain: the
bucket under object lock owns their retention, the artifact orphan collector never touches the
prefix, and an expiry rule there would delete the evidence the export exists to preserve. Never
add a rule whose filter is empty (whole bucket) or that covers `audit/`.

Apply the template to the artifact bucket with your service's lifecycle command (it is the
rule document, not a deployment step CrawlX performs). The audit bucket is a separate,
object-lock bucket and takes no lifecycle template; if you must share one bucket, apply the
template there too, and the `audit/` prefix stays exempt. Applying the rules to a real bucket is
an operator action and is not verified by CrawlX's tests; the repository test checks the template.

The daily audit export itself is a scheduled job: the Helm chart renders it from the
`auditExport` values and `deploy/k8s/audit-export-cronjob.yaml` is the plain manifest
([audit export](runbooks.md#audit-export)).

## Verification

`cargo test -p crawlx-storage --test s3 --test s3_profiles` runs the profile parsing,
defaults, overrides, every refusal, the checksum and addressing behavior against an in-process
S3 server that records each request's path and headers, and presigned URL shapes. It needs no
network.

The same file contains one conformance test per profile (put, get, head, list, delete, presign)
that runs against a real endpoint when `CRAWLX_TEST_S3_ENDPOINT` is set:

| Variable | Meaning |
|---|---|
| `CRAWLX_TEST_S3_ENDPOINT` | Endpoint of the service under test; the tests skip when unset |
| `CRAWLX_TEST_S3_PROFILE` | Profile to run (`self-hosted` when unset); the other profiles' tests skip |
| `CRAWLX_TEST_S3_BUCKET` | Bucket (`crawlx-artifacts` when unset); created if missing |
| `CRAWLX_TEST_S3_ACCESS_KEY`, `CRAWLX_TEST_S3_SECRET_KEY` | Credentials (`crawlx` / `crawlx-secret` when unset) |
| `CRAWLX_TEST_S3_REGION`, `CRAWLX_TEST_S3_PATH_STYLE`, `CRAWLX_TEST_S3_ALLOW_HTTP`, ... | Any other `CRAWLX_S3_*` option under the `CRAWLX_TEST_S3_` prefix |
