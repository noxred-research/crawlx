# Object storage

The library backend stores artifacts, archives, exports and audit objects in an S3-compatible
bucket (`crawlx_storage::s3::S3Blobs`). The services that speak the S3 API differ in addressing,
region handling, encryption, object lock and checksum support, so the backend has one
**profile** per family of services. A profile sets the defaults, and the configuration is
checked against what the profile can do **when it is built**: an unsupported option is a
typed error at startup, never a silently dropped header or a failed request later.

`crawlx serve` and `crawlx worker` (and `crawlx crawl --database-url`) use the same settings for
runtime artifacts, on every database engine: when `CRAWLX_S3_BUCKET` is set they write and read
artifacts through the bucket (with the database index, the ephemeral delivery buffer, the upload
spool and encrypted custody, as on the filesystem); without it they use `--artifacts-dir`.
`crawlx config check` validates the profile and settings for both. Serve and worker must point at
the same bucket.

Select the profile with `CRAWLX_S3_PROFILE`. The default is `standard`, which keeps the
behavior from before profiles existed.

## Selecting the backend

Profiles configure an S3 client; they do not change every process's artifact backend.
The current `crawlx serve`, `crawlx worker` and local `crawlx crawl` commands use their
filesystem artifact directory. Setting `CRAWLX_S3_BUCKET` does not redirect those writes.
API and worker processes must therefore share the same filesystem artifact directory.
Library embeddings can supply `S3ArtifactStore` explicitly.

The CLI selects S3 for `admin audit-export --s3-bucket BUCKET`, `inspect trail
--s3-bucket BUCKET`, and the artifact verification/retention commands with
`--s3-bucket BUCKET`. Object delivery destinations also use the configured S3 client.
Configure the same profile, endpoint and bucket when reading or cleaning those objects.


## Profiles

| | `standard` | `compatible` | `edge` | `self-hosted` |
|---|---|---|---|---|
| Service | The original hosted service | Any other S3-compatible service | Edge-hosted service with an account-scoped endpoint | Server you run yourself |
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

Blank values count as unset; any other unrecognized value is an error that names the variable.
Credentials are not part of this configuration: the SDK reads its standard environment
credential variables (access key id, secret access key, optional session token).

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
