# CrawlX Kubernetes manifests

Plain manifests mirroring the Helm chart in `deploy/helm/crawlx` for clusters that do not use Helm.
These manifests are PostgreSQL only; MariaDB and SQLite deployments use the Helm chart
(`storage.engine`, docs/ops/storage-backends.md).
Apply in this order:

```sh
kubectl apply -f deploy/k8s/namespace.yaml
kubectl create -n crawlx secret generic crawlx-db --from-file=url=./database-url.txt
kubectl create -n crawlx secret generic crawlx-db-api --from-file=url=./api-database-url.txt
kubectl create -n crawlx secret generic crawlx-webhook --from-file=signing_key=./webhook-key.txt
kubectl create -n crawlx secret generic crawlx-artifact-key --from-file=artifact_key=./artifact-key.hex
kubectl create -n crawlx secret generic crawlx-secret-registry --from-file=url=./secret-registry-url.txt --from-file=users.acl=./secret-registry-users.acl
kubectl create -n crawlx configmap crawlx-chromium-seccomp --from-file=crawlx-chromium.json=docker/seccomp/crawlx-chromium.json
kubectl apply -f deploy/k8s/api-deployment.yaml -f deploy/k8s/worker-deployment.yaml -f deploy/k8s/networkpolicy.yaml
kubectl apply -f deploy/k8s/secret-registry.yaml
```

`crawlx-db-api` must use a separate `LOGIN NOBYPASSRLS NOSUPERUSER NOCREATEROLE`
role with no schema CREATE or owner-role membership. Grant DML only on RLS-protected
application tables, SELECT on the security-invoker views, and usage on their sequences;
revoke UPDATE/DELETE on `audit_events`. `docker/provision-api-role.sql` is the repeatable
grant reference for the default `public` schema. The API rejects an owner or bypass login
at startup. `crawlx-db` retains startup/maintenance authority; workers use lease authority.
Helm uses `secrets.databaseApi` with key `database_url_api` for the same restricted DSN.

The seccomp profile is `type: Localhost`, so it must be present on every worker node under
`/var/lib/kubelet/seccomp/crawlx-chromium.json` (the `ConfigMap` above is for operators that install
it with a node-level DaemonSet; the kubelet does not read ConfigMaps for seccomp). Chromium's sandbox needs
user namespaces: the nodes must run with `user.max_user_namespaces > 0` and, on Debian/Ubuntu kernels,
`kernel.unprivileged_userns_clone = 1`.

`CRAWLX_EGRESS_MODE=netns` selects privileged namespace launch; `netns-rootless`
selects ordinary-user launch with a subordinate browser identity. Both require the
verified helper and explicit browser UID/GID settings in
[`namespace.env.example`](../isolation/namespace.env.example). Browser traffic can
reach only the owned proxy/CDP routes; helper preflight and launch attestation fail
closed. Rootless mode additionally requires host subordinate-id mappings and
unprivileged user namespaces. Kubernetes/CNI enforcement still needs deployment proof.

Emergency stop (RB-11 level 3): `kubectl apply -f deploy/k8s/networkpolicy.yaml` already contains the
`crawlx-worker-deny-all-egress` policy with `enabled: "false"` in its label selector; flip the label on the worker
pods (`kubectl label pods -n crawlx -l app=crawlx-worker crawlx.dev/egress=denied --overwrite`) to cut all target
traffic without touching the software, then `kubectl scale deploy/crawlx-worker --replicas=0`.

## Artifact custody

Every PostgreSQL-backed worker and API pod needs encrypted-artifact custody settings; the manifests
above carry them and the pods do not start usefully without them.

- **Key provider** (API and workers, the same one): exactly one of `CRAWLX_ARTIFACT_KEY_FILE`
  (the manifests mount the `crawlx-artifact-key` Secret key `artifact_key`: exactly 64 hexadecimal
  characters, optional trailing LF; generate it once with `openssl rand -hex 32 > artifact-key.hex`)
  or `CRAWLX_ARTIFACT_KMS_KEY_ID` (a cloud KMS key ID/ARN; replace the key-file env var and volume with it).
  Setting both, or neither on a worker, is a startup error. The API only decrypts for reads: without a
  provider it starts and sealed artifacts fail with a clear error.
- **Secret registry** (workers only): `CRAWLX_SECRET_REDIS_URL` from the `crawlx-secret-registry` Secret key
  `url` (`redis://:<password>@crawlx-secret-registry:6379/`). It must be a dedicated Redis/Valkey with
  RDB/AOF disabled, no replicas, a positive `maxmemory` and `noeviction`, and not the ZDR delivery Redis.
  `secret-registry.yaml` runs such a Valkey; use the same password in `url` and `users.acl`:

```text
user default on ><password> ~crawlx:secrets:* &* -@all +@read +@write +@keyspace +@scripting +@connection +time +info +config|get
```

  The registry is volatile: a restart loses every run's secret authority and durable content writes
  of those runs fail closed until the run ends. An operator-supplied Redis must also allow the worker
  pods through the NetworkPolicy (`networkpolicy.yaml` allows `app: crawlx-secret-registry`).
- `CRAWLX_SECRET_AUTHORITY_TTL_SECS` (optional, default 3600, maximum 86400):
  renewable fenced use window. Renewal rechecks the live producer, authorization
  and retention and never extends Redis secret TTLs.
- `CRAWLX_SECRET_AUTHORITY_HARD_MAX_SECS` (optional, default 259200): original
  absolute ceiling, narrowed by explicit retention and authorization expiry.
  Missing either permission caps the ceiling at 86400 seconds.

Keep decrypt access to every KMS key (or the exact key file) while sealed artifacts exist; see the
operations runbook for rotation limits. Helm enables the managed registry with
`artifactCustody.secretRedis.managed.enabled=true`; set the URL hostname to `<release>-secret-registry`.

## Shared volatile ZDR delivery

Standard deployments leave ZDR disabled unless a shared delivery backend is configured. The API
rejects new ZDR requests when no backend is enabled; it never substitutes persistent artifacts or
per-process memory for production delivery.

For multi-node workers, create the `crawlx-zdr` Secret from two local files:

- `url`: the authenticated Redis URL, for example `redis://zdr:<password>@crawlx-zdr:6379/`.
- `users.acl`: disable the default user and grant the dedicated `zdr` user only the delivery key
  namespace and commands. A suitable ACL is:

```text
user default off
user zdr on ><password> ~crawlx:zdr:{delivery}:* +@read +@write +@scripting +config|get +info +ping +auth +time -save -bgsave -bgrewriteaof -replicaof -slaveof -sync -psync -replconf
```

Use the same strong password in both files. Do not commit them or print the authenticated URL.
Then deploy the optional transport and restart the application pods so they load the secret:

```sh
kubectl create -n crawlx secret generic crawlx-zdr --from-file=url=./zdr-url.txt --from-file=users.acl=./zdr-users.acl
kubectl apply -f deploy/k8s/zdr-delivery.yaml -f deploy/k8s/networkpolicy.yaml
kubectl rollout restart -n crawlx deployment/crawlx-api deployment/crawlx-worker
```

The profile uses Valkey without RDB/AOF, replicas, persistent volumes, or backups. Its writable
directory is memory-backed; configure nodes without swap. Native Redis key TTL remains active when
every API/worker process stops, and a transport restart intentionally discards undelivered content.
The adapter rechecks persistence/replication settings and refuses an unsafe server. Do not replace
this instance with a durable application cache. For external transport, use `rediss://` with a valid
trusted certificate; the in-cluster profile relies on authenticated clients and the supplied
NetworkPolicy, not public exposure. Helm enables the equivalent profile with `zdr.enabled=true`;
set the secret URL hostname to `<release>-zdr`.

For colocated processes only, explicitly set `CRAWLX_ZDR_DIR` to the same tmpfs base directory in
both processes. The store uses its `zdr/` child namespace. Both processes must share the mount and
service UID. Separate pod `emptyDir` mounts do not share content, and a persistent artifact PVC is
never a valid substitute. Filesystem mode does not claim multi-node support.

Install `deploy/systemd/crawlx-zdr-clean.service` and `.timer` on a colocated host, with the same
`CRAWLX_ZDR_DIR` in `/etc/crawlx/zdr.env`. The timer runs `crawlx admin sweep-delivery` every minute,
independently of the API and workers, and takes the same crash-released lock before deleting
expired pages or abandoned temporary writes. Never clean or replace `zdr/.lock` outside that
locked cleanup. Memory filesystems can swap on some hosts; disable swap, hibernation, core dumps,
and content snapshots, and exclude the namespace from backups.


## Independent safety auditor

After applying migration 0022 with the DDL credential, provision the independent LOGIN roles
and secrets described in [the safety-auditor runbook](../../docs/ops/runbooks.md#independent-safety-auditor).
Do not use the API, worker, migration, or ordinary admin database credential for either connection.

```sh
kubectl create -n crawlx secret generic crawlx-safety-reader \
  --from-file=database_url=./safety-reader-database-url.txt
kubectl create -n crawlx secret generic crawlx-safety-pauser \
  --from-file=database_url=./safety-pause-database-url.txt
kubectl apply -f deploy/k8s/safety-auditor.yaml
```

Supply the DSN files from your secret manager; restrict local file permissions and remove local copies
after provisioning. Never commit credentials. Set both DSNs to the same PostgreSQL database, using
different limited LOGIN roles and TLS (`sslmode=verify-full` with your trusted server certificate).
Update the image tag to the release containing the command before applying the manifest.

The `crawlx-safety-audit` CronJob runs `crawlx admin safety-audit --json` every minute with
`concurrencyPolicy: Forbid` and no retry. It uses the existing API image,
which includes the CLI but no Chromium. Its pod has no worker configuration, artifact volume, service
account token, or privileged database credential. The companion NetworkPolicy denies all ingress and
permits only same-namespace PostgreSQL pods (`app: crawlx-postgres`, TCP 5432), plus cluster DNS.
Use a NetworkPolicy-capable CNI. NetworkPolicies are additive: do not apply broader policies that also
select these pods. Adapt the PostgreSQL selector when your database placement differs.

Helm installs the same schedule and isolation policy by default. Configure
`safetyAuditor.readerSecret` and `safetyAuditor.pauseSecret` for externally created secrets, each with
key `database_url`; configure `networkPolicy.databaseSelector` for the PostgreSQL pods. Auditor isolation
remains enabled when general chart network policies are disabled. `safetyAuditor.enabled=false`
disables the scheduled auditor and its policy; do not disable it in production without replacement.

Route failed Jobs and audit JSON logs to the paging system. Exit 1 with nonempty `violations` means
SEV-1; other command errors, stuck audits, or missing scheduled Jobs mean the independent control did not
complete and need operator attention. `SAFETY_INVARIANT_VIOLATIONS` increments inside the short-lived
process; the supplied schedule does not export that counter to Prometheus. Do not assume the existing
Prometheus alert sees it. Use the Job result and preserved JSON report for reliable scheduled paging.
