{{/* Storage engine settings the chart can check at render time. Included once from configmap.yaml. */}}
{{- define "crawlx.storageValidate" -}}
{{- $engine := .Values.storage.engine -}}
{{- if not (has $engine (list "postgres" "mariadb" "sqlite")) -}}
{{- fail (printf "storage.engine must be postgres, mariadb or sqlite, got %q" $engine) -}}
{{- end -}}
{{- if and (eq $engine "sqlite") .Values.safetyAuditor.enabled -}}
{{- fail "refused: sqlite_safety_auditor: the independent safety auditor needs two distinct database identities (reader and pauser); sqlite has none; set safetyAuditor.enabled=false" -}}
{{- end -}}
{{- if and (eq $engine "mariadb") .Values.safetyAuditor.enabled -}}
{{- fail "refused: backend_unimplemented: the independent safety auditor is not available on mariadb yet; use postgres, or set safetyAuditor.enabled=false" -}}
{{- end -}}
{{- if eq $engine "sqlite" -}}
{{- if or (gt (int .Values.api.replicas) 1) (gt (int .Values.worker.replicas) 1) .Values.worker.canary.enabled -}}
{{- fail "refused: sqlite_second_worker: sqlite supports exactly one worker process per database file and one API replica on the same host; set api.replicas=1, worker.replicas=1 and worker.canary.enabled=false, or use mariadb or postgres" -}}
{{- end -}}
{{- if not .Values.storage.sqlite.existingClaim -}}
{{- fail "storage.sqlite.existingClaim is required for storage.engine=sqlite" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Port of the database server for network policies. */}}
{{- define "crawlx.databasePort" -}}
{{- if gt (int .Values.storage.port) 0 -}}{{ int .Values.storage.port }}{{- else if eq .Values.storage.engine "mariadb" -}}3306{{- else -}}5432{{- end -}}
{{- end -}}

{{/* The restricted request login exists on PostgreSQL only. */}}
{{- define "crawlx.requestLoginEnv" -}}
{{- if eq .Values.storage.engine "postgres" }}
- name: CRAWLX_API_DATABASE_URL_FILE
  value: /run/secrets/crawlx/database_url_api
{{- end }}
{{- end -}}

{{- define "crawlx.requestLoginSource" -}}
{{- if eq .Values.storage.engine "postgres" }}
- secret:
    name: {{ .Values.secrets.databaseApi }}
    items: [{ key: database_url_api, path: database_url_api }]
{{- end }}
{{- end -}}

{{/* The SQLite file's volume, mounted by every pod that opens the database. */}}
{{- define "crawlx.sqliteMount" -}}
{{- if eq .Values.storage.engine "sqlite" }}
- { name: database, mountPath: /var/lib/crawlx/db }
{{- end }}
{{- end -}}

{{- define "crawlx.sqliteVolume" -}}
{{- if eq .Values.storage.engine "sqlite" }}
- name: database
  persistentVolumeClaim: { claimName: {{ .Values.storage.sqlite.existingClaim | quote }} }
{{- end }}
{{- end -}}

{{- define "crawlx.apiImage" -}}
{{ .Values.image.registry }}/crawlx-api:{{ .Values.image.tag }}
{{- end -}}

{{- define "crawlx.workerImage" -}}
{{ .Values.image.registry }}/crawlx-worker:{{ .Values.image.tag }}-chromium{{ .Values.image.chromiumVersion }}
{{- end -}}

{{- define "crawlx.gymImage" -}}
{{ .Values.image.registry }}/crawlx-gym:{{ .Values.image.tag }}
{{- end -}}

{{/* Pod-level security context shared by every crawlx pod. */}}
{{- define "crawlx.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: {{ .uid }}
runAsGroup: {{ .uid }}
fsGroup: {{ .uid }}
{{- end -}}

{{- define "crawlx.containerSecurityContext" -}}
runAsNonRoot: true
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: ["ALL"]
{{- end -}}

{{/* Common env for the crawlx binary: file-backed secrets and the environment name. */}}
{{- define "crawlx.commonEnv" -}}
- name: CRAWLX_ENVIRONMENT
  value: {{ .Values.environment | quote }}
- name: CRAWLX_CONFIG
  value: /etc/crawlx/crawlx.toml
- name: CRAWLX_DATABASE_URL_FILE
  value: {{ .Values.config.database.url_file | quote }}
{{- with .Values.config.telemetry.otlp_endpoint }}
- name: CRAWLX_OTLP_ENDPOINT
  value: {{ . | quote }}
{{- end }}
{{- end -}}

{{/* Only API and worker consumers receive the authenticated delivery endpoint. */}}
{{- define "crawlx.deliveryEnv" -}}
{{- if .Values.zdr.enabled }}
- name: CRAWLX_ZDR_REDIS_URL
  valueFrom:
    secretKeyRef: { name: {{ .Values.zdr.secret }}, key: url }
{{- end }}
{{- end -}}

{{/* Artifact custody. The API receives only the key provider; workers and the config-check
     job (`worker` true) also receive the secret-registry Redis and the authority lifetime.
     Fails closed: no provider, both providers, no secret-registry URL or a bad lifetime stops rendering. */}}
{{- define "crawlx.artifactCustodyEnv" -}}
{{- $a := .root.Values.artifactCustody -}}
{{- if and $a.kmsKeyId $a.keyFileSecret }}
{{- fail "artifactCustody.kmsKeyId and artifactCustody.keyFileSecret are mutually exclusive: set exactly one artifact key provider (CRAWLX_ARTIFACT_KMS_KEY_ID or CRAWLX_ARTIFACT_KEY_FILE)" }}
{{- end }}
{{- if not (or $a.kmsKeyId $a.keyFileSecret) }}
{{- fail "artifactCustody requires an artifact key provider: set artifactCustody.kmsKeyId (cloud KMS key ID/ARN) or artifactCustody.keyFileSecret (Secret with key artifact_key: 64 hexadecimal characters); API and workers must use the same key" }}
{{- end }}
{{- if $a.kmsKeyId }}
- name: CRAWLX_ARTIFACT_KMS_KEY_ID
  value: {{ $a.kmsKeyId | quote }}
{{- else }}
- name: CRAWLX_ARTIFACT_KEY_FILE
  value: /run/secrets/crawlx/artifact_key
{{- end }}
{{- if .worker }}
{{- if not $a.secretRedis.existingSecret }}
{{- fail "artifactCustody.secretRedis.existingSecret is required: name a Secret with key `url` (redis://:<password>@<host>:6379/) of the dedicated, persistence-disabled, noeviction secret-registry Redis; it must not be the ZDR delivery Redis" }}
{{- end }}
{{- $ttl := int $a.secretRedis.ttlSeconds }}
{{- if or (lt $ttl 1) (gt $ttl 86400) }}
{{- fail "artifactCustody.secretRedis.ttlSeconds must be 1..86400" }}
{{- end }}
- name: CRAWLX_SECRET_REDIS_URL_FILE
  value: /run/secrets/crawlx/secret_redis_url
- name: CRAWLX_SECRET_AUTHORITY_TTL_SECS
  value: {{ $ttl | quote }}
{{- end }}
{{- end -}}

{{- define "crawlx.artifactCustodySources" -}}
{{- $a := .root.Values.artifactCustody -}}
{{- if $a.keyFileSecret }}
- secret:
    name: {{ $a.keyFileSecret | quote }}
    items: [{ key: artifact_key, path: artifact_key, mode: 0440 }]
{{- end }}
{{- if .worker }}
- secret:
    name: {{ required "artifactCustody.secretRedis.existingSecret is required" $a.secretRedis.existingSecret | quote }}
    items: [{ key: url, path: secret_redis_url, mode: 0440 }]
{{- end }}
{{- end -}}

{{- define "crawlx.metricsSidecar" -}}
{{- if .Values.config.telemetry.otlp_endpoint }}
- name: metrics
  image: {{ .Values.metricsSidecar.image }}
  args: ["--config=/etc/otelcol/config.yaml"]
  securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities: { drop: ["ALL"] }
    seccompProfile: { type: RuntimeDefault }
  resources:
    requests: { cpu: "20m", memory: 64Mi }
    limits: { memory: 128Mi }
  volumeMounts:
    - { name: metrics-config, mountPath: /etc/otelcol, readOnly: true }
{{- end }}
{{- end -}}

{{/* Optional operator capabilities. Worker-only secrets never enter the API container. */}}
{{- define "crawlx.capabilityEnv" -}}
{{- $c := .root.Values.capabilities -}}
{{- if $c.retainedProfiles.enabled }}
{{- fail "profile_unavailable: retained browser profiles are unavailable while encrypted artifact custody is enabled; set capabilities.retainedProfiles.enabled=false" }}
{{- end }}
{{- if and (or $c.requestIdentity.existingSecret $c.checkpointEncryption.kmsKeyId $c.protocolRegistry.existingSecret $c.deliveryRegistry.existingSecret $c.articleLanguage.existingClaim) (not .root.Values.configCheck.enabled) }}
{{- fail "optional operator capabilities require configCheck.enabled" }}
{{- end }}
{{- if $c.requestIdentity.existingSecret }}
- name: CRAWLX_REQUEST_IDENTITY_KEY_FILE
  value: /run/secrets/crawlx/request_identity_key
{{- end }}
{{- if .worker }}
{{- if $c.checkpointEncryption.kmsKeyId }}
- name: CRAWLX_CHECKPOINT_KMS_KEY_ID
  value: {{ $c.checkpointEncryption.kmsKeyId | quote }}
{{- end }}
{{- if $c.protocolRegistry.existingSecret }}
- name: CRAWLX_PROTOCOL_REGISTRY
  value: /run/secrets/crawlx/protocol_registry.json
{{- end }}
{{- if $c.deliveryRegistry.existingSecret }}
- name: CRAWLX_DELIVERY_REGISTRY
  value: /run/secrets/crawlx/delivery_registry.json
{{- end }}
{{- if $c.articleLanguage.existingClaim }}
- name: CRAWLX_ARTICLE_LANGUAGE_BUNDLE
  value: /opt/crawlx/article-language
- name: ORT_DYLIB_PATH
  value: {{ required "articleLanguage.runtimeLibrary is required" $c.articleLanguage.runtimeLibrary | quote }}
- name: LD_LIBRARY_PATH
  value: {{ dir $c.articleLanguage.runtimeLibrary | quote }}
{{- end }}
{{- end }}
{{- end -}}

{{- define "crawlx.capabilitySources" -}}
{{- $c := .root.Values.capabilities -}}
{{- if $c.requestIdentity.existingSecret }}
- secret:
    name: {{ $c.requestIdentity.existingSecret | quote }}
    items: [{ key: request_identity_key, path: request_identity_key, mode: 0440 }]
{{- end }}
{{- if .worker }}
{{- if $c.protocolRegistry.existingSecret }}
- secret:
    name: {{ $c.protocolRegistry.existingSecret | quote }}
    items: [{ key: registry.json, path: protocol_registry.json, mode: 0440 }]
{{- end }}
{{- if $c.deliveryRegistry.existingSecret }}
- secret:
    name: {{ $c.deliveryRegistry.existingSecret | quote }}
    items: [{ key: registry.json, path: delivery_registry.json, mode: 0440 }]
{{- end }}
{{- end }}
{{- end -}}

{{- define "crawlx.operatorCapabilityMounts" -}}
{{- range $kind := list "protocol" "delivery" }}
{{- $registry := index $.Values.capabilities (printf "%sRegistry" $kind) }}
{{- if $registry.credentialsSecret }}
{{- $_ := required (printf "%sRegistry.existingSecret is required with credentialsSecret" $kind) $registry.existingSecret }}
- { name: {{ $kind }}-credentials, mountPath: /run/secrets/crawlx-{{ $kind }}, readOnly: true }
{{- end }}
{{- end }}
{{- if .Values.capabilities.articleLanguage.existingClaim }}
- { name: article-language, mountPath: /opt/crawlx/article-language, readOnly: true }
{{- end }}
{{- end -}}

{{- define "crawlx.operatorCapabilityVolumes" -}}
{{- range $kind := list "protocol" "delivery" }}
{{- $registry := index $.Values.capabilities (printf "%sRegistry" $kind) }}
{{- if $registry.credentialsSecret }}
- name: {{ $kind }}-credentials
  secret:
    secretName: {{ $registry.credentialsSecret | quote }}
    defaultMode: 0440
{{- end }}
{{- end }}
{{- if .Values.capabilities.articleLanguage.existingClaim }}
- name: article-language
  persistentVolumeClaim:
    claimName: {{ .Values.capabilities.articleLanguage.existingClaim | quote }}
    readOnly: true
{{- end }}
{{- end -}}

{{/* Helm may decode YAML numbers as float64. TOML integer fields must stay integers.
     Normalize only numeric scalar map values, never serialized text or string lists.
     Work on a copy so rendering cannot mutate operator values. */}}
{{- define "crawlx.configIntegers" -}}
{{- range $key, $value := . -}}
{{- if kindIs "map" $value -}}
{{- include "crawlx.configIntegers" $value -}}
{{- else if kindIs "float64" $value -}}
{{- $integer := int64 $value -}}
{{- if eq $value (float64 $integer) -}}
{{- $_ := set $ $key $integer -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "crawlx.configToml" -}}
{{- $config := deepCopy .Values.config -}}
{{- include "crawlx.configIntegers" $config -}}
{{- toToml $config -}}
{{- end -}}
