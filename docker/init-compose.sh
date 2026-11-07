#!/usr/bin/env bash
# First-start helper for docker/docker-compose.yml (secrets are files, never flags).
#
# Writes, below DIR (default: the directory of this script):
#   secrets/postgres_password, database_url, database_url_migrate   PostgreSQL role and DSNs
#   secrets/postgres_api_password, database_url_api                  restricted request role
#   secrets/webhook_signing_key                                      HMAC key of webhook deliveries
#   secrets/minio_root_user, minio_root_password                     object store root credentials
#   secrets/artifact_key                                             artifact key (64 hex
#                                                                    characters; api and worker)
#   secrets/secret_custody_redis_password, secret_custody_redis_url  volatile secret-registry Valkey:
#                                                                    its password and the worker's URL
#   gates/                                                           empty; the worker mounts it as
#                                                                    its --gates-dir (g1.passed of the
#                                                                    shipped build goes here)
#   .env                                                             compose variables: the
#                                                                    secrets and gates directories, a
#                                                                    bootstrap API key (`crawlx serve
#                                                                    --api-key`) and the object-store
#                                                                    settings of `crawlx admin`
#
# Existing files are never overwritten (the PostgreSQL password is fixed once its volume exists);
# delete a file to have it generated again. The secrets directory is mode 0700 and the files
# 0444: Docker bind-mounts each file, so the container user (uids 10001, 999, 1001 differ per
# image) reads it through the file mode while the directory keeps other host users out.
#
# Usage: docker/init-compose.sh [DIR]
set -euo pipefail

dir="${1:-$(cd "$(dirname "$0")" && pwd)}"
mkdir -p "$dir/secrets" "$dir/gates"
dir="$(cd "$dir" && pwd)"
secrets="$dir/secrets"
chmod 0700 "$secrets"
umask 077
say() { printf '%s\n' "$*"; }

# Optional keys are operator-provisioned, never generated or rotated by this helper.
# Validate before creating any default secrets. Do not echo key bytes or pass them as arguments.
validate_optional_key() {
  local name="$1" file="$2" bytes key
  [ -n "$file" ] || { say "$name must name a non-empty key file" >&2; exit 1; }
  [ -f "$file" ] && [ -r "$file" ] || { say "$name must name a readable regular file" >&2; exit 1; }
  bytes="$(wc -c <"$file")"
  if [ "$bytes" -ne 64 ] && [ "$bytes" -ne 65 ]; then
    say "$name requires exactly 64 hexadecimal characters (optional final LF)" >&2
    exit 1
  fi
  IFS= read -r key <"$file" || true
  if [[ ! "$key" =~ ^[0123456789abcdefABCDEF]{64}$ ]]; then
    say "$name requires exactly 64 hexadecimal characters (optional final LF)" >&2
    exit 1
  fi
}
if [[ ${CRAWLX_REQUEST_IDENTITY_KEY_FILE+x} ]]; then
  if [[ ${CRAWLX_REQUEST_IDENTITY_KEY+x} ]]; then
    printf '%s\n' 'request identity inline and file settings are mutually exclusive' >&2
    exit 1
  fi
  validate_optional_key CRAWLX_REQUEST_IDENTITY_KEY_FILE "$CRAWLX_REQUEST_IDENTITY_KEY_FILE"
fi
if [[ ${CRAWLX_PROFILE_KEY_FILE+x} ]]; then
  validate_optional_key CRAWLX_PROFILE_KEY_FILE "$CRAWLX_PROFILE_KEY_FILE"
fi

hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

# write_secret NAME VALUE: create secrets/NAME unless it exists
write_secret() {
  local file="$secrets/$1"
  if [ -e "$file" ]; then
    say "kept    $file"
    return
  fi
  printf '%s' "$2" >"$file"
  chmod 0444 "$file"
  say "created $file"
}

# postgres_password and the DSNs derive from one password: reuse the stored one
if [ -e "$secrets/postgres_password" ]; then
  pg_password="$(cat "$secrets/postgres_password")"
else
  pg_password="$(hex 24)"
fi
dsn="postgres://crawlx:${pg_password}@postgres:5432/crawlx"

write_secret postgres_password "$pg_password"
write_secret database_url "$dsn"
# the DDL role (`crawlx_migrate`); one role until the operator splits them
write_secret database_url_migrate "$dsn"
if [ -e "$secrets/postgres_api_password" ]; then
  api_password="$(cat "$secrets/postgres_api_password")"
else
  api_password="$(hex 24)"
fi
write_secret postgres_api_password "$api_password"
write_secret database_url_api "postgres://crawlx_api:${api_password}@postgres:5432/crawlx"
write_secret webhook_signing_key "$(hex 32)"
write_secret minio_root_user "crawlx$(hex 4)"
write_secret minio_root_password "$(hex 24)"
# Artifact custody. The artifact key seals every encrypted artifact: it is generated once
# and then kept (replacing it makes existing sealed artifacts unreadable). The registry URL derives
# from one stored password, like the PostgreSQL DSNs.
write_secret artifact_key "$(hex 32)"
if [ -e "$secrets/secret_custody_redis_password" ]; then
  custody_password="$(cat "$secrets/secret_custody_redis_password")"
else
  custody_password="$(hex 24)"
fi
write_secret secret_custody_redis_password "$custody_password"
write_secret secret_custody_redis_url "redis://:${custody_password}@secret-custody:6379/"

env_file="$dir/.env"
if [ -e "$env_file" ]; then
  say "kept    $env_file"
else
  # cx_live_ + 26 base32 characters (a-z, 2-7), the key format `crawlx serve --api-key` accepts
  secret="$(head -c 17 /dev/urandom | base32 | tr 'A-Z' 'a-z' | tr -d '=\n' | cut -c1-26)"
  {
    say "# generated by docker/init-compose.sh; contains secrets, keep it mode 0600"
    say "CRAWLX_SECRETS_DIR=\"$secrets\""
    say "CRAWLX_API_KEY_SPEC=\"default=cx_live_${secret}\""
    say "CRAWLX_GATES_HOST_DIR=\"$dir/gates\""
    say "CRAWLX_S3_BUCKET=crawlx-artifacts"
    say "CRAWLX_S3_ACCESS_KEY=\"$(cat "$secrets/minio_root_user")\""
    say "CRAWLX_S3_SECRET_KEY=\"$(cat "$secrets/minio_root_password")\""
  } >"$env_file"
  chmod 0600 "$env_file"
  say "created $env_file"
fi

say "next: docker compose -f docker/docker-compose.yml up -d --build --wait"
say "      the API key is CRAWLX_API_KEY_SPEC in $env_file (the part after 'default=')"
