#!/usr/bin/env bash
# Throwaway service containers for the backend integration tests (search, analytics, event
# streams). Every container has a unique name and a loopback-only port, keeps its data in tmpfs and
# is removed by `down`.
#
#   eval "$(ci/backend-services.sh up opensearch elasticsearch clickhouse kafka rabbitmq)"
#   cargo test -p crawlx-worker --lib delivery::backends
#   ci/backend-services.sh down
#
# `up` prints `export CRAWLX_TEST_...` lines on stdout (progress goes to stderr) and records the
# container names in ${CRAWLX_BACKEND_STATE:-$PWD/target/backend-services.names}. The runtime is
# podman or docker (`CRAWLX_CONTAINER_RUNTIME` overrides). Ports start at ${CRAWLX_BACKEND_PORT_BASE:-19200}.
set -euo pipefail

runtime="${CRAWLX_CONTAINER_RUNTIME:-}"
if [ -z "$runtime" ]; then
  if command -v podman >/dev/null 2>&1; then runtime=podman; else runtime=docker; fi
fi
state="${CRAWLX_BACKEND_STATE:-$PWD/target/backend-services.names}"
base="${CRAWLX_BACKEND_PORT_BASE:-19200}"
suffix="${CRAWLX_BACKEND_SUFFIX:-$$-$RANDOM}"

OPENSEARCH_IMAGE="${CRAWLX_OPENSEARCH_IMAGE:-docker.io/opensearchproject/opensearch:2}"
ELASTICSEARCH_IMAGE="${CRAWLX_ELASTICSEARCH_IMAGE:-docker.elastic.co/elasticsearch/elasticsearch:8.15.3}"
CLICKHOUSE_IMAGE="${CRAWLX_CLICKHOUSE_IMAGE:-docker.io/clickhouse/clickhouse-server:latest}"
KAFKA_IMAGE="${CRAWLX_KAFKA_IMAGE:-docker.io/apache/kafka:latest}"
RABBITMQ_IMAGE="${CRAWLX_RABBITMQ_IMAGE:-docker.io/library/rabbitmq:4-management}"

log() { echo "backend-services: $*" >&2; }

start() { # name port-offset image args...
  local name="crawlx-bk-$1-$suffix"
  shift
  echo "$name" >> "$state"
  "$runtime" run -d --name "$name" "$@" >/dev/null
}

wait_http() { # url attempts
  local i
  for ((i = 0; i < ${2:-90}; i++)); do
    if curl -fsS -m 3 "$1" >/dev/null 2>&1; then return 0; fi
    sleep 2
  done
  log "timed out waiting for $1"
  return 1
}

up() {
  mkdir -p "$(dirname "$state")"
  : > "$state"
  local offset=0 service port
  for service in "$@"; do
    port=$((base + offset))
    offset=$((offset + 1))
    case "$service" in
      opensearch)
        start opensearch -p "127.0.0.1:$port:9200" --tmpfs /usr/share/opensearch/data:rw,size=1g,mode=1777 \
          -e discovery.type=single-node -e DISABLE_SECURITY_PLUGIN=true -e DISABLE_INSTALL_DEMO_CONFIG=true \
          -e OPENSEARCH_JAVA_OPTS="-Xms512m -Xmx512m" "$OPENSEARCH_IMAGE"
        wait_http "http://127.0.0.1:$port/" 120
        echo "export CRAWLX_TEST_OPENSEARCH_URL=http://127.0.0.1:$port"
        ;;
      elasticsearch)
        start elasticsearch -p "127.0.0.1:$port:9200" --tmpfs /usr/share/elasticsearch/data:rw,size=1g,mode=1777 \
          -e discovery.type=single-node -e xpack.security.enabled=false -e ES_JAVA_OPTS="-Xms512m -Xmx512m" \
          "$ELASTICSEARCH_IMAGE"
        wait_http "http://127.0.0.1:$port/" 120
        echo "export CRAWLX_TEST_ELASTICSEARCH_URL=http://127.0.0.1:$port"
        ;;
      clickhouse)
        start clickhouse -p "127.0.0.1:$port:8123" --tmpfs /var/lib/clickhouse:rw,size=1g,mode=1777 \
          -e CLICKHOUSE_SKIP_USER_SETUP=1 --ulimit nofile=262144:262144 "$CLICKHOUSE_IMAGE"
        wait_http "http://127.0.0.1:$port/ping" 90
        echo "export CRAWLX_TEST_CLICKHOUSE_URL=http://127.0.0.1:$port"
        ;;
      kafka)
        start kafka -p "127.0.0.1:$port:9092" \
          -e KAFKA_NODE_ID=1 -e KAFKA_PROCESS_ROLES=broker,controller \
          -e KAFKA_LISTENERS=PLAINTEXT://:9092,CONTROLLER://:9093 \
          -e KAFKA_ADVERTISED_LISTENERS="PLAINTEXT://127.0.0.1:$port" \
          -e KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER \
          -e KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT \
          -e KAFKA_CONTROLLER_QUORUM_VOTERS=1@localhost:9093 \
          -e KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1 -e KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR=1 \
          -e KAFKA_TRANSACTION_STATE_LOG_MIN_ISR=1 -e KAFKA_LOG_DIRS=/tmp/kraft-logs \
          --tmpfs /tmp:rw,size=1g,mode=1777 "$KAFKA_IMAGE"
        # the broker has no HTTP interface: wait for the port to accept connections
        local i
        for ((i = 0; i < 60; i++)); do
          if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then break; fi
          sleep 2
        done
        sleep 8
        echo "export CRAWLX_TEST_KAFKA_BROKERS=127.0.0.1:$port"
        ;;
      rabbitmq)
        local management=$((port + 100))
        start rabbitmq -p "127.0.0.1:$port:5672" -p "127.0.0.1:$management:15672" \
          -e RABBITMQ_DEFAULT_USER=crawlx -e RABBITMQ_DEFAULT_PASS=crawlx-test-only "$RABBITMQ_IMAGE"
        wait_http "http://crawlx:crawlx-test-only@127.0.0.1:$management/api/overview" 90
        echo "export CRAWLX_TEST_AMQP_URL=amqp://127.0.0.1:$port/%2f"
        echo "export CRAWLX_TEST_AMQP_USER=crawlx"
        echo "export CRAWLX_TEST_AMQP_PASSWORD=crawlx-test-only"
        echo "export CRAWLX_TEST_AMQP_MANAGEMENT=http://127.0.0.1:$management"
        ;;
      *)
        log "unknown service $service (opensearch, elasticsearch, clickhouse, kafka, rabbitmq)"
        return 2
        ;;
    esac
    log "$service ready on 127.0.0.1:$port"
  done
}

down() {
  [ -f "$state" ] || return 0
  local name
  while read -r name; do
    [ -n "$name" ] && "$runtime" rm -f "$name" >/dev/null 2>&1 || true
  done < "$state"
  rm -f "$state"
}

case "${1:-}" in
  up) shift; up "$@" ;;
  down) down ;;
  *) echo "usage: $0 up <service>... | down" >&2; exit 2 ;;
esac
