#!/usr/bin/env bash
set -euo pipefail

TLS_DIR="${LKMP_TLS_DIR:-/etc/lkmp/tls}"
mkdir -p "${TLS_DIR}" /var/lib/lkmp/migrations /var/lib/lkmp/journals

# Serialize initial shared PKI bootstrap across containers sharing the PKI volume
(
  flock -x 9
  if [[ ! -s "${TLS_DIR}/ca.crt" || ! -s "${TLS_DIR}/node.crt" || ! -s "${TLS_DIR}/node.key" ]]; then
    lkmp tls-init \
      --out-dir "${TLS_DIR}" \
      --host localhost \
      --host node-a \
      --host node-b \
      --host 127.0.0.1 \
      --host ::1 \
      --host 172.28.0.10 \
      --host 172.28.0.11 \
      --overwrite
  fi
) 9>"${TLS_DIR}/.bootstrap.lock"

exec "$@"
