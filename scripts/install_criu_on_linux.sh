#!/usr/bin/env bash
set -euo pipefail

SUDO=""
if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
fi

echo "=== Installing libnftables-dev and CRIU dependencies ==="
$SUDO apt-get update -qq
$SUDO apt-get install -y -qq \
    iproute2 \
    nftables \
    libnftables-dev \
    rsync \
    build-essential \
    pkg-config \
    libprotobuf-dev \
    libprotobuf-c-dev \
    protobuf-c-compiler \
    protobuf-compiler \
    python3-protobuf \
    libnl-3-dev \
    libnl-route-3-dev \
    libcap-dev \
    libnet1-dev \
    uuid-dev \
    libbsd-dev \
    libdrm-dev \
    libgnutls28-dev \
    python3-yaml \
    git \
    curl

echo "=== Building latest CRIU (with Linux 6.12+/7.0 vvar_vclock vDSO & libnftables support) ==="
WORKDIR="/tmp/criu-build-latest"
rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"
cd "$WORKDIR"

git clone --depth 1 https://github.com/checkpoint-restore/criu.git criu-src
cd criu-src
make -j"$(nproc)" criu/criu
$SUDO install -m 0755 criu/criu /usr/local/sbin/criu
$SUDO ln -sf /usr/local/sbin/criu /usr/bin/criu
rm -rf "$WORKDIR"

echo "=== Installed CRIU successfully ==="
$SUDO criu --version
$SUDO criu check || true
$SUDO criu check --extra || true
