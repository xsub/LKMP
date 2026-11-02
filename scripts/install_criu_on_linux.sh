#!/usr/bin/env bash
set -euo pipefail

echo "=== Installing libnftables-dev and CRIU dependencies ==="
sudo apt-get update -qq
sudo apt-get install -y -qq \
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
sudo install -m 0755 criu/criu /usr/local/sbin/criu
sudo ln -sf /usr/local/sbin/criu /usr/bin/criu

echo "=== Installed CRIU successfully ==="
sudo criu --version
sudo criu check
sudo criu check --extra || true
