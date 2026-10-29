# LKMP (`lkmp`) — Linux Process Live Migration Orchestrator

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![CRIU](https://img.shields.io/badge/engine-CRIU%204.x-green.svg)](https://criu.org/)

**LKMP** (`lkmp`) is a process-tree live migration orchestrator built on top of **CRIU** (*Checkpoint/Restore In Userspace*). It moves a running Linux process (or process tree) from **Source Host A** to **Destination Host B** with minimal downtime, preserving memory, registers, open file descriptors, and active TCP connections—while guaranteeing a deterministic **rollback** to the source host if anything fails.

---

## Why LKMP?

CRIU provides the low-level checkpoint/restore engine, and the legacy `P.Haul` project that once orchestrated multi-host migrations on top of CRIU is unmaintained. `lkmp` fills that gap as a modern, zero-dependency orchestrator that handles:

- **Migration Envelope (`lkmp run`)**: Launches workloads inside isolated `pid`, `net`, `mnt`, `ipc`, `uts`, and `time` (`CLOCK_MONOTONIC` / `CLOCK_BOOTTIME` offset) namespaces with a dedicated `cgroup v2` subtree for atomic freezing.
- **Non-Destructive Preflight Analysis (`lkmp preflight`)**:
  - Verifies CPU instruction-set superset compatibility (`avx2`, `avx512f`, `xsave`, etc.) so `glibc` IFUNC-resolved code paths never crash with `SIGILL` after migration.
  - Parses ELF64/ELF32 `.note.gnu.build-id` notes and SHA-256 digests across `/proc/<pid>/maps` and `/proc/<pid>/fd` to verify binary identity on Destination B.
  - Detects kernel blockers (`io_uring`, active `ptrace`, unconfigured hardware devices) and auto-configures required CRIU flags (`--ext-unix-sk`, `--ghost-limit`).
- **Iterative Pre-Copy & Lazy Post-Copy**: Streams dirty memory pages over TLS (`criu page-server`) while the workload runs, or demand-pages memory after restore via `userfaultfd` (`criu lazy-pages`).
- **TCP Preservation & IP Mobility**: Locks workload network traffic with `nftables` (preventing kernel TCP `RST` packets during switchover) and moves the workload IP via L2 Gratuitous ARP (`garp`), L3 BGP `/32` routes (`bgp`), or cloud API webhooks (`cloud`).
- **Transactional Rollback & Secret Wiping**: Keeps the source process intact (`--leave-stopped`) until the restored process passes health checks on Destination B. On commit, memory dump files (`pages-*.img`, `core-*.img`) are overwritten with zeros before deletion.

---

## Architecture

```mermaid
flowchart LR
    CLI["lkmp CLI / Controller"] -->|"JSON-RPC + mTLS"| AA["lkmp-agent (Source A)"]
    CLI -->|"JSON-RPC + mTLS"| AB["lkmp-agent (Destination B)"]
    AA -->|"pre-dump / dump"| CA["CRIU (Source A)"]
    AB -->|"page-server / restore / lazy-pages"| CB["CRIU (Destination B)"]
    CA -->|"Memory pages over TLS"| CB
    AA -->|"Metadata .img + fs delta (rsync)"| AB
    AA -.->|"1. Release IP + nftables lock"| NET["IP Mobility (GARP / BGP / Cloud)"]
    AB -.->|"2. Claim IP + unlock"| NET
```

### Migration State Machine

```mermaid
stateDiagram-v2
    [*] --> PREFLIGHT
    PREFLIGHT --> PREPARE: Compatible
    PREFLIGHT --> ABORTED: Blocker detected
    PREPARE --> PRE_COPY: fs pre-synced
    PRE_COPY --> PRE_COPY: Dirty set shrinking
    PRE_COPY --> FREEZE: Converged / <10% shrink / max_iter
    FREEZE --> FINAL_DUMP: nftables locked, cgroup frozen
    FINAL_DUMP --> TRANSFER: Final pages + metadata + fs delta
    TRANSFER --> RESTORE
    RESTORE --> SWITCHOVER: Process restored on B (stopped)
    SWITCHOVER --> VERIFY: IP moved, SIGCONT on B
    VERIFY --> COMMIT: Health check OK
    VERIFY --> ROLLBACK: Health check failed
    RESTORE --> ROLLBACK: Restore error
    ROLLBACK --> [*]: Resume on Source A (SIGCONT)
    COMMIT --> [*]: Kill Source A & zero-wipe images
    ABORTED --> [*]
```

---

## Migration Strategies

| Strategy (`--strategy`) | Downtime | Risk | Best For |
| :--- | :--- | :--- | :--- |
| **`cold`** | `RSS / bandwidth` (seconds) | Lowest | Small processes, batch jobs, simple stop-and-copy |
| **`pre-copy`** *(default)* | `final_dirty / bandwidth + restore` (tens to hundreds of ms) | Low (full rollback on A) | General stateful services, databases, network servers |
| **`lazy`** | Minimal (metadata transfer only) | Higher (page faults over network via `userfaultfd`) | Huge memory footprints with high write rates where pre-copy does not converge |
| **`hybrid`** | Minimal | Medium | Large memory with a hot working set (`pre-dump` rounds followed by `--lazy-pages`) |

### Pre-Copy Convergence Rules
Iterative `pre-dump` rounds stop automatically when **any** of the following holds:
1. **Target Downtime Met**: $\text{dirty\_bytes} \le \text{bandwidth} \times \text{target\_downtime}$
2. **Diminishing Returns**: Dirty page volume shrank by $< 10\%$ compared to the previous round
3. **Iteration Cap**: Reached `--max-iter` (default `8`)

---

## Project Structure

```text
.
├── bin/lkmp                      # Executable CLI entrypoint
├── lkmp/
│   ├── config.py                 # MigrationConfig, EnvelopeConfig, strategy/mode enums
│   ├── models.py                 # State machine states, preflight & telemetry models
│   ├── envelope.py               # Namespace unshare & cgroup v2 freeze manager
│   ├── preflight.py              # /proc inspector, ELF build-id parser, ISA superset checker
│   ├── convergence.py            # Pre-copy convergence math & dirty-page tracker
│   ├── criu_driver.py            # CRIU command builder & GPU plugin hooks (cuda-checkpoint, amdgpu)
│   ├── network.py                # nftables packet lock & GARP/BGP/Cloud IP mobility
│   ├── fs_sync.py                # rsync pre-sync, frozen delta sync & zero-wipe
│   ├── agent.py                  # Privileged host daemon (lkmp-agent) & TLS JSON-RPC
│   ├── orchestrator.py           # 10-state migration controller & rollback engine
│   └── cli.py                    # CLI parser and command handlers
├── deploy/
│   ├── Dockerfile.node           # Ubuntu 24.04 node image with CRIU, nftables, iproute2
│   └── docker-compose.test.yml   # Two-node privileged test cluster on shared L2 bridge
└── tests/                        # Unit & end-to-end two-agent TCP RPC test suite
```

---

## Quick Start

### 1. Installation & Tests

`lkmp` uses the Python 3.10+ standard library with zero external Python package dependencies.

```bash
git clone https://github.com/xsub/LKMP.git
cd LKMP

# Run the unit and two-agent RPC integration test suite
python3 -m unittest discover -s tests -p "test_*.py" -v
```

### 2. Start `lkmp-agent` on Source A and Destination B

On both Linux hosts (requires `root` or `CAP_CHECKPOINT_RESTORE` + `CAP_SYS_ADMIN` + `CAP_NET_ADMIN`):

```bash
# On Source Host A (10.0.0.1)
sudo ./bin/lkmp agent \
  --host 0.0.0.0 \
  --port 9700 \
  --tls-ca /etc/lkmp/ca.pem \
  --tls-cert /etc/lkmp/node-a.pem \
  --tls-key /etc/lkmp/node-a.key

# On Destination Host B (10.0.0.2)
sudo ./bin/lkmp agent \
  --host 0.0.0.0 \
  --port 9700 \
  --tls-ca /etc/lkmp/ca.pem \
  --tls-cert /etc/lkmp/node-b.pem \
  --tls-key /etc/lkmp/node-b.key
```

### 3. Launch a Workload inside a Migration Envelope on Host A

```bash
sudo ./bin/lkmp run \
  --id srv-1 \
  --ip 10.0.0.99/24 \
  --iface eth0 \
  -- /usr/local/bin/my-stateful-server
```

### 4. Run Non-Destructive Preflight Check

```bash
./bin/lkmp preflight \
  --pid 4242 \
  --source 10.0.0.1:9700 \
  --dest 10.0.0.2:9700 \
  --strategy pre-copy
```

### 5. Live-Migrate the Process Tree from Host A to Host B

```bash
./bin/lkmp migrate \
  --pid 4242 \
  --workload-id srv-1 \
  --source 10.0.0.1:9700 \
  --dest 10.0.0.2:9700 \
  --strategy pre-copy \
  --fs-mode rsync \
  --writable-path /var/lib/my-stateful-server \
  --ip-mobility garp \
  --workload-ip 10.0.0.99/24 \
  --health-cmd "curl -sf http://10.0.0.99:8080/healthz"
```

---

## Two-Node Test Cluster (Docker Compose)

You can spin up a two-node Linux cluster (`node-a` at `172.28.0.10` and `node-b` at `172.28.0.11`) with CRIU, `nftables`, `iproute2`, and `rsync` pre-installed:

```bash
docker compose -f deploy/docker-compose.test.yml up -d --build
```

---

## CLI Reference

| Command | Description |
| :--- | :--- |
| `lkmp run` | Start a process tree inside an isolated PID/net/mnt/ipc/uts/time namespace and `cgroup v2` envelope |
| `lkmp agent` | Start the privileged `lkmp-agent` JSON-RPC daemon on a host |
| `lkmp preflight` | Inspect `/proc/<pid>`, verify CPU ISA superset & ELF build-ids on Destination B, and estimate downtime |
| `lkmp migrate` | Run the full migration state machine (`Preflight` → `PreCopy` → `Freeze` → `Restore` → `Switchover` → `Verify` → `Commit`/`Rollback`) |

### Key `lkmp migrate` Flags

- `--strategy {cold,pre-copy,lazy,hybrid}`: Memory transfer mode (default: `pre-copy`)
- `--fs-mode {shared,rsync}`: Shared storage verification or `rsync` pre-sync + frozen delta sync
- `--ip-mobility {none,garp,bgp,cloud}`: How the workload IP moves during switchover
- `--gpu-plugin {none,amdgpu,cuda-checkpoint}`: Coordinate AMD or NVIDIA GPU state serialization alongside CRIU
- `--unsafe-bare`: Allow migrating a bare host process not started inside `lkmp run`
- `--health-cmd <cmd>`: Command executed on Destination B before committing; non-zero exit triggers automatic rollback to Source A

---

## License

Apache License 2.0
