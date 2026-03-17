[![Repolytics](https://api.repolytics.site/api/badge/Ketankhunti/railway?style=flat&color=blue&metric=code)](https://www.repolytics.site/github/Ketankhunti/railway)

# Rail-Obs: Zero-Instrumentation Observability Engine

An eBPF-powered observability platform that captures HTTP traces across containerized services at the kernel level — **without any code changes, SDKs, or instrumentation**.

## What It Does

```
Your services (Flask, Node.js, Go, Rust — any language)
      │ plain HTTP calls
      ▼
eBPF probes in the Linux kernel capture every request/response
      │ automatic, zero config
      ▼
Traces with parent-child relationships, latency, error rates
      │
      ▼
REST API → Dashboard / Alerts / Correlation
```

**Verified:** A `GET /api/users/42` request through Flask services produces a linked trace chain — parent span → child span — captured entirely from kernel-level eBPF probes with zero application changes.

## Architecture

```
┌──────────────────── Linux Host ─────────────────────┐
│                                                      │
│  ┌─────────┐  HTTP  ┌─────────┐  HTTP  ┌─────────┐ │
│  │ Service │───────→│ Service │───────→│ Service │ │
│  │    A    │        │    B    │        │    C    │ │
│  └─────────┘        └─────────┘        └─────────┘ │
│                                                      │
│  12 eBPF Probes (kernel space):                      │
│    5 kprobes:  tcp_v4_connect, inet_csk_accept,      │
│                tcp_sendmsg, tcp_recvmsg, tcp_close    │
│    7 tracepoints: sys_enter_write, sys_enter_sendto, │
│                   sys_enter_writev, sys_enter_read,   │
│                   sys_exit_read, sys_enter_recvfrom,  │
│                   sys_exit_recvfrom                   │
│                                                      │
│  ┌──────────────────────────────────────────────────┐│
│  │ Collector (Rust)                                  ││
│  │  Ring Buffer → Span Assembler → Alert Engine      ││
│  │  → REST API (:3000)                               ││
│  └──────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────┘
```

## Key Features

- **Zero instrumentation** — no OTEL SDK, no code changes, no sidecars
- **12 eBPF probes** covering all TCP syscall variants (write, sendto, writev, read, recvfrom)
- **HTTP payload capture** — 2KB per event via 4×512-byte chunked BPF reads
- **Parent-child trace correlation** — links spans across services using 4-tuple + PID matching
- **Streaming anomaly detection** — z-score, threshold, and rate-of-change alerting
- **ClickHouse storage** — AggregatingMergeTree with p50/p95/p99 rollups
- **Route normalization** — `/api/users/123` → `/api/users/:id`
- **159 automated tests** across 9 Rust crates

## Project Structure

```
rail-obs/
├── crates/                    # Rust workspace (9 crates)
│   ├── common/                # Shared types: SpanEvent, TraceContext, ServiceMapping
│   ├── http-parser/           # HTTP/1.1 request/response parser (33 tests)
│   ├── span-assembler/        # Connection state machine, parent-child correlation (18 tests)
│   ├── ingestion/             # Route normalization, ClickHouse writer (14 tests)
│   ├── alerting/              # Threshold, anomaly (z-score), rate-of-change rules (30 tests)
│   ├── api/                   # REST API: traces, metrics, topology, alerts (22 tests)
│   ├── collector/             # Main binary with synthetic + real eBPF sources
│   └── discovery/             # Docker container → netns resolution (28 tests)
│
├── ebpf/                      # eBPF workspace (separate Cargo workspace)
│   ├── rail-obs-ebpf-common/  # Shared types between kernel and userspace
│   ├── rail-obs-ebpf-probes/  # 12 BPF programs compiled to bytecode
│   └── rail-obs-userspace/    # Loads probes, reads ring buffer, runs full pipeline
│
├── sql/
│   ├── clickhouse/            # spans, rollups (AggregatingMergeTree), topology, trace_logs
│   └── postgres/              # alert_rules, alert_events
│
├── demo/                      # Demo services (Docker)
│   ├── api-gateway/           # Python/Flask — entry point
│   ├── user-service/          # Node.js/Express — user CRUD
│   ├── db-service/            # Python/Flask — mock database
│   ├── payment-service/       # Python/Flask — 5% error rate
│   ├── docker-compose.yml
│   └── generate-traffic.sh
│
└── ARCHITECTURE.md            # Detailed design document (reviewed 3 rounds)
```

## Quick Start

### Run with Synthetic Data (Windows/Mac/Linux)

```bash
# Build and run the collector with synthetic traffic
cargo run -p rail-obs-collector

# Query traces
curl http://localhost:3000/api/v1/traces?project_id=proj_demo&start_time=2000-01-01&end_time=2030-12-31&limit=5

# Query alerts
curl http://localhost:3000/api/v1/alerts/events?project_id=proj_demo

# Health check
curl http://localhost:3000/health
```

### Run with Real eBPF (Linux / WSL2)

```bash
# Build eBPF probes (requires nightly Rust + bpf-linker)
cd ebpf
cargo +nightly build -p rail-obs-ebpf-probes \
  --target bpfel-unknown-none -Z build-std=core --release

# Build userspace collector
cargo build -p rail-obs-userspace

# Run (requires root / CAP_BPF)
sudo target/debug/rail-obs-userspace \
  target/bpfel-unknown-none/release/rail-obs-probes

# In another terminal — start demo services
cd demo && docker compose up --build -d

# Generate traffic
curl http://localhost:8001/api/users/42

# Query traces from eBPF
curl -G http://localhost:3000/api/v1/traces \
  -d project_id=unknown -d start_time=1970-01-01 \
  -d end_time=2030-12-31 -d limit=10
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/api/v1/traces` | List traces (filterable) |
| GET | `/api/v1/traces/{trace_id}` | Trace detail with all spans |
| GET | `/api/v1/services/{id}/metrics` | Service metrics timeseries |
| GET | `/api/v1/services/topology` | Service dependency graph |
| POST | `/api/v1/alerts/rules` | Create alert rule |
| GET | `/api/v1/alerts/rules` | List alert rules |
| PUT | `/api/v1/alerts/rules/{id}` | Update alert rule |
| DELETE | `/api/v1/alerts/rules/{id}` | Delete alert rule |
| GET | `/api/v1/alerts/events` | List alert events |
| GET | `/api/v1/correlate/metric-to-traces` | Find traces causing a metric spike |
| GET | `/api/v1/correlate/trace-to-logs/{trace_id}` | Logs correlated to a trace |

## How Tracing Works

### 1. eBPF Probes Capture TCP Events

```
kprobe/tcp_sendmsg                      → 4-tuple (src:port → dst:port)
tracepoint/syscalls/sys_enter_sendto    → HTTP payload ("GET /api/users/42 HTTP/1.1\r\n...")
```

Both fire for the same syscall on the same PID. Userspace correlates them.

### 2. HTTP Parser Extracts Request Details

```
"GET /api/users/42 HTTP/1.1\r\nHost: user-service\r\ntraceparent: 00-abc...\r\n\r\n"
  → method: GET
  → path: /api/users/42
  → route: /api/users/:id (normalized)
  → traceparent: extracted if present
```

### 3. Span Assembler Links Parent → Child

```
Service A sends GET to Service B at 172.17.0.3:8002
  → Client span created: trace_id=X, span_id=A

Service B receives GET on 172.17.0.3:8002
  → Matched by 4-tuple to client span
  → Server span created: trace_id=X, parent_span_id=A

Result: A → B linked chain with shared trace_id
```

### 4. Alert Engine Evaluates Rules

```yaml
rule: "High Error Rate"
type: threshold
metric: error_rate > 10%
window: 60s

rule: "Latency Anomaly"
type: anomaly
metric: p99_latency
z_score_threshold: 3.0
baseline: 300s
```

## Tests

```bash
cargo test
# 159 tests across 9 crates, all passing
```

| Crate | Tests | Coverage |
|-------|-------|----------|
| common | 13 | Trace ID encoding, W3C traceparent parsing, service mapping |
| http-parser | 33 | All HTTP methods, truncation, non-HTTP rejection, headers |
| span-assembler | 18 | Keep-alive, pipelining, same-host correlation, parent-child |
| ingestion | 14 | Route normalization, ClickHouse row conversion |
| alerting | 30 | Threshold, anomaly (z-score), rate-of-change, dedup, cooldown |
| api | 22 | All 12 endpoints, CRUD, correlation, filtering |
| discovery | 28 | Netns parsing, Docker inspect, mapping file, edge cases |

## Tech Stack

| Component | Technology | Why |
|-----------|-----------|-----|
| eBPF probes | Rust + Aya | Safe BPF in Rust, no BCC/libbpf dependency |
| Collector | Rust + Tokio | High-throughput async, single binary |
| Storage | ClickHouse | Column-oriented, 10-20x compression, 1M+ rows/sec insert |
| Alert metadata | PostgreSQL | Transactional CRUD for mutable config |
| API | Rust + Axum | Async, fast, consistent with collector stack |
| Demo services | Python/Flask, Node.js | Multi-language to prove zero-instrumentation |

## Requirements

### For synthetic pipeline (development)
- Rust stable (1.94+)
- No other dependencies

### For eBPF (production / demo)
- Linux kernel 5.8+ (ring buffer support)
- Rust nightly + `bpf-linker`
- Root access or CAP_BPF + CAP_NET_ADMIN
- clang/llvm for BPF compilation
- Docker (for demo services)

## License

MIT
