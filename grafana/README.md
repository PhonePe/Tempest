<!-- SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Tempest Grafana Dashboard

## Setup

### 1. Prometheus Scrape Config

The metrics route requires Tempest's API key by default
(`api.metrics_require_api_key = true`). Tempest reads the key only from the
`x-api-key` request header, so Prometheus `authorization` or `bearer_token`
settings do not work. If your Prometheus version supports `http_headers` in the
scrape configuration, send the header from a protected file containing the same
value as `api.api_key`:

```yaml
scrape_configs:
  - job_name: 'tempest'
    scrape_interval: 15s
    metrics_path: '/metrics'
    http_headers:
      x-api-key:
        files: ['/etc/prometheus/secrets/tempest-api-key']
    static_configs:
      - targets: ['localhost:8080']
```

`8080` is the default `api.port`; use your configured value. Otherwise, when
Prometheus reaches Tempest only through a trusted observability network, enable
the narrowly scoped exception and omit `http_headers`:

```toml
[api]
enable_metrics = true
metrics_require_api_key = false
```

This does not disable authentication on any `/api/v1` control route. Keep the
Tempest HTTP listener firewalled from untrusted networks because `/metrics`
exposes operational state.

### 2. Import Dashboard

1. Open Grafana → Dashboards → Import
2. Upload `tempest-dashboard.json` from this directory
3. Select your Prometheus datasource

### 3. Metrics Endpoint

Tempest exposes Prometheus-format metrics at:

```
GET http://<tempest-host>:8080/metrics
```

## Exposed Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `tempest_active_transfers` | gauge | Currently active TFTP and HTTP artifact transfers |
| `tempest_uptime_seconds` | gauge | Server uptime |
| `tempest_drain_mode` | gauge | Whether drain mode is active (0/1) |
| `tempest_transfers_total{phase}` | counter | Total transfers started, by boot phase |
| `tempest_transfer_bytes_total{phase}` | counter | Total bytes transferred, by boot phase |
| `tempest_transfer_failures_total{phase}` | counter | Failed transfers, by boot phase |
| `tempest_retransmissions_total` | counter | Total packet retransmissions |
| `tempest_transfers_by_transport_total{transport}` | counter | Transfers started by `TFTP`, bearer `HTTP`, or `HTTP_NATIVE` |
| `tempest_transfer_bytes_by_transport_total{transport}` | counter | Bytes completed by transport/authorization mode |
| `tempest_transfer_failures_by_transport_total{transport}` | counter | Failed transfers by transport/authorization mode |
| `tempest_transfers_by_profile_transport_total{boot_profile,transport}` | counter | Profile-scoped transfer count, including native HTTP Boot |
| `tempest_active_boot_sessions{boot_profile}` | gauge | Active boot sessions by profile |
| `tempest_rate_limit_rejected_total{layer}` | counter | Rate-limited requests (TFTP/API) |
| `tempest_capacity_rejected_total` | counter | Requests rejected at max capacity |
| `tempest_admission_queued_total` | counter | Requests placed in admission queue |
| `tempest_admission_started_total` | counter | Requests dequeued and started |
| `tempest_admission_dropped_total` | counter | Requests dropped from queue |
| `tempest_extension_failures_total{contract,operation}` | counter | Explicit scheduler, read-protocol, and router errors or rejected provider output |
| `tempest_version_groups_total` | gauge | Registered version groups |
| `tempest_active_versions` | gauge | Active file versions |
| `tempest_quarantined_files` | gauge | Files blocked by integrity policy |
| `tempest_transfer_duration_seconds{phase}` | histogram | Transfer duration distribution |
| `tempest_release_control_events_total{event}` | counter | Cutover, integrity, rollback, withdrawal, and signature outcomes |
| `tempest_release_cutover_duration_seconds` | histogram | Release cutover duration distribution |

## Dashboard Panels

The dashboard is organized into sections:

- **Overview** — stat panels for active transfers, uptime, drain mode, quarantine, versions
- **Transfer Throughput** — per-phase transfer rates, bytes/s, failure rates
- **Transfer Duration** — p50/p95/p99 latency histograms per boot phase
- **Rate Limiting & Admission** — rejection rates, admission queue health
- **Network & Protocol** — retransmissions and transfer rate by transport
- **HTTP Artifact Delivery** — bearer/native request and byte rates, native
  requests by profile, and native failure ratio
- **Version & Integrity** — version groups over time, quarantine status
- **Extensions** — failure rate by fixed contract and operation

`HTTP` denotes the bearer-token `/api/v1/artifacts/{name}` route.
`HTTP_NATIVE` denotes the source-IP-session `/boot/v1/{configured-name}` route.
These are fixed labels; machine IP, MAC, token, and URI are deliberately not
Prometheus labels.
