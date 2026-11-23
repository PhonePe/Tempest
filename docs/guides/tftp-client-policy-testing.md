<!-- SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Isolated TFTP client-policy comparison

[Standalone runner](../../scripts/tftp-client-policy.py) compares two **local,
trusted Linux executables**, not two running services. It needs Python 3.10 or
newer, `unshare` from util-linux, and `ip` from iproute2. There are no Python
packages, TOML-parser dependencies, target-host arguments, or target-port arguments.

## Safety and prerequisites

- Run on a disposable Linux test machine as an **unprivileged user**, not through
  `sudo`. The user should own the binary bundle and output parent. Root invocation
  is rejected: log in as the bundle owner and invoke Python normally. Do not make
  private bundles world-readable to work around namespace permissions.
- Unprivileged user and network namespaces must be permitted by the kernel and
  local security policy. Restricted containers or AppArmor policy may prohibit
  this. Use a suitable test VM instead of disabling isolation or falling back to
  the host network. The hard file-descriptor limit must be at least 1044; 2048 is
  recommended.
- The supervisor re-executes the script through
  `unshare --user --map-root-user --net`. Before starting any binary or opening
  network connections, the worker compares its network and user namespace
  identities against inherited descriptors for the actual original namespaces,
  checks the non-root UID mapping, and requires that **only loopback exists**.
  Only then does it run `ip link set lo up`.
- All traffic uses private-namespace loopback. There is no veth, external route,
  production API, service-manager invocation, production configuration, or live
  saturation step. Inherited proxies, credentials, and application environment
  settings are not passed to the binaries. The API client explicitly ignores
  proxy environment settings.
- Network namespaces are not a sandbox for malicious executables: the filesystem
  is still accessible as the invoking user. Use trusted binaries. The supervisor
  owns a dedicated process group containing the worker and its children and kills
  that group on completion, interruption, or failed startup; it never kills by
  process name. As with any supervisor, forcibly killing the supervisor itself
  with SIGKILL prevents its cleanup handler from running.

## Run on Ubuntu 22.04

Copy the runner and the two compatible Linux binaries into a private directory on
the test machine. Cross-compilation and transport are separate from this harness.
Keep both binaries unchanged during the run; SHA-256 is recorded and checked again
after each binary's suite. From the bundle directory, run:

```sh
python3 tftp-client-policy.py \
  --before-binary ./tempest-before \
  --after-binary ./tempest-after \
  --output ./policy-results
```

Or, with a repository checkout on the remote machine:

```sh
python3 scripts/tftp-client-policy.py \
  --before-binary ./tempest-before \
  --after-binary ./tempest-after \
  --output ./policy-results
```

The output directory must not exist; its parent must exist and be writable. It is
created privately. A normal run should finish well under 90 seconds. The worker
has an 80-second wall alarm; the outer supervisor enforces an 88-second deadline
plus bounded process reaping. Commands/readiness have three-second limits,
socket/API operations have subsecond limits, and process shutdown escalates after
0.5 seconds. Logs are capped at 1 MiB per subprocess output file. CPU, descriptor,
fixture, packet-loop, and request counts are bounded. At most four concurrent
transfers exist in the quota scenario (three possible baseline holders and one
healthy download); there is no request flood.

## Synthetic setup and compatibility

Each of the six scenarios starts a **fresh process**, for both binaries. It creates
three small deterministic artifacts and publishes one `default` managed release
through the isolated `/api/v1/versions/switch` API. A successful managed byte-for-byte
download and slot cleanup are setup prerequisites. No raw-root fallback is used.
Audit and SQL persistence are disabled; Versions API and metrics are explicitly
enabled. Boot-phase overrides are empty. The server uses one listener shard and
two Tokio worker threads.

Every generated configuration passes `--check-config` before startup. A baseline
may lack **only** `server.max_tftp_transfers_per_ip` and
`server.max_client_timeout_secs`. The script removes a field only after the
checker explicitly reports that exact unknown field, retries validation, and
records each omission. It never omits the existing absolute-lifetime setting,
silently retries unrelated incompatibilities, or removes fields from the candidate.
Both binaries must support the existing effective-config diagnostic and managed
release APIs. Configuration, execution-format, startup, API, fixture, and unexpected
server-exit failures are `ERROR`, not evidence that a baseline lacks protection.

The complete diagnostic `--print-effective-config` output is archived per scenario.
Only simple integer/boolean `[server]` scalars are extracted and checked against the
explicit synthetic settings; this is deliberately **not** a general TOML parser.
Python 3.10 does not need `tomllib`. The input configuration and JSON report also
record the exact configured values and omissions.

## Wire scenarios

All scenarios set global capacity to **4**, per-IP capacity to **2** (where
supported), `accept_client_timeout = true`, 512-byte blocks, window size 1, and
five retries. All timing is **real monotonic elapsed time**, not virtual time.

| Scenario | Synthetic settings | Required observation |
| --- | --- | --- |
| Timeout at ceiling | Ceiling 5; lifetime 15 s | Request `timeout=5`; OACK contains **exactly** 5 and correct `tsize`; effective block size is 512; managed bytes download and slot releases. |
| Timeout above ceiling | Ceiling 5; lifetime 15 s | Request `timeout=255`; OACK **omits timeout**, retains correct `tsize` and effective 512-byte blocks; no clamped counteroffer; managed bytes still download. |
| Per-IP quota and cancellation | Ceiling 255; lifetime 15 s | Two `127.0.0.2` sockets hold OACK with accepted timeout 255. A third distinct source port receives listener ERROR 0 with exact text `Client transfer limit reached`. A `127.0.0.3` client downloads exact managed bytes while holders remain. Client ERROR cancellation releases a slot; the **same endpoint** downloads the next logical artifact while the second holder remains. All slots then release. |
| Silent OACK | Ceiling 255; lifetime 3 s | Accepted timeout 255 does not postpone absolute expiry while ACK(0) is withheld. |
| Silent DATA | Ceiling 255; lifetime 3 s | After ACK(0)/DATA(1), accepted timeout 255 does not postpone absolute expiry while DATA ACK is withheld. |
| Progressing ACK | Ceiling 255; lifetime 4 s | ACKs approximately every 0.7 s produce at least four verified forward DATA advances, but do not renew the original absolute deadline. |

The requested `blksize=512` may be omitted from OACK: the unnegotiated RFC 1350
default is also 512. The runner accepts either omission or an exact 512 reply,
rejects any different block size, and records the original options unchanged.

Lifetime cases check the terminal ERROR 0 on the original transfer IP/port within
the configured lifetime minus 0.15 s through plus 0.8 s, active-slot release
**without client cancellation**, and same-endpoint next-artifact recovery. Early
timeout-255 retransmission is not accepted as expiry. If expiry fails, explicit
client cancellation is used only for cleanup; JSON labels subsequent recovery
accordingly, never as successful expiry. Deadline ERROR is best-effort in core;
this loopback test requires observing it, so packet loss or severe scheduling
pressure can fail the experiment and must be investigated rather than ignored.

On a baseline without per-IP policy, the third socket may get OACK instead of
ERROR. That mismatch is retained as a failed check; the healthy fourth transfer
is still tested, then the unexpected third holder is explicitly cancelled.
Existing absolute-lifetime or exact-timeout protections may already pass on the
baseline. A baseline with all protections passing is valid too: the runner does
not require artificial red results.

## Results and interpretation

The console prints one status per binary/scenario and the report location. The
output directory contains a JSON report, launcher log, and per-scenario synthetic
configurations, effective configurations, config-check logs, server logs, and
fixtures. JSON includes binary and fixture SHA-256, namespace evidence, exact
settings/omissions, individual checks (including failed checks), observed packets,
progress timestamps, and real elapsed durations. Local synthetic filesystem paths
are present in generated evidence; review them before sharing the bundle.

- **Exit 0:** all six baseline scenarios executed without setup/runtime errors,
  and all six candidate scenarios passed every check. Baseline policy `FAIL` is
  allowed and reported, not swallowed; baseline `ERROR` invalidates comparison.
- **Exit 1:** a candidate check failed, a scenario errored, isolation failed, or
  the comparison otherwise did not complete successfully. Inspect JSON and logs.
- **Exit 2:** command-line, platform, prerequisite, or supervisor failure. There
  may be no complete report; an interrupted partial report is not a passing run.

This tests the configured policies, **not** the default 16-per-IP/255-timeout/300-s
lifetime profile. In particular, short lifetime evidence is not a 300-second soak.
It does not qualify WRQ, IPv6/mapped addresses, multiple shards, NAT fairness,
spoofed/distributed clients, sustained new admissions, physical firmware, production
performance, SQL durability, or custom provider compositions. A finite failed
expiry observation does not prove unlimited retention.

## Offline validation

From the repository root:

```sh
python3 -B -m unittest discover -s scripts -p test_tftp_client_policy.py -v
python3 -B scripts/tftp-client-policy.py --help
python3 -B -c 'from pathlib import Path; [compile(p.read_text(), str(p), "exec") for p in (Path("scripts/tftp-client-policy.py"), Path("scripts/test_tftp_client_policy.py"))]'
```

The unit tests mock namespace/process/network boundaries and test packet parsing,
configuration compatibility, result gating, and cleanup. They start no Tempest
server and provide no live UDP policy evidence. A macOS help/compile/unit pass is
not a substitute for the isolated Linux before/after run above.