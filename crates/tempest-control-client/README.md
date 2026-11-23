<!-- SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# tempest-control-client

Typed, timeout-bounded Rust client for Tempest's control plane.

It supports:

- listing active versions and version-group manifests, including exact active
  identities in a coherent integrity-controller snapshot;
- requesting capability-confined verification of retained release artifacts;
- previewing dependency-aware deletion and confirming exact-identity retained
  metadata removal when persistence is disabled (never artifact bytes);
- deploying, rolling back, and withdrawing releases; and
- registering or advancing source-IP boot sessions.

The client accepts HTTP or HTTPS base URLs, disables redirects, propagates an
optional `x-api-key`, bounds successful JSON responses to 16 MiB, and bounds
error messages to 4 KiB. Mutating request shapes and serialized bodies are also
bounded before transport. TLS termination, API-key custody, and authorization
policy remain deployment responsibilities.

```rust,no_run
use tempest_control_client::ControlClient;

# fn client() -> Result<(), Box<dyn std::error::Error>> {
let api_key = std::env::var("TEMPEST_API_KEY")?;
let client = ControlClient::new("https://tempest.example", Some(api_key))?;
# let _ = client;
# Ok(())
# }
```

This crate is in its `0.1.x` pre-1.0 series, targets Tempest `/api/v1` with digest-bound mutations on `/api/v2`, and
requires Rust 1.85 or newer.

This crate is maintained in the Tempest workspace and versioned independently;
it is not published to crates.io. Core does not depend on it. From the repository root, run
`cargo test --locked -p tempest-control-client` for local HTTP fixture tests and
`make test-live` to exercise the client against the server from the same checkout.

`preview_delete` and `confirm_delete` use `/api/v2/delete/preview` and
`/api/v2/delete/confirm`. Preserve the displayed `expected_identity`; do not
automatically confirm a replacement identity after a conflict. SQL metadata
requires the server's coordinated single-serving-node profile; other SQL modes
and all byte deletion return explicit blockers. Callers must also protect their own
drafts, journal and dependencies. See the [full contract](../../docs/guides/deletion.md).
Send canonical relative logical names (no repeated/trailing separators or dot
components); Unicode names remain supported. A serving server that loses its SQL
namespace lease refuses subsequent release/session mutations, including requests
queued before the loss. Treat that failure as unavailable state, not permission
to retry against a replacement identity.
