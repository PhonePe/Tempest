<!-- SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Upgrading Tempest

`0.1.0` is the first public release, so there are no version-specific upgrade
notes yet. Each later release that changes configuration, HTTP, extension-trait,
persistence, or wire behavior adds a section here, newest first.

## Migrating from a Conventional TFTP Server

Tempest does not serve arbitrary files beneath `server.root` over TFTP. Before
moving boot traffic to Tempest:

1. Inventory the logical names that DHCP advertises and that boot scripts
   fetch over TFTP.
2. Publish the files that clients without a boot session need as the
   `default` boot profile release with `POST /api/v1/versions/switch`. Include
   only files that are safe for any reachable TFTP client.
3. Publish each session-specific boot profile with every logical name it needs,
   including shared bootloaders. Missing members never fall back to the
   `default` release or to raw root files; they return TFTP ERROR 1.
4. Without SQL persistence, publish release state again after every restart
   before admitting boot traffic.

## Rolling upgrade procedure

Back up the Tempest database, audit JSONL segments, and artifact manifests, and
test restoration before starting a new binary. Schema changes are applied in
place and no automated downgrade migration is supplied; a stateful rollback must
restore the matching backup. Drain each node before replacing it, run the new
binary against a staging copy of persistent state, verify `/ready`, and upgrade
nodes one at a time.
