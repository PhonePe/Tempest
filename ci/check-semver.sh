#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
# SPDX-License-Identifier: Apache-2.0

# Compares PACKAGE's public API against its previous release tag.
set -euo pipefail

package="${1:?usage: check-semver.sh PACKAGE TAG_PATTERN [CURRENT_TAG]}"
tag_pattern="${2:?usage: check-semver.sh PACKAGE TAG_PATTERN [CURRENT_TAG]}"
current_tag="${3:-}"

baseline=$(git tag --list "${tag_pattern}" --sort=-v:refname \
  | grep -Fvx "${current_tag}" \
  | head -n 1 || true)
if [[ -z "${baseline}" ]]; then
  echo "No earlier ${package} release tag exists; semver comparison starts after the first release."
  exit 0
fi

# Installed only when there is a release to compare against, and only when the
# pinned version is missing: `cargo install` contacts the crates.io index even
# for an installed tool. Keep in sync with .github/workflows/semver.yml, which
# installs the same version before calling this script.
version="0.51.0"
if ! cargo semver-checks --version 2>/dev/null | grep -Fqx "cargo-semver-checks ${version}"; then
  cargo install cargo-semver-checks --locked --version "${version}"
fi
cargo semver-checks check-release -p "${package}" --baseline-rev "${baseline}"
