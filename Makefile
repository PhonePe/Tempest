# SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
# SPDX-License-Identifier: Apache-2.0

BIN      := tempest
CARGO    ?= cargo
VERSION  := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)

# ── Release builds ───────────────────────────────────────────────────────────
# Release archives come only from the rc-linux-* targets: digest-pinned Linux
# builders, the committed lockfile, every production feature, and the compiler
# pinned in rust-toolchain.toml. RC_TAG names a release candidate; set it empty
# (RC_TAG=) on a release tag for tempest-X.Y.Z-<platform> archive names.
# RC_SKIP_CHECK=1 skips the repository gate when the caller already ran it.
CONTAINER_ENGINE ?= podman
RC_RUST_VERSION  ?= 1.100.0
RC_TAG           ?= rc1
RC_SKIP_CHECK    ?=
# Static musl builds run natively for each architecture on the multi-arch Alpine
# image (amd64 emulates on Apple silicon).
RC_BUILDER_IMAGE ?= docker.io/library/rust:1.100.0-alpine3.24@sha256:8d0e82abfdf9a38071e07cabc5afba4ddbe077631a80e4e742a760c38beadc33
# The Bullseye base image supplies glibc 2.31 and its C toolchain, which set the
# glibc release binary's compatibility floor. Rust publishes no newer Bullseye
# images, so the pinned compiler is installed into it with rustup, which checks
# each component against the SHA-256 in the HTTPS-fetched release manifest.
RC_GNU_BUILDER_IMAGE ?= docker.io/library/rust:1.91.1-bullseye@sha256:ed6afcf912afc6aeddf0d1ff0dc6894c9b1c8f865964ef3f533e3ea77a64ffea

DIST_DIR      := dist
RC_SUFFIX     = $(if $(RC_TAG),-$(RC_TAG))
RC_DIST_NAME  = $(BIN)-$(VERSION)$(RC_SUFFIX)-$(RC_NAME)
RC_BUILD_BIN  = target/rc-$(RC_NAME)/$(RC_TARGET)/release/$(BIN)
RC_LINKER_ENV = CARGO_TARGET_$(shell printf '%s' '$(RC_TARGET)' | tr 'a-z-' 'A-Z_')_LINKER
# Shipped beside the binary in every release archive.
RC_ARCHIVE_FILES := LICENSE README.md config/tempest.toml deploy/systemd/tempest.service

rc-linux-amd64: RC_NAME := linux-amd64
rc-linux-amd64: RC_PLATFORM := linux/amd64
rc-linux-amd64: RC_TARGET := x86_64-unknown-linux-musl
rc-linux-amd64: RC_ELF := x86-64
rc-linux-arm64: RC_NAME := linux-arm64
rc-linux-arm64: RC_PLATFORM := linux/arm64
rc-linux-arm64: RC_TARGET := aarch64-unknown-linux-musl
rc-linux-arm64: RC_ELF := ARM aarch64
rc-linux-amd64 rc-linux-arm64: RC_IMAGE = $(RC_BUILDER_IMAGE)
rc-linux-amd64 rc-linux-arm64: RC_LINKAGE := static
rc-linux-amd64 rc-linux-arm64: RC_RUSTFLAGS := -C target-feature=+crt-static --remap-path-prefix=/work=.
rc-linux-amd64-gnu: RC_NAME := linux-amd64-gnu
rc-linux-amd64-gnu: RC_PLATFORM := linux/amd64
rc-linux-amd64-gnu: RC_TARGET := x86_64-unknown-linux-gnu
rc-linux-amd64-gnu: RC_ELF := x86-64
rc-linux-amd64-gnu: RC_IMAGE = $(RC_GNU_BUILDER_IMAGE)
rc-linux-amd64-gnu: RC_LINKAGE := dynamically linked
rc-linux-amd64-gnu: RC_RUSTFLAGS := --remap-path-prefix=/work=.

.PHONY: all build rc-linux-amd64 rc-linux-arm64 rc-linux-amd64-gnu test test-v test-filter test-doc test-live bench bench-check doc-check clippy fmt fmt-check license-check license-format check clean install native help test-sql test-sql-all coverage-sql test-uso-kernel msrv openapi-check cross-check fuzz container-check test-salt

# ── Default: native host binary ──────────────────────────────────────────────
all: build

build:
	$(CARGO) build --release
	@echo ""
	@echo "  Binary : target/release/$(BIN)"
	@file target/release/$(BIN)

# ── Linux release archives ───────────────────────────────────────────────────
# The source tree is read-only in the builder. Cargo writes only to the
# dedicated target directory and uses a persistent registry cache.
rc-linux-amd64 rc-linux-arm64 rc-linux-amd64-gnu:
	@command -v $(CONTAINER_ENGINE) >/dev/null 2>&1 || { \
	  echo "error: $(CONTAINER_ENGINE) is not installed"; \
	  echo "set CONTAINER_ENGINE=docker to use Docker instead"; \
	  exit 1; \
	}
	@$(CONTAINER_ENGINE) info >/dev/null 2>&1 || { \
	  echo "error: $(CONTAINER_ENGINE) is not running"; \
	  echo "start its Linux VM/daemon and retry"; \
	  exit 1; \
	}
	@test -z "$(RC_TAG)" || printf '%s\n' "$(RC_TAG)" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]*$$' || { \
	  echo "error: RC_TAG must contain only letters, digits, dots, underscores, or hyphens"; \
	  exit 1; \
	}
	$(if $(RC_SKIP_CHECK),,$(MAKE) check)
	@mkdir -p target/rc-$(RC_NAME) $(DIST_DIR)
	$(CONTAINER_ENGINE) run --rm --platform $(RC_PLATFORM) \
	  --mount type=bind,src="$(CURDIR)",dst=/work,readonly \
	  --mount type=bind,src="$(CURDIR)/target/rc-$(RC_NAME)",dst=/out \
	  --mount type=volume,src=tempest-cargo-registry,dst=/usr/local/cargo/registry \
	  --workdir /work \
	  --env CARGO_TARGET_DIR=/out \
	  --env $(RC_LINKER_ENV)=cc \
	  --env RUSTUP_TOOLCHAIN=$(RC_RUST_VERSION)-$(RC_TARGET) \
	  --env RUSTFLAGS="$(RC_RUSTFLAGS)" \
	  $(RC_IMAGE) \
	  sh -ec 'rustup toolchain install --no-self-update --profile minimal "$$RUSTUP_TOOLCHAIN"; \
	    test "$$(rustc -vV | sed -n "s/^host: //p")" = "$(RC_TARGET)"; \
	    rustc --version; \
	    ldd --version 2>&1 | head -1 || true; \
	    cargo build --locked --release --all-features --target $(RC_TARGET); \
	    /out/$(RC_TARGET)/release/$(BIN) --version'
	@file $(RC_BUILD_BIN) | grep -Eq 'ELF 64-bit.*$(RC_ELF)' || { \
	  echo "error: $(RC_NAME) build is not a 64-bit $(RC_ELF) ELF binary"; \
	  file $(RC_BUILD_BIN); \
	  exit 1; \
	}
	@file $(RC_BUILD_BIN) | grep -Eq '$(RC_LINKAGE)' || { \
	  echo "error: $(RC_NAME) build is not $(RC_LINKAGE)"; \
	  file $(RC_BUILD_BIN); \
	  exit 1; \
	}
	rm -rf $(DIST_DIR)/$(RC_DIST_NAME)
	mkdir -p $(DIST_DIR)/$(RC_DIST_NAME)
	install -m 0755 $(RC_BUILD_BIN) $(DIST_DIR)/$(RC_DIST_NAME)/$(BIN)
	install -m 0644 $(RC_ARCHIVE_FILES) $(DIST_DIR)/$(RC_DIST_NAME)/
	cd $(DIST_DIR) && COPYFILE_DISABLE=1 tar -czf $(RC_DIST_NAME).tar.gz $(RC_DIST_NAME)
	cd $(DIST_DIR) && shasum -a 256 $(RC_DIST_NAME).tar.gz > $(RC_DIST_NAME).tar.gz.sha256
	@echo ""
	@echo "  $(RC_NAME) release archive:"
	@ls -lh $(DIST_DIR)/$(RC_DIST_NAME).tar.gz $(DIST_DIR)/$(RC_DIST_NAME).tar.gz.sha256
	@file $(DIST_DIR)/$(RC_DIST_NAME)/$(BIN)

# ── Tests ────────────────────────────────────────────────────────────────────
# Run all lib + integration tests (doc-tests run separately)
test:
	$(CARGO) test --locked --workspace --lib --tests

# Run all tests with captured output printed (useful when debugging failures)
test-v:
	$(CARGO) test --locked --workspace --lib --tests -- --nocapture

# Run tests whose name matches a filter:  make test-filter FILTER=audit
# Example filters: audit  compression  rate_limit  transfer  window
FILTER ?=
test-filter:
	@test -n "$(FILTER)" || (echo "Usage: make test-filter FILTER=<pattern>"; exit 1)
	$(CARGO) test --locked --workspace --lib --tests $(FILTER) -- --nocapture

# Run doc-tests only
test-doc:
	$(CARGO) test --locked --workspace --doc --all-features

bench:
	$(CARGO) bench --bench protocol_hotpaths -- --noplot --output-format bencher

bench-check:
	$(CARGO) bench --locked --bench protocol_hotpaths -- --noplot --output-format bencher > protocol-bench.txt
	cat protocol-bench.txt
	python3 scripts/check-benchmark-budgets.py benchmarks/protocol-budgets.json protocol-bench.txt

# Build the public API documentation with CI-equivalent warning handling
doc-check:
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --locked --workspace --no-deps --all-features

clippy:
	$(CARGO) clippy --locked --workspace --all-targets --all-features -- -D warnings

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

# Equivalent of license:check / license:format; rules live in tests/license_headers.rs.
license-check:
	$(CARGO) test --locked --test license_headers

license-format:
	TEMPEST_LICENSE_FORMAT=1 $(CARGO) test --locked --test license_headers

test-live:
	bash ci/run_live_contract.sh

check: fmt-check license-check clippy test test-doc doc-check test-live

# ── CI entry points (called by .github/workflows) ────────────────────────────
# Keep job logic here, not in workflow files.
MSRV_TOOLCHAIN     ?= 1.85.0
REDOCLY_VERSION    ?= 2.41.0
FUZZ_RUNS          ?= 200000
CROSS_TARGETS      ?= x86_64-unknown-linux-musl aarch64-unknown-linux-musl

# Every SQL-feature test against one disposable database. A missing URL fails
# instead of skipping, so a misconfigured job cannot pass vacuously.
test-sql:
	@test -n "$$TEMPEST_TEST_DATABASE_URL" || { \
	  echo "error: TEMPEST_TEST_DATABASE_URL must name a disposable test database"; \
	  exit 2; \
	}
	TEMPEST_REQUIRE_TEST_DATABASE=1 $(CARGO) test $(SQL_TEST_ARGS)

# Both supported databases from one build. Every SQL-feature test runs against
# PostgreSQL; only the database-backed test modules run again against MySQL,
# because the other tests do not touch the database. The unit test
# `persistence::tests::database_tests_stay_in_sql_test_modules` fails when a
# database-backed test is added outside SQL_TEST_MODULES.
SQL_TEST_ARGS    := --locked --workspace --all-features --lib --tests
SQL_TEST_MODULES := persistence:: sqlx_instrumentation:: api::sessions::tests::
define run_sql_tests
	@test -n "$$TEMPEST_TEST_POSTGRES_URL" && test -n "$$TEMPEST_TEST_MYSQL_URL" || { \
	  echo "error: TEMPEST_TEST_POSTGRES_URL and TEMPEST_TEST_MYSQL_URL must name disposable test databases"; \
	  exit 2; \
	}
	TEMPEST_REQUIRE_TEST_DATABASE=1 TEMPEST_TEST_DATABASE_URL="$$TEMPEST_TEST_POSTGRES_URL" \
	  $(1) $(SQL_TEST_ARGS)
	TEMPEST_REQUIRE_TEST_DATABASE=1 TEMPEST_TEST_DATABASE_URL="$$TEMPEST_TEST_MYSQL_URL" \
	  $(1) $(SQL_TEST_ARGS) -- $(SQL_TEST_MODULES)
endef

test-sql-all:
	$(call run_sql_tests,$(CARGO) test)

# test-sql-all under coverage instrumentation: one instrumented build, both
# database runs merged into one LCOV report with workspace-relative paths, for
# SonarQube. Requires cargo-llvm-cov and the llvm-tools component.
COVERAGE_DIR ?= target/coverage
# Measured at 90.75% lines in November 2026; raise it as coverage grows.
COVERAGE_MIN_LINES ?= 85
coverage-sql:
	$(CARGO) llvm-cov clean --workspace
	$(call run_sql_tests,$(CARGO) llvm-cov --no-report --remap-path-prefix)
	mkdir -p $(COVERAGE_DIR)
	$(CARGO) llvm-cov report --lcov --output-path $(COVERAGE_DIR)/lcov.info
	$(CARGO) llvm-cov report --summary-only | tee $(COVERAGE_DIR)/coverage-summary.txt
	$(CARGO) llvm-cov report --summary-only --fail-under-lines $(COVERAGE_MIN_LINES) > /dev/null

# Linux UDP_SEGMENT qualification: only the tests ignored by default because
# they need kernel support (Linux 4.18+) and IPv4/IPv6 loopback. Every test run
# already covers the module's other tests.
test-uso-kernel:
	@test "$$(uname -s)" = Linux || { echo "error: test-uso-kernel requires Linux"; exit 2; }
	$(CARGO) test --locked -p tempest-ignition --lib protocol::transfer::udp_gso \
	  -- --ignored

# Installs the MSRV toolchain only when it is missing: even for an installed
# toolchain, `rustup toolchain install` contacts the Rust distribution server.
msrv:
	@rustup toolchain list | grep -q '^$(MSRV_TOOLCHAIN)-' || \
	  rustup toolchain install $(MSRV_TOOLCHAIN) --profile minimal
	$(CARGO) +$(MSRV_TOOLCHAIN) check --locked --workspace --all-targets --no-default-features
	$(CARGO) +$(MSRV_TOOLCHAIN) check --locked --workspace --all-targets --all-features

# Requires Node.js (npx). Enforces the OpenAPI/crate version relationship.
openapi-check:
	@spec="$$(sed -n 's/^  version: //p' docs/openapi.yaml | head -n 1)"; \
	  test "$$spec" = "$(VERSION)" || { \
	    echo "error: OpenAPI info.version $$spec does not match crate $(VERSION)"; \
	    exit 1; \
	  }
	REDOCLY_SUPPRESS_UPDATE_NOTICE=true REDOCLY_TELEMETRY=off \
	  npx --yes @redocly/cli@$(REDOCLY_VERSION) lint --extends=spec docs/openapi.yaml

cross-check:
	rustup target add $(CROSS_TARGETS)
	@for target in $(CROSS_TARGETS); do \
	  $(CARGO) check --locked -p tempest-ignition --target $$target --no-default-features || exit 1; \
	done

# The toolchain file pins a stable release; fuzzing needs nightly explicitly.
fuzz:
	$(CARGO) +nightly fuzz run packet_parse -- -runs=$(FUZZ_RUNS) -timeout=5 -rss_limit_mb=2048
	$(CARGO) +nightly fuzz run option_negotiation -- -runs=$(FUZZ_RUNS) -timeout=5 -rss_limit_mb=2048

# Renders the Salt formula's templates; needs Python 3.11+ (tomllib), Jinja2 and
# PyYAML. Override the interpreter with PYTHON=python3.12, for example.
PYTHON ?= python3
test-salt:
	@$(PYTHON) -c 'import sys; sys.exit(sys.version_info < (3, 11))' || { \
	  echo "error: make test-salt needs Python 3.11+ (tomllib); $(PYTHON) is $$($(PYTHON) -V 2>&1)."; \
	  echo "set PYTHON to a newer interpreter, for example PYTHON=python3.12"; \
	  exit 2; \
	}
	cd salt && $(PYTHON) -m unittest discover -s tests -v

# Builds the production image without publishing it, then smoke-tests it.
container-check:
	$(CONTAINER_ENGINE) build --build-arg TEMPEST_VERSION=$(VERSION) \
	  --build-arg TEMPEST_REVISION=$$(git rev-parse HEAD) -t tempest:ci .
	$(CONTAINER_ENGINE) run --rm tempest:ci --version

# ── Native build (host arch, for quick local iteration) ──────────────────────
native: build

# ── Install to /usr/local/bin (native) ───────────────────────────────────────
install: native
	install -m 755 target/release/$(BIN) /usr/local/bin/$(BIN)
	@echo "  Installed: /usr/local/bin/$(BIN)"

# ── Cleanup ───────────────────────────────────────────────────────────────────
clean:
	$(CARGO) clean
	rm -rf $(DIST_DIR)

# ── Help ──────────────────────────────────────────────────────────────────────
help:
	@echo "Tempest $(VERSION) — build targets"
	@echo ""
	@echo "  make            Build a native release binary (default)"
	@echo "  make rc-linux-amd64      Validate + build the static Linux amd64 release archive"
	@echo "  make rc-linux-arm64      Validate + build the static Linux arm64 release archive"
	@echo "  make rc-linux-amd64-gnu  Validate + build the glibc 2.31+ Linux amd64 archive"
	@echo "                           (RC_TAG=rc1 names a candidate; RC_TAG= for a release)"
	@echo "  make native     Build for the host machine (arm64 Darwin here)"
	@echo "  make test                  Run all tests"
	@echo "  make test-v                Run all tests with stdout/stderr printed"
	@echo "  make test-filter FILTER=x  Run only tests matching pattern x"
	@echo "  make test-doc              Run doc-tests only"
	@echo "  make test-live             Run the client against the local server"
	@echo "  make bench                 Run protocol microbenchmarks"
	@echo "  make bench-check           Enforce gross-regression budgets"
	@echo "  make doc-check             Build all-features rustdoc with warnings denied"
	@echo "  make clippy     cargo clippy -D warnings"
	@echo "  make fmt        Format source"
	@echo "  make fmt-check  Check formatting without changing files"
	@echo "  make license-check   Fail on a missing or outdated license header"
	@echo "  make license-format  Add or repair license headers in place"
	@echo "  make check      format, lint, tests, doc-tests, and rustdoc"
	@echo "  make install    Build native + install to /usr/local/bin"
	@echo "  make clean      Remove build artifacts and dist/"
