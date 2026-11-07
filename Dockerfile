# syntax=docker/dockerfile:1.7
#
# ---------------------------------------------------------------------------
# Pigeon Mail — container image
#
# CONTRACT NOTE (why this build does not work today):
# the image builds the single `pigeon` binary from a Cargo workspace that
# declares a binary crate named `pigeon` with the subcommands `serve` and `mcp`
# (`cargo build --release -p pigeon`). That crate is landing in a parallel PR;
# the workspace checked out on this branch only contains library crates, so the
# cargo step below fails until it lands. That is expected — this file is written
# against the contract in docs/ARCHITECTURE.md, not against the current tree.
#
# Targets:
#   pigeon            (default, last stage)  binary only — node is NEVER pulled
#   pigeon-webmail                           binary + the optional webmail bundle
#
#   docker build -t pigeon-mail .                          # API + SMTP, no webmail
#   docker build -t pigeon-mail --target pigeon-webmail .  # + webmail bundle
#   WITH_WEBMAIL=1 docker compose build                    # same, via compose
# ---------------------------------------------------------------------------

# 1.99: the workspace Cargo.lock requires rustc >= 1.91-era crates; 1.85 fails
# the build (dependency MSRV). CI uses `stable`, which currently satisfies it.
ARG RUST_VERSION=1.99
# 0 = binary only. Only the `pigeon-webmail` target consumes this value, and
# that target is not in the default target's dependency graph, so the node
# image is never downloaded for a plain `docker build .`.
ARG WITH_WEBMAIL=0

# ---------- build ----------
FROM rust:${RUST_VERSION}-slim AS builder

WORKDIR /build

# Dependency layer: manifests first so the cargo registry cache survives source
# edits. Cargo.lock is committed, so the glob always matches; it is written as a
# glob only so a fork without a lockfile still gets a clear cargo error instead
# of a Docker COPY error.
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates

# `--locked` is used whenever a lockfile is present so the image matches the
# committed dependency graph exactly.
RUN set -eux; \
    if [ -f Cargo.lock ]; then \
        cargo build --release --locked -p pigeon; \
    else \
        cargo build --release -p pigeon; \
    fi

# Staging directories for the runtime stage: distroless ships no shell, so there
# is no `mkdir`/`useradd` there. Directories are created here and copied in with
# `--chown` below, which is how the non-root uid gets a writable data dir.
RUN install -d -m 0750 -o 10001 -g 10001 /stage/data /stage/etc

# ---------- optional webmail bundle ----------
# Not in the default target's dependency graph => skipped entirely when
# WITH_WEBMAIL is unset. Requires a `web/` workspace member (parallel PR): the
# COPY fails while that member is absent.
FROM node:22-slim AS webmail

ARG WITH_WEBMAIL
WORKDIR /src/web
COPY web/ ./

RUN set -eux; \
    if [ "${WITH_WEBMAIL}" != "1" ]; then \
        echo "error: the pigeon-webmail target requires --build-arg WITH_WEBMAIL=1" >&2; \
        exit 1; \
    fi; \
    npm ci --no-audit --no-fund; \
    npm run build

# ---------- runtime (shared) ----------
# distroless/cc-debian12: glibc + libssl + a CA bundle (needed for outbound
# STARTTLS and HTTPS to webhook receivers) and no shell, package manager or
# curl for an attacker to reuse. There is no /etc/passwd entry for uid 10001,
# which is fine for a single static binary; numeric USER is the contract and
# matches `runAsUser: 10001` in the Kubernetes manifests.
FROM gcr.io/distroless/cc-debian12 AS base

COPY --from=builder /build/target/release/pigeon /usr/local/bin/pigeon
COPY --from=builder --chown=10001:10001 /stage/data /var/lib/pigeon
COPY --from=builder --chown=10001:10001 /stage/etc /etc/pigeon

# Defaults mirror docs/ARCHITECTURE.md "Configuration (principal env vars)".
# Everything is overridable from the environment: config is 12-factor, there is
# no config file.
ENV PIGEON_MASTER_KEY_FILE=/etc/pigeon/master.key \
    PIGEON_DB_PATH=/var/lib/pigeon/pigeon.db \
    PIGEON_HTTP_ADDR=:8000 \
    PIGEON_SMTP_IN_ADDR=:25

# 8000 API/MCP-HTTP, 25 inbound SMTP, 587 submission.
EXPOSE 8000 25 587

VOLUME ["/var/lib/pigeon"]

USER 10001:10001

# `serve` runs every service (api, mcp, web, smtp-in, smtp-out) in one process —
# the documented default. `mcp` is the stdio MCP server, usable with
# `docker run -i --rm ... pigeon mcp`.
ENTRYPOINT ["/usr/local/bin/pigeon"]
CMD ["serve"]

# WHY THERE IS NO HEALTHCHECK:
# the runtime image is distroless — no shell, no curl, no wget — so a
# `HEALTHCHECK` would need a probe binary baked into the image for no benefit.
# Probes are the contract instead: Kubernetes uses HTTP GET /healthz (liveness)
# and /readyz (readiness) on :8000. A compose `healthcheck:` is intentionally
# absent until the binary ships a built-in probe command (its name is for the
# binary PR to define); until then `docker compose ps` reports the container as
# running, not ready.

# ---------- webmail variant ----------
FROM base AS pigeon-webmail

# NOTE: /usr/local/share/pigeon/web is the placeholder install path shared with
# install.sh; confirm it against the `web` and `api` crates when they land.
COPY --from=webmail /src/web/dist /usr/local/share/pigeon/web
ENV PIGEON_WEBMAIL=on

# ---------- default: binary only ----------
# Must stay LAST: the last stage is what `docker build .` produces, and it must
# not depend on the node stage above.
FROM base AS pigeon
