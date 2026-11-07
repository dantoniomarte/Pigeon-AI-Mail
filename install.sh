#!/usr/bin/env bash
#
# Pigeon Mail — host installer for Linux + systemd.
#
# Fresh install on a VPS:
#   sudo ./install.sh --domain example.com
#
# --domain is the MAIL DOMAIN you serve (example.com), not the SMTP hostname:
# MX, SPF, DKIM and DMARC are all published on that domain.
#
# What it does, in order:
#   1. checks Linux + CPU arch (x86_64 -> amd64, aarch64 -> arm64)
#   2. creates the system user `pigeon` (no login shell, home = data dir)
#   3. creates <data-dir> (0750 pigeon:pigeon) and /etc/pigeon (0750 root:pigeon —
#      the group needs traverse access to reach master.key)
#   4. creates /etc/pigeon/master.key when missing (0640 root:pigeon)
#   5. installs the `pigeon` binary to /usr/local/bin (--bin or GitHub release)
#   6. best-effort setcap cap_net_bind_service=+ep for :25/:587
#   7. writes /etc/pigeon/pigeon.env and the pigeon.service unit
#   8. daemon-reload, then enable --now / restart when the unit is already active
#      (that restart is what makes a binary upgrade take effect)
#
# Everything it writes is idempotent: re-running upgrades the binary and keeps
# the existing master key and database untouched.
#
# No eval anywhere; every expansion is quoted.
#
# Agent configs: `--agent <platform>` copies the ready-made MCP configuration for
# that platform (from ./config/<platform>/) and prints where to place it. Used
# WITHOUT --domain it does only that — no root, no service, no files written
# outside the destination directory.

set -euo pipefail

readonly SCRIPT_NAME="${0##*/}"
# Directory this script lives in; empty when piped from curl (no checkout).
SCRIPT_DIR=""
if [[ -f "${BASH_SOURCE[0]:-}" ]]; then
    SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
fi

# Early validation (before any side effects): flags that reference paths
# must point at things that exist.
[[ -z "$WEBMAIL_LOCAL_DIR" || -d "$WEBMAIL_LOCAL_DIR" ]] || die "--webmail-dir not found: $WEBMAIL_LOCAL_DIR"

readonly KNOWN_AGENTS="pi claude cursor codex grok opencode gentle-shell hermes generic docker remote"
readonly SERVICE_USER="pigeon"
readonly INSTALL_BIN="/usr/local/bin/pigeon"
readonly CONFIG_DIR="/etc/pigeon"
readonly KEY_FILE="${CONFIG_DIR}/master.key"
readonly ENV_FILE="${CONFIG_DIR}/pigeon.env"
readonly UNIT_FILE="/etc/systemd/system/pigeon.service"
readonly RELEASE_BASE_URL="https://github.com/dantoniomarte/Pigeon-AI-Mail/releases/latest/download"

# NOTE: placeholder install path for the optional webmail bundle, shared with the
# Dockerfile. Confirm it against the `web`/`api` crates when they land.
readonly WEBMAIL_DIR="/usr/local/share/pigeon/web"

DOMAIN=""
API_PORT="8000"
DATA_DIR="/var/lib/pigeon"
LOCAL_BIN=""
WEBMAIL_LOCAL_DIR=""
WANT_WEBMAIL=1
START_SERVICE=1
AGENT_TARGETS=()
AGENT_DIR=""
AGENT_CONFIG_SRC="${PIGEON_CONFIG_SRC:-}"

info() { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# Temp artefacts are tracked so they are removed on every exit path, including
# the `die` calls inside the download helpers (a RETURN trap alone misses those).
TEMP_PATHS=()
register_temp() { TEMP_PATHS+=("$1"); }
cleanup_temp() {
    local path
    trap - RETURN
    for path in ${TEMP_PATHS[@]+"${TEMP_PATHS[@]}"}; do
        rm -rf -- "$path"
    done
    TEMP_PATHS=()
}
trap cleanup_temp EXIT

# ---------------------------------------------------------------------------
# Agent configuration helpers
# ---------------------------------------------------------------------------

# add_agents <value>: accept "claude", "pi,codex" or "all" (repeatable flag).
add_agents() {
    local raw="$1" item known
    local -a items=()
    [[ -n "$raw" ]] || die "--agent needs a value"
    # Split on commas only; the loop below keeps the default IFS so the "all"
    # expansion (a space-separated list) still works.
    IFS=',' read -r -a items <<<"$raw"
    for item in ${items[@]+"${items[@]}"}; do
        item="${item// /}"
        [[ -n "$item" ]] || continue
        if [[ "$item" == "all" ]]; then
            for known in $KNOWN_AGENTS; do
                AGENT_TARGETS+=("$known")
            done
            continue
        fi
        case " $KNOWN_AGENTS " in
            *" $item "*) AGENT_TARGETS+=("$item") ;;
            *) die "unknown --agent '${item}' (choose: ${KNOWN_AGENTS// /, }, or all)" ;;
        esac
    done
}

# agent_config_source: the config/ tree that ships with the checkout.
agent_config_source() {
    if [[ -n "$AGENT_CONFIG_SRC" ]]; then
        printf '%s\n' "$AGENT_CONFIG_SRC"
        return 0
    fi
    if [[ -n "$SCRIPT_DIR" && -d "${SCRIPT_DIR}/config" ]]; then
        printf '%s\n' "${SCRIPT_DIR}/config"
        return 0
    fi
    return 1
}

# agent_place_hint <platform>: where the copied file belongs.
agent_place_hint() {
    case "$1" in
        pi) printf '~/.pi/agent/mcp.json (user) or <project>/.pi/mcp.json\n' ;;
        claude) printf 'claude_desktop_config.json -> the Claude config dir (macOS: ~/Library/Application Support/Claude)\n' ;;
        cursor) printf 'mcp.json -> ~/.cursor/mcp.json (global) or <project>/.cursor/mcp.json\n' ;;
        codex) printf 'config.toml -> ~/.codex/config.toml (merge the [mcp_servers.pigeon-mail] tables)\n' ;;
        grok) printf 'mcp.json -> ~/.grok/mcp.json (or the mcpServers block of user-settings.json)\n' ;;
        opencode) printf 'mcp.json -> ~/.config/opencode/opencode.json (merge the "mcp" object)\n' ;;
        gentle-shell) printf 'settings.json -> ~/.gentle-shell/config.json (merge the "mcpServers" object)\n' ;;
        hermes) printf 'mcp.yaml -> ~/.hermes/mcp.yaml (or the Hermes config directory)\n' ;;
        generic) printf "any client's mcpServers map (command: pigeon mcp)\n" ;;
        docker) printf "any client's mcpServers map (docker exec -i <container> pigeon mcp)\n" ;;
        remote) printf 'nothing to place: export PIGEON_URL and PIGEON_API_KEY for the agent\n' ;;
        *) printf '(see SETUP.md)\n' ;;
    esac
}

# agent_test_hint <platform>: the shortest proof that the connection works.
agent_test_hint() {
    case "$1" in
        remote)
            printf 'curl -sS "$PIGEON_URL/readyz"   # then GET /v1/messages with the key\n'
            ;;
        docker)
            printf 'docker exec -i <container> /usr/local/bin/pigeon mcp  <<< initialize/tools-list\n'
            ;;
        *)
            printf "pigeon mcp with an initialize + tools/list request on stdin  # expect 25 tools\n"
            ;;
    esac
}

# export_agent_configs <dest-root>: copy every selected platform folder and print
# the placement + test for each. Idempotent: re-running overwrites the copies.
# Nothing secret is copied — the configs only carry paths, and an API key is
# never written by this installer.
export_agent_configs() {
    local dest_root="$1" src platform file seen count=0
    local -a selected=()

    src="$(agent_config_source)" || die "agent configs not found — run this from a checkout, or set PIGEON_CONFIG_SRC=/path/to/repo/config"
    [[ -d "$src" ]] || die "agent config directory not found: ${src}"

    # De-duplicate while keeping the order the operator asked for.
    for platform in ${AGENT_TARGETS[@]+"${AGENT_TARGETS[@]}"}; do
        for seen in ${selected[@]+"${selected[@]}"}; do
            [[ "$seen" == "$platform" ]] && continue 2
        done
        selected+=("$platform")
    done

    for platform in ${selected[@]+"${selected[@]}"}; do
        [[ -d "${src}/${platform}" ]] || die "no config for '${platform}' under ${src}"
    done

    install -d -m 0755 -- "$dest_root"
    for platform in ${selected[@]+"${selected[@]}"}; do
        install -d -m 0755 -- "${dest_root}/${platform}"
        for file in "${src}/${platform}"/*; do
            [[ -f "$file" ]] || continue
            install -m 0644 -- "$file" "${dest_root}/${platform}/$(basename -- "$file")"
        done
        count=$((count + 1))
    done

    printf '\nAgent configuration exported to %s\n\n' "$dest_root"
    for platform in ${selected[@]+"${selected[@]}"}; do
        printf '  [%s]  %s/\n' "$platform" "${dest_root}/${platform}"
        printf '      place : %s\n' "$(agent_place_hint "$platform")"
        printf '      test  : %s\n' "$(agent_test_hint "$platform")"
        printf '      setup : %s/%s/SETUP.md   (guide: docs/AGENTS.md)\n\n' \
            "$dest_root" "$platform"
    done
    printf '  %d platform(s) exported. Full guide: docs/AGENTS.md\n' "$count"
    printf '  These files contain no secrets (paths and URLs only).\n\n'
}

usage() {
    cat <<'USAGE'
Pigeon Mail installer (Linux + systemd).

Usage: install.sh --domain <domain> [options]
       install.sh --agent <platform> [--agent <platform>...] [--agent-dir <path>]

Required (server install):
  --domain <domain>   Mail domain this instance serves (e.g. example.com).
                      MX, SPF, DKIM and DMARC are published ON this domain; the
                      host that answers :25 is mail.<domain> in the printed
                      records. Change the host name if it differs.

Server options:
  --port <port>       API/MCP HTTP port (default: 8000)
  --data-dir <path>   Database directory (default: /var/lib/pigeon)
  --bin <path>        Install this local `pigeon` binary instead of downloading
  --no-webmail        Do not install the optional webmail bundle
  --webmail-dir <p>   Install the webmail from this local directory
                      (private repos, air-gapped hosts)
  --no-start          Write everything but do not enable/start the service

Agent options:
  --agent <platform>  Copy the ready-made agent configuration and print where to
                      place it. Repeatable or comma-separated. Platforms:
                        pi, claude, cursor, codex, grok, opencode, gentle-shell,
                        hermes, generic, docker, remote, all
                      Given WITHOUT --domain this only exports configs and exits
                      (no root needed, nothing else is touched).
  --agent-dir <path>  Destination root for --agent.
                      Default: ./pigeon-agent-config in config-only mode,
                      /etc/pigeon/agents with --domain.

  -h, --help          Show this help

Examples:
  sudo ./install.sh --domain example.com
  sudo ./install.sh --domain example.com --bin ./target/release/pigeon --no-start
  sudo ./install.sh --domain example.com --agent all
  ./install.sh --agent claude
  ./install.sh --agent pi,codex --agent-dir ~/.config/pigeon-agents
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain)
            [[ $# -ge 2 ]] || die "--domain needs a value"
            DOMAIN="$2"
            shift 2
            ;;
        --port)
            [[ $# -ge 2 ]] || die "--port needs a value"
            API_PORT="$2"
            shift 2
            ;;
        --data-dir)
            [[ $# -ge 2 ]] || die "--data-dir needs a value"
            DATA_DIR="$2"
            shift 2
            ;;
        --bin)
            [[ $# -ge 2 ]] || die "--bin needs a value"
            LOCAL_BIN="$2"
            shift 2
            ;;
        --webmail-dir)
            [[ $# -ge 2 ]] || die "--webmail-dir needs a value"
            [[ -n "$2" ]] || die "--webmail-dir needs a non-empty path"
            [[ "$WANT_WEBMAIL" -eq 1 ]] || die "--webmail-dir conflicts with --no-webmail"
            WEBMAIL_LOCAL_DIR="$2"
            shift 2
            ;;
        --no-webmail)
            [[ -z "$WEBMAIL_LOCAL_DIR" ]] || die "--no-webmail conflicts with --webmail-dir"
            WANT_WEBMAIL=0
            shift
            ;;
        --no-start)
            START_SERVICE=0
            shift
            ;;
        --agent)
            [[ $# -ge 2 ]] || die "--agent needs a value"
            add_agents "$2"
            shift 2
            ;;
        --agent-dir)
            [[ $# -ge 2 ]] || die "--agent-dir needs a value"
            AGENT_DIR="$2"
            shift 2
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            die "unknown argument: $1"
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------

[[ -n "$DOMAIN" || ${#AGENT_TARGETS[@]} -gt 0 ]] || {
    usage >&2
    die "--domain is required (or --agent to export an agent configuration)"
}

# ---------------------------------------------------------------------------
# Config-only mode: --agent without --domain writes nothing but the copies.
# ---------------------------------------------------------------------------

if [[ -z "$DOMAIN" ]]; then
    if [[ -z "$AGENT_DIR" ]]; then
        AGENT_DIR="${PWD}/pigeon-agent-config"
    fi
    info "config-only mode (--agent without --domain): no service, no root needed"
    export_agent_configs "$AGENT_DIR"
    exit 0
fi

[[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]] || die "invalid --domain: ${DOMAIN}"
[[ "$API_PORT" =~ ^[0-9]+$ ]] || die "invalid --port: ${API_PORT}"
# 10# forces base 10 so a leading zero ("08000") is not read as octal.
API_PORT=$((10#$API_PORT))
((API_PORT >= 1 && API_PORT <= 65535)) || die "--port out of range: ${API_PORT}"
[[ "$DATA_DIR" = /* ]] || die "--data-dir must be an absolute path: ${DATA_DIR}"
# Normalise trailing slashes before the path checks below (keep "/" as is).
while [[ "$DATA_DIR" != "/" && "$DATA_DIR" == */ ]]; do
    DATA_DIR="${DATA_DIR%/}"
done
# The systemd unit sets ProtectHome=true / ProtectSystem=strict, so these trees
# are invisible or read-only to the service; "/" would scatter the database over
# the system root. Refuse them instead of writing a unit that cannot work.
case "$DATA_DIR" in
    /) die "--data-dir cannot be the filesystem root" ;;
    /home | /home/*)
        die "--data-dir cannot live under /home (ProtectHome=true hides it from the service): ${DATA_DIR}"
        ;;
    /root | /root/*)
        die "--data-dir cannot live under /root (ProtectHome=true hides it from the service): ${DATA_DIR}"
        ;;
    /run/user | /run/user/*)
        die "--data-dir cannot live under /run/user (it is per-session tmpfs, not durable): ${DATA_DIR}"
        ;;
esac

[[ "$(uname -s)" == "Linux" ]] || die "this installer targets Linux only"
[[ "${EUID}" -eq 0 ]] || die "run as root (sudo ./${SCRIPT_NAME} --domain ${DOMAIN})"

case "$(uname -m)" in
    x86_64 | amd64) ARCH="amd64" ;;
    aarch64 | arm64) ARCH="arm64" ;;
    *) die "unsupported architecture: $(uname -m) (expected x86_64 or aarch64)" ;;
esac

for cmd in openssl install useradd groupadd getent tar curl systemctl; do
    command -v "$cmd" >/dev/null 2>&1 || die "missing required command: ${cmd}"
done

# ---------------------------------------------------------------------------
# User and directories
# ---------------------------------------------------------------------------

# Group first: the config dir and the master key are group-owned by it.
if getent group "$SERVICE_USER" >/dev/null 2>&1; then
    info "system group '${SERVICE_USER}' already exists"
else
    info "creating system group '${SERVICE_USER}'"
    groupadd --system "$SERVICE_USER"
fi

if getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
    info "system user '${SERVICE_USER}' already exists"
else
    info "creating system user '${SERVICE_USER}'"
    useradd --system \
        --home-dir "$DATA_DIR" \
        --shell /usr/sbin/nologin \
        --gid "$SERVICE_USER" \
        --comment "Pigeon Mail service account" \
        "$SERVICE_USER"
fi

install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$DATA_DIR"
# Config dir is root-owned, group-readable/traversable by the service account
# only. 0700 would keep the group out and the service could not reach
# master.key even with the file at 0640 — 0750 is the narrowest mode that works.
install -d -m 0750 -o root -g "$SERVICE_USER" "$CONFIG_DIR"

# ---------------------------------------------------------------------------
# Master key (never regenerated: rotating it makes stored mail unreadable)
# ---------------------------------------------------------------------------

if [[ -f "$KEY_FILE" ]]; then
    info "master key exists, keeping it: ${KEY_FILE}"
    chown root:"$SERVICE_USER" "$KEY_FILE"
    chmod 0640 "$KEY_FILE"
else
    info "generating master key: ${KEY_FILE}"
    umask 077
    openssl rand -hex 32 >"$KEY_FILE"
    # 64 hex chars = 32 raw bytes. Readable by the service group, never world.
    chown root:"$SERVICE_USER" "$KEY_FILE"
    chmod 0640 "$KEY_FILE"
    warn "back up ${KEY_FILE} now, together with the database. Losing the key means losing all stored mail."
fi

# ---------------------------------------------------------------------------
# Binary
# ---------------------------------------------------------------------------

extract_pigeon_binary() {
    # $1 = extract dir, $2 = archive url
    [[ -f "${1}/pigeon" ]] || die "archive does not contain a 'pigeon' binary: ${2}"
    install -m 0755 "${1}/pigeon" "$INSTALL_BIN"
}

install_from_release() {
    local archive extract_dir url code
    url="${RELEASE_BASE_URL}/pigeon-${ARCH}.tar.gz"
    archive="$(mktemp --suffix=.tar.gz)"
    extract_dir="$(mktemp -d)"
    register_temp "$archive"
    register_temp "$extract_dir"
    # Cleans both on every successful return; `die` inside this function is
    # covered by the EXIT trap that calls the same helper.
    trap cleanup_temp RETURN

    info "downloading ${url}"
    # curl -f makes 4xx/5xx a failure; -w still reports the status code we branch on.
    if ! code="$(curl -fsSL --retry 2 --connect-timeout 10 -o "$archive" -w '%{http_code}' "$url")"; then
        code="${code:-000}"
    fi

    case "$code" in
        200) ;;
        404)
            die "pre-release: no binaries yet — build from source (see README)"
            ;;
        *)
            die "download failed (HTTP ${code}): ${url}"
            ;;
    esac

    tar -xzf "$archive" -C "$extract_dir"
    extract_pigeon_binary "$extract_dir" "$url"
}

if [[ -n "$LOCAL_BIN" ]]; then
    [[ -f "$LOCAL_BIN" ]] || die "--bin path not found: ${LOCAL_BIN}"
    info "installing local binary: ${LOCAL_BIN}"
    install -m 0755 "$LOCAL_BIN" "$INSTALL_BIN"
else
    install_from_release
fi
info "installed ${INSTALL_BIN}"

# Ports 25 and 587 are below 1024. The systemd unit grants CAP_NET_BIND_SERVICE
# through AmbientCapabilities; the file capability below is belt and braces so
# the same binary also works when started by hand or by another supervisor.
if ! command -v setcap >/dev/null 2>&1; then
    warn "setcap not available (install libcap2-bin); relying on systemd AmbientCapabilities"
elif ! setcap 'cap_net_bind_service=+ep' "$INSTALL_BIN"; then
    warn "setcap failed on ${INSTALL_BIN}; relying on systemd AmbientCapabilities"
else
    info "granted CAP_NET_BIND_SERVICE to ${INSTALL_BIN}"
fi

# ---------------------------------------------------------------------------
# Optional webmail bundle
# ---------------------------------------------------------------------------

install_webmail() {
    local archive extract_dir url code
    # --webmail-dir <path>: install a local bundle (private repos, air-gapped)
    if [[ -n "$WEBMAIL_LOCAL_DIR" ]]; then
        [[ -d "$WEBMAIL_LOCAL_DIR" ]] || die "--webmail-dir not found: $WEBMAIL_LOCAL_DIR"
        info "installing webmail from local directory: $WEBMAIL_LOCAL_DIR"
        rm -rf -- "$WEBMAIL_DIR"
        install -d -m 0755 -o root -g root "$WEBMAIL_DIR"
        if ! cp -R "${WEBMAIL_LOCAL_DIR}/." "$WEBMAIL_DIR/"; then
            rm -rf -- "$WEBMAIL_DIR"
            die "failed to copy webmail bundle from $WEBMAIL_LOCAL_DIR (partial copy removed)"
        fi
        chmod -R a+rX "$WEBMAIL_DIR"
        info "installed webmail bundle: ${WEBMAIL_DIR}"
        return 0
    fi
    url="${RELEASE_BASE_URL}/pigeon-webmail.tar.gz"
    archive="$(mktemp --suffix=.tar.gz)"
    extract_dir="$(mktemp -d)"
    register_temp "$archive"
    register_temp "$extract_dir"
    trap cleanup_temp RETURN

    if ! code="$(curl -fsSL --retry 2 --connect-timeout 10 -o "$archive" -w '%{http_code}' "$url")"; then
        code="${code:-000}"
    fi
    if [[ "$code" != "200" ]]; then
        info "no webmail bundle available (private repo or no release yet); use --webmail-dir <path> for a local bundle"
        return 1
    fi

    tar -xzf "$archive" -C "$extract_dir"
    # Wipe the previous bundle first: hashed asset filenames change between
    # releases, so overlaying would leave stale chunks the server keeps serving.
    rm -rf -- "$WEBMAIL_DIR"
    install -d -m 0755 -o root -g root "$WEBMAIL_DIR"
    cp -R "${extract_dir}/." "$WEBMAIL_DIR/"
    # The service account only needs to read the bundle.
    chmod -R a+rX "$WEBMAIL_DIR"
    info "installed webmail bundle: ${WEBMAIL_DIR}"
    return 0
}

WEBMAIL_ENABLED=0
if [[ "$WANT_WEBMAIL" -eq 1 ]]; then
    if install_webmail; then
        WEBMAIL_ENABLED=1
    fi
else
    info "skipping webmail (--no-webmail)"
fi
# The server's boolean parser also accepts `true`/`1`; `on`/`off` is the
# spelling documented in docs/ARCHITECTURE.md and .env.example, so every
# surface (installer, ConfigMap, env template) agrees.
WEBMAIL_VALUE="off"
if [[ "$WEBMAIL_ENABLED" -eq 1 ]]; then
    WEBMAIL_VALUE="on"
fi

# ---------------------------------------------------------------------------
# Runtime configuration
# ---------------------------------------------------------------------------

info "writing ${ENV_FILE}"
umask 077
cat >"$ENV_FILE" <<EOF
# Managed by install.sh — re-run the installer instead of editing by hand.
PIGEON_HTTP_ADDR=:${API_PORT}
PIGEON_MASTER_KEY_FILE=${KEY_FILE}
PIGEON_DB_PATH=${DATA_DIR}/pigeon.db
PIGEON_SMTP_IN_ADDR=:25
PIGEON_SMTP_HOSTNAME=mail.${DOMAIN}
PIGEON_SMTP_OUT_STARTTLS=required
PIGEON_WEBMAIL=${WEBMAIL_VALUE}
PIGEON_LOG=info,json
EOF
chown root:"$SERVICE_USER" "$ENV_FILE"
chmod 0640 "$ENV_FILE"

info "writing ${UNIT_FILE}"
cat >"$UNIT_FILE" <<EOF
[Unit]
Description=Pigeon Mail server (API + MCP + SMTP)
Documentation=https://github.com/dantoniomarte/Pigeon-AI-Mail/blob/main/docs/DEPLOY.md
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
EnvironmentFile=${ENV_FILE}
ExecStart=${INSTALL_BIN} serve
Restart=on-failure
RestartSec=2

# :25 and :587 are privileged ports.
AmbientCapabilities=cap_net_bind_service
CapabilityBoundingSet=cap_net_bind_service
NoNewPrivileges=true

# Hardening: read-only system, the data dir is the only writable path.
ProtectSystem=strict
ReadWritePaths=${DATA_DIR}
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$UNIT_FILE"

if [[ "$START_SERVICE" -eq 1 ]]; then
    systemctl daemon-reload
    # daemon-reload only re-reads unit files; `enable --now` is a no-op on an
    # already-active unit. An upgrade (new binary or new environment) therefore
    # needs an explicit restart, or the old process keeps running.
    if systemctl is-active --quiet pigeon.service; then
        systemctl restart pigeon.service
        ACTION="restarted"
    else
        systemctl enable --now pigeon.service
        ACTION="started"
    fi
    info "service ${ACTION}"
    systemctl --no-pager --lines=0 status pigeon.service || true
else
    info "not starting (--no-start). Enable with: systemctl daemon-reload && systemctl enable --now pigeon"
fi

# ---------------------------------------------------------------------------
# Agent configuration (optional)
# ---------------------------------------------------------------------------

if [[ ${#AGENT_TARGETS[@]} -gt 0 ]]; then
    # Server-owned copy by default; the operator copies it to the agent's own
    # config path as the agent's user. The files hold paths and URLs only.
    if [[ -z "$AGENT_DIR" ]]; then
        AGENT_DIR="${CONFIG_DIR}/agents"
    fi
    export_agent_configs "$AGENT_DIR"
fi

# ---------------------------------------------------------------------------
# Next steps
# ---------------------------------------------------------------------------

cat <<EOF

Pigeon Mail is installed.

  binary      ${INSTALL_BIN}
  config      ${ENV_FILE}
  master key  ${KEY_FILE}   (0640 root:${SERVICE_USER} — back it up!)
  database    ${DATA_DIR}/pigeon.db
  webmail     ${WEBMAIL_VALUE}
  service     pigeon.service ($([[ "$START_SERVICE" -eq 1 ]] && echo "running" || echo "not started"))

Next steps:

1. DNS — every Mail record goes ON the mail domain you serve (${DOMAIN}),
   except the A record of the host that answers :25. The host is assumed to be
   mail.${DOMAIN}; substitute your own if it differs:

     mail.${DOMAIN}.                       A      <server-public-ip>
     ${DOMAIN}.                            MX     10 mail.${DOMAIN}.
     ${DOMAIN}.                            TXT    "v=spf1 a mx -all"
     <selector>._domainkey.${DOMAIN}.      TXT    "v=DKIM1; k=rsa; p=<public-key>"
     _dmarc.${DOMAIN}.                     TXT    "v=DMARC1; p=quarantine; rua=mailto:dmarc@${DOMAIN}"

   Verify each one after publishing:
     dig +short A mail.${DOMAIN}
     dig +short MX ${DOMAIN}
     dig +short TXT ${DOMAIN}
     dig +short TXT _dmarc.${DOMAIN}
     dig +short TXT <selector>._domainkey.${DOMAIN}

   DKIM: the selector and the public key are printed when the signing key is
   created (see docs/DEPLOY.md, "DNS records"). The DKIM/DMARC values above are
   placeholders.

   IMPORTANT: an MX record only works if inbound port 25 is reachable. If this
   host already runs another MTA on :25 (postfix, exim, mailcow…), Pigeon needs
   its own IP or must take over :25. Submission (587, inbound listener) and the
   API (8000) are unaffected.

2. TLS: put a reverse proxy (Caddy, nginx, Traefik) in front of :${API_PORT} and
   terminate TLS there. Pigeon speaks plain HTTP on the loopback/internal port.

3. Create an admin account and its API key on this host:
     set -a; . /etc/pigeon/pigeon.env; set +a
     pigeon keygen --account admin@${DOMAIN}
   Save the pk_… token (shown once). IGNORE the 'master key' the command
   also prints and its rotation instructions — the master key was already
   created by this installer at /etc/pigeon/master.key and must NOT change.
   See docs/ARCHITECTURE.md for additional keys with specific scopes.

4. Webhooks: POST /v1/webhooks registers an HTTPS endpoint; delivery events are
   HMAC-signed. See docs/ARCHITECTURE.md and docs/DEPLOY.md.

5. Health: GET /healthz (liveness) and GET /readyz (readiness: store reachable,
   master key present) on :${API_PORT}.

Full guide: docs/DEPLOY.md
EOF
