#!/usr/bin/env bash
# WRHS relay: native installer for Debian and Ubuntu servers (systemd), no
# Docker. Installs Node.js 22 if needed, the relay as the "wrhs-relay"
# service (listening on 127.0.0.1 only), and HTTPS in front of it:
#
#   caddy       Caddy with an automatic Let's Encrypt certificate. Needs DNS
#               for --domain pointing at this server and ports 80 and 443 open.
#   cloudflare  Cloudflare Tunnel: no open ports. Create the tunnel in the
#               Cloudflare dashboard (public hostname -> HTTP localhost:8080)
#               and pass its token.
#   none        Your own reverse proxy, pointed at 127.0.0.1:8080.
#
# Usage (from a checkout of the WRHS repository):
#
#   sudo deploy/relay/install.sh --domain relay.example.com
#   sudo deploy/relay/install.sh --domain relay.example.com --tls cloudflare --tunnel-token <token>
#   sudo deploy/relay/install.sh --tls none [--port 8080]
#
#   sudo deploy/relay/install.sh add-agent '<entry from wrhs-agent registration>'
#   sudo deploy/relay/install.sh remove-agent <agent id>
#   sudo deploy/relay/install.sh list-agents
#   sudo deploy/relay/install.sh status
#   sudo deploy/relay/install.sh uninstall [--purge]
#
# Running it again (for example after `git pull`) upgrades the relay and
# keeps its configuration and agents.

set -euo pipefail
umask 022

APP_DIR=/opt/wrhs-relay
CONF_DIR=/etc/wrhs-relay
AGENTS_FILE=$CONF_DIR/agents.json
ENV_FILE=$CONF_DIR/relay.env
STATE_FILE=$CONF_DIR/install.conf
SERVICE=wrhs-relay
SVC_USER=wrhs-relay
UNIT_FILE=/etc/systemd/system/$SERVICE.service
CADDYFILE=/etc/caddy/Caddyfile
CADDY_SITE=/etc/caddy/wrhs-relay.caddy
CADDY_IMPORT="import $CADDY_SITE"
NODE_MAJOR=22
NODE_MIN=22.18.0
SRC_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

# ---------------------------------------------------------------- helpers

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }
warn() { printf '\033[1;33mWARNING:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

usage() { sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

need_root() { [[ $EUID -eq 0 ]] || die "run this as root (sudo $0 ...)"; }

check_system() {
  [[ -r /etc/os-release ]] || die "unsupported system: /etc/os-release is missing"
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ " ${ID:-} ${ID_LIKE:-} " == *" debian "* || " ${ID:-} ${ID_LIKE:-} " == *" ubuntu "* ]] ||
    die "this installer supports Debian and Ubuntu (found ${PRETTY_NAME:-unknown}); see docs/DEPLOYMENT.md for Docker"
  command -v apt-get >/dev/null || die "apt-get not found"
  [[ -d /run/systemd/system ]] || die "systemd is not running; this installer needs it"
}

APT_UPDATED=0
apt_install() {
  local missing=()
  for p in "$@"; do dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p"); done
  [[ ${#missing[@]} -eq 0 ]] && return 0
  if [[ $APT_UPDATED -eq 0 ]]; then
    apt-get update -qq
    APT_UPDATED=1
  fi
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing[@]}" >/dev/null
}

apt_repo_added() { APT_UPDATED=0; }

version_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" == "$2" ]]; }

state_get() { [[ -r $STATE_FILE ]] && sed -n "s/^$1=//p" "$STATE_FILE" | tail -n1 || true; }

env_port() { [[ -r $ENV_FILE ]] && sed -n 's/^RELAY_PORT=//p' "$ENV_FILE" | tail -n1 || true; }

# ---------------------------------------------------------------- Node.js

NODE=
NPM=

usable_node() {
  local n=$1 v
  [[ -x $n ]] || return 1
  case $(readlink -f "$n") in /home/* | /root/*) return 1 ;; esac # the service could not read it
  v=$("$n" --version 2>/dev/null) || return 1
  version_ge "${v#v}" "$NODE_MIN"
}

ensure_node() {
  local c
  for c in "$(state_get NODE)" /usr/bin/node "$(command -v node || true)"; do
    if [[ -n $c ]] && usable_node "$c"; then
      NODE=$(readlink -f "$c")
      break
    fi
  done
  if [[ -z $NODE ]]; then
    say "Installing Node.js $NODE_MAJOR (NodeSource)"
    apt_install ca-certificates curl gnupg
    install -d -m 0755 /etc/apt/keyrings
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key |
      gpg --dearmor --yes -o /etc/apt/keyrings/nodesource.gpg
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$NODE_MAJOR.x nodistro main" \
      >/etc/apt/sources.list.d/nodesource.list
    # Not apt_install: an older nodejs from the distribution is replaced too.
    apt-get update -qq
    APT_UPDATED=1
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nodejs >/dev/null
    usable_node /usr/bin/node || die "Node.js $NODE_MIN or later is required; /usr/bin/node is $(/usr/bin/node --version 2>&1)"
    NODE=/usr/bin/node
  fi
  NPM=$(dirname "$NODE")/npm
  [[ -x $NPM ]] || NPM=$(command -v npm) || die "npm not found next to $NODE"
  note "Node.js $("$NODE" --version) at $NODE"
}

# ---------------------------------------------------------------- relay

stage_app() {
  # Only what the relay needs: the protocol and relay packages and their
  # dependencies. The other workspaces' package.json files keep npm ci happy.
  local stage=$APP_DIR.new
  for f in package.json package-lock.json packages/protocol/src packages/relay/src; do
    [[ -e $SRC_DIR/$f ]] || die "$SRC_DIR/$f is missing; run this script from a checkout of the WRHS repository"
  done
  rm -rf "$stage"
  install -d "$stage/packages"
  cp "$SRC_DIR/package.json" "$SRC_DIR/package-lock.json" "$stage/"
  for p in protocol relay agent client; do
    install -d "$stage/packages/$p"
    cp "$SRC_DIR/packages/$p/package.json" "$stage/packages/$p/"
  done
  cp -r "$SRC_DIR/packages/protocol/src" "$stage/packages/protocol/"
  cp -r "$SRC_DIR/packages/relay/src" "$stage/packages/relay/"
  (cd "$stage" && "$NPM" ci --omit=dev --ignore-scripts --no-audit --no-fund --loglevel=error >/dev/null)
  chown -R root:root "$stage"
}

ensure_user_and_config() {
  local port=$1
  id -u "$SVC_USER" >/dev/null 2>&1 ||
    useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$SVC_USER"
  install -d -m 0750 -o root -g "$SVC_USER" "$CONF_DIR"
  if [[ ! -e $AGENTS_FILE ]]; then
    install -m 0640 -o root -g "$SVC_USER" "$SRC_DIR/deploy/relay/agents.json.example" "$AGENTS_FILE"
  fi
  if [[ ! -e $ENV_FILE ]]; then
    install -m 0640 -o root -g "$SVC_USER" /dev/null "$ENV_FILE"
    cat >"$ENV_FILE" <<EOF
# WRHS relay settings (see docs/DEPLOYMENT.md). Restart after changes:
#   sudo systemctl restart $SERVICE
RELAY_HOST=127.0.0.1
RELAY_PORT=$port
RELAY_AGENTS_FILE=$AGENTS_FILE
# The relay is reachable only through the local reverse proxy or tunnel,
# so the client address it appends to X-Forwarded-For can be trusted.
RELAY_TRUST_PROXY=1
#RELAY_MAX_SESSIONS_PER_IP=16
#RELAY_OPENS_PER_MINUTE=30
EOF
  elif [[ -n ${PORT_SET:-} ]]; then
    sed -i "s/^RELAY_PORT=.*/RELAY_PORT=$port/" "$ENV_FILE"
  fi
}

write_unit() {
  cat >"$UNIT_FILE" <<EOF
# Installed by deploy/relay/install.sh
[Unit]
Description=WRHS relay
After=network-online.target
Wants=network-online.target

[Service]
User=$SVC_USER
Group=$SVC_USER
WorkingDirectory=$APP_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$NODE $APP_DIR/packages/relay/src/main.ts
Restart=always
RestartSec=2
# The relay only reads its files and talks to the network.
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native
# Not MemoryDenyWriteExecute: Node.js needs it off for its JIT.

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable "$SERVICE" >/dev/null 2>&1
}

wait_healthy() {
  local port
  port=$(env_port)
  for _ in $(seq 1 30); do
    curl -fsS --max-time 2 "http://127.0.0.1:$port/healthz" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  return 1
}

restart_relay() {
  systemctl restart "$SERVICE"
  wait_healthy || {
    journalctl -u "$SERVICE" -n 30 --no-pager >&2 || true
    return 1
  }
}

swap_in_app() {
  local old=$APP_DIR.old
  rm -rf "$old"
  [[ -d $APP_DIR ]] && mv "$APP_DIR" "$old"
  mv "$APP_DIR.new" "$APP_DIR"
  if restart_relay; then
    rm -rf "$old"
    return 0
  fi
  if [[ -d $old ]]; then
    warn "the new version did not start; going back to the previous one"
    rm -rf "$APP_DIR"
    mv "$old" "$APP_DIR"
    restart_relay || true
  fi
  die "the relay did not start (see the log above, or: journalctl -u $SERVICE)"
}

# ---------------------------------------------------------------- HTTPS in front

open_firewall() {
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw allow 80/tcp >/dev/null
    ufw allow 443/tcp >/dev/null
    note "ufw: allowed TCP 80 and 443"
  fi
}

setup_caddy() {
  local domain=$1 port=$2
  if ! command -v caddy >/dev/null; then
    say "Installing Caddy"
    apt_install ca-certificates curl gnupg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' |
      gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
      -o /etc/apt/sources.list.d/caddy-stable.list
    apt_repo_added
    apt_install caddy
  fi
  say "Configuring Caddy for https://$domain"
  cat >"$CADDY_SITE" <<EOF
# Installed by deploy/relay/install.sh. TLS here is only the outer layer;
# confidentiality comes from the end-to-end inner layer.
$domain {
	reverse_proxy 127.0.0.1:$port {
		flush_interval -1
		transport http {
			read_timeout 0
		}
	}
	header {
		Strict-Transport-Security "max-age=31536000"
		-Server
	}
}
EOF
  if [[ ! -e $CADDYFILE ]] || caddyfile_is_stock; then
    # Replace the package's placeholder site (it would hold port 80).
    [[ -e $CADDYFILE ]] && cp "$CADDYFILE" "$CADDYFILE.wrhs-backup"
    printf '%s\n' "$CADDY_IMPORT" >"$CADDYFILE"
  elif ! grep -qxF "$CADDY_IMPORT" "$CADDYFILE"; then
    cp "$CADDYFILE" "$CADDYFILE.wrhs-backup"
    printf '\n%s\n' "$CADDY_IMPORT" >>"$CADDYFILE"
    note "added '$CADDY_IMPORT' to your existing $CADDYFILE (backup: $CADDYFILE.wrhs-backup)"
  fi
  caddy validate --config "$CADDYFILE" --adapter caddyfile >/dev/null 2>&1 ||
    die "Caddy rejected the configuration: caddy validate --config $CADDYFILE --adapter caddyfile"
  systemctl enable caddy >/dev/null 2>&1
  systemctl reload caddy 2>/dev/null || systemctl restart caddy
  open_firewall
  if ! getent ahosts "$domain" >/dev/null; then
    warn "$domain does not resolve yet. Point its DNS at this server; Caddy gets the certificate once it does."
  fi
}

caddyfile_is_stock() {
  # The Caddy package's default: one ":80" site serving /usr/share/caddy.
  local body
  body=$(grep -v '^[[:space:]]*#' "$CADDYFILE" | sed '/^[[:space:]]*$/d')
  [[ $body == *":80 {"* && $body == *"root * /usr/share/caddy"* && $(grep -c '{' <<<"$body") -le 2 ]]
}

setup_cloudflared() {
  local token=$1
  if ! command -v cloudflared >/dev/null; then
    say "Installing cloudflared"
    apt_install ca-certificates curl
    install -d -m 0755 /usr/share/keyrings
    curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o /usr/share/keyrings/cloudflare-main.gpg
    echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main' \
      >/etc/apt/sources.list.d/cloudflared.list
    apt_repo_added
    apt_install cloudflared
  fi
  if [[ -n $token ]]; then
    say "Connecting the Cloudflare tunnel"
    if [[ -e /etc/systemd/system/cloudflared.service ]]; then
      cloudflared service uninstall >/dev/null 2>&1 || true
    fi
    cloudflared service install "$token" >/dev/null 2>&1 || die "cloudflared service install failed; check the tunnel token"
  elif ! systemctl is-active --quiet cloudflared 2>/dev/null; then
    warn "no --tunnel-token given: the tunnel is not connected yet. Run: sudo cloudflared service install <token>"
  fi
}

check_public() {
  local domain=$1
  if [[ $domain == localhost ]]; then
    note "skipping the public check for localhost (Caddy's own certificate authority)"
    return 0
  fi
  if ! getent ahosts "$domain" >/dev/null; then
    warn "$domain does not resolve (yet), so https://$domain is not reachable. The relay itself is running."
    return 0
  fi
  say "Checking https://$domain/healthz"
  for _ in $(seq 1 30); do
    if curl -fsS --max-time 5 "https://$domain/healthz" >/dev/null 2>&1; then
      note "reachable"
      return 0
    fi
    sleep 3
  done
  warn "https://$domain/healthz is not answering yet (DNS, firewall, certificate or tunnel). The relay itself is running."
}

# ---------------------------------------------------------------- agents

agents_edit() {
  # agents_edit add|remove|list [value]: edits the agents file with Node.
  local action=$1 value=${2:-}
  [[ -e $AGENTS_FILE ]] || die "$AGENTS_FILE not found; install the relay first"
  NODE=$(state_get NODE)
  [[ -n $NODE && -x $NODE ]] || NODE=$(command -v node) || die "node not found"
  # shellcheck disable=SC2016 # JavaScript, not shell
  ACTION=$action VALUE=$value FILE=$AGENTS_FILE "$NODE" --input-type=module -e '
    import { readFileSync, writeFileSync, renameSync } from "node:fs";
    const { ACTION, VALUE, FILE } = process.env;
    const agents = JSON.parse(readFileSync(FILE, "utf8"));
    const ids = () => Object.keys(agents).filter((k) => !k.startsWith("_"));
    const fail = (m) => { console.error("ERROR: " + m); process.exit(2); };
    if (ACTION === "list") {
      for (const id of ids()) console.log(id);
      process.exit(0);
    }
    if (ACTION === "remove") {
      if (!(VALUE in agents)) fail(`no agent ${VALUE}`);
      delete agents[VALUE];
    } else {
      // Accepts {"id": "hash"} (wrhs-agent registration), "id": "hash" (wrhs-agent show) or id:hash.
      let entries;
      const v = VALUE.trim();
      try {
        entries = Object.entries(JSON.parse(v.startsWith("{") ? v : `{${v}}`));
      } catch {
        const m = /^([0-9a-f]{32})\s*[:=]\s*([0-9a-f]{64})$/.exec(v);
        if (!m) fail("expected the output of wrhs-agent registration, for example {\"<agent id>\": \"<token hash>\"}");
        entries = [[m[1], m[2]]];
      }
      if (!entries.length) fail("no agent entry given");
      for (const [id, hash] of entries) {
        if (!/^[0-9a-f]{32}$/.test(id) || typeof hash !== "string" || !/^[0-9a-f]{64}$/.test(hash)) {
          fail(`bad entry for ${id}: expected a 32-hex agent id and a 64-hex token hash`);
        }
        console.log(`${id in agents ? "updated" : "added"} agent ${id}`);
        agents[id] = hash;
      }
    }
    writeFileSync(FILE + ".tmp", JSON.stringify(agents, null, 2) + "\n");
    renameSync(FILE + ".tmp", FILE);
  '
  chown root:"$SVC_USER" "$AGENTS_FILE"
  chmod 0640 "$AGENTS_FILE"
}

# ---------------------------------------------------------------- commands

cmd_install() {
  local domain=$DOMAIN tls=$TLS token=$TOKEN port
  check_system
  port=${PORT:-$(env_port)}
  port=${port:-8080}
  [[ $port =~ ^[0-9]+$ && $port -ge 1 && $port -le 65535 ]] || die "--port must be 1-65535"
  [[ -z $tls ]] && tls=$(state_get TLS)
  [[ -z $domain ]] && domain=$(state_get DOMAIN)
  tls=${tls:-caddy}
  case $tls in caddy | cloudflare | none) ;; *) die "--tls must be caddy, cloudflare or none" ;; esac
  if [[ $tls != none && -z $domain ]]; then
    if [[ -t 0 ]]; then
      read -r -p "Relay domain (for example relay.example.com): " domain
    fi
    [[ -n $domain ]] || die "--domain is required with --tls $tls"
  fi
  if [[ -n $domain && ! $domain =~ ^[A-Za-z0-9.-]+$ ]]; then die "--domain must be a host name, like relay.example.com"; fi

  say "Preparing"
  apt_install ca-certificates curl
  ensure_node
  ensure_user_and_config "$port"

  say "Installing the relay to $APP_DIR"
  stage_app
  write_unit
  swap_in_app
  note "relay running on 127.0.0.1:$(env_port)"

  case $tls in
    caddy) setup_caddy "$domain" "$(env_port)" ;;
    cloudflare) setup_cloudflared "$token" ;;
    none) ;;
  esac

  printf 'TLS=%s\nDOMAIN=%s\nNODE=%s\n' "$tls" "$domain" "$NODE" >"$STATE_FILE"
  chmod 0644 "$STATE_FILE"

  if [[ -n $domain && $tls != none ]]; then check_public "$domain"; fi

  local url=${domain:+https://$domain}
  echo
  say "Done"
  case $tls in
    none) note "Point your reverse proxy (HTTPS, WebSockets on) at http://127.0.0.1:$(env_port)." ;;
    cloudflare) note "In the Cloudflare dashboard, the tunnel's public hostname $domain must point to HTTP localhost:$(env_port)." ;;
  esac
  cat <<EOF

Next steps:
  1. On the Windows PC, install the agent with the relay address:
       install.ps1 -RelayUrl ${url:-https://<your relay domain>} -User <name>
  2. Allow the agent here, with the entry printed by
       wrhs-agent registration   (on the PC)
     sudo $0 add-agent '{"<agent id>": "<token hash>"}'

Logs:     journalctl -u $SERVICE -f
Settings: $ENV_FILE
EOF
}

cmd_add_agent() {
  [[ -n ${1:-} ]] || die "usage: $0 add-agent '{\"<agent id>\": \"<token hash>\"}'"
  agents_edit add "$1"
  restart_relay || die "the relay did not restart"
  note "relay restarted; the agent connects within about 30 seconds (journalctl -u $SERVICE -f shows agent-online)"
}

cmd_remove_agent() {
  [[ -n ${1:-} ]] || die "usage: $0 remove-agent <agent id>"
  agents_edit remove "$1"
  restart_relay || die "the relay did not restart"
  note "removed agent $1"
}

cmd_status() {
  systemctl --no-pager status "$SERVICE" | head -n 5 || true
  if wait_healthy; then note "health check: ok"; else warn "health check failed"; fi
  note "agents: $(agents_edit list | wc -l)"
  local domain tls
  domain=$(state_get DOMAIN)
  tls=$(state_get TLS)
  if [[ -n $domain ]]; then note "public address: https://$domain ($tls)"; fi
}

cmd_uninstall() {
  local tls
  tls=$(state_get TLS)
  say "Removing the relay"
  systemctl disable --now "$SERVICE" >/dev/null 2>&1 || true
  rm -f "$UNIT_FILE"
  systemctl daemon-reload
  rm -rf "$APP_DIR" "$APP_DIR.new" "$APP_DIR.old"
  if [[ -e $CADDY_SITE ]]; then
    rm -f "$CADDY_SITE"
    if [[ -e $CADDYFILE ]]; then
      sed -i "\\|^${CADDY_IMPORT}\$|d" "$CADDYFILE"
      if [[ -z $(grep -v '^[[:space:]]*$' "$CADDYFILE" || true) && -e $CADDYFILE.wrhs-backup ]]; then
        mv "$CADDYFILE.wrhs-backup" "$CADDYFILE"
      fi
      systemctl reload caddy 2>/dev/null || true
    fi
    note "removed the Caddy site (Caddy itself stays installed)"
  fi
  if [[ $tls == cloudflare ]]; then
    note "the Cloudflare tunnel service stays installed; remove it with: sudo cloudflared service uninstall"
  fi
  if [[ ${PURGE:-} == 1 ]]; then
    rm -rf "$CONF_DIR"
    userdel "$SVC_USER" 2>/dev/null || true
    note "deleted $CONF_DIR and the $SVC_USER user"
  else
    note "kept $CONF_DIR (agents and settings); add --purge to delete it"
  fi
  say "Done"
}

# ---------------------------------------------------------------- main

COMMAND=install
DOMAIN=
TLS=
TOKEN=
PORT=
PORT_SET=
PURGE=
ARGS=()
while [[ $# -gt 0 ]]; do
  case $1 in
    install | add-agent | remove-agent | list-agents | status | uninstall)
      [[ ${#ARGS[@]} -eq 0 && $COMMAND == install ]] || die "unexpected '$1'"
      COMMAND=$1
      ;;
    --domain) DOMAIN=${2:-}; shift ;;
    --domain=*) DOMAIN=${1#*=} ;;
    --tls) TLS=${2:-}; shift ;;
    --tls=*) TLS=${1#*=} ;;
    --tunnel-token) TOKEN=${2:-}; shift ;;
    --tunnel-token=*) TOKEN=${1#*=} ;;
    --port) PORT=${2:-}; PORT_SET=1; shift ;;
    --port=*) PORT=${1#*=}; PORT_SET=1 ;;
    --purge) PURGE=1 ;;
    -h | --help) usage 0 ;;
    -*) die "unknown option $1 (see --help)" ;;
    *) ARGS+=("$1") ;;
  esac
  shift
done

need_root
case $COMMAND in
  install) [[ ${#ARGS[@]} -eq 0 ]] || die "unexpected '${ARGS[0]}'"; cmd_install ;;
  add-agent) cmd_add_agent "${ARGS[*]:-}" ;;
  remove-agent) cmd_remove_agent "${ARGS[0]:-}" ;;
  list-agents) agents_edit list ;;
  status) cmd_status ;;
  uninstall) cmd_uninstall ;;
esac
