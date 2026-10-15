# Deploying WRHS

A deployment has three parts:

1. **Relay**: a public HTTPS endpoint, for example a small VPS. It is
   untrusted for confidentiality.
2. **Agent**: on the Windows PC whose desktop you want (see
   [WINDOWS.md](WINDOWS.md); this is the usual setup), or on a machine in
   the network that can reach your RDP hosts. Needs only outbound HTTPS.
   guacd is optional (see §2).
3. **Launcher**: a personalized HTML file that each user keeps on their
   device.

## 0. Try it locally first

The demo starts a relay, an agent, guacd and a throwaway Linux desktop
(xrdp) on your machine:

```bash
npm ci && npm run build
cd deploy/demo
./setup.sh              # prints the demo password and TOTP secret
docker compose up --build
# open deploy/demo/data/wrhs-demo-launcher.html in your browser
```

Add the printed TOTP secret to any authenticator app, sign in as `demo`, and
pick "Demo Linux desktop".

## 1. Relay

Requirements: a host with ports 80/443 open and a DNS name, for example
`relay.example.com`.

```bash
cd deploy/relay
cp agents.json.example agents.json   # no agents yet; you add them at step 2
RELAY_DOMAIN=relay.example.com docker compose up -d
```

Caddy obtains a certificate automatically and proxies to the relay.

### Without Docker (Debian or Ubuntu)

`deploy/relay/install.sh` installs the relay as a systemd service. It sets
up everything the Docker setup does:

- Node.js 22 (from NodeSource, if a recent enough one is not installed).
- The `wrhs-relay` service, running as its own system user and listening on
  127.0.0.1 only.
- HTTPS in front of it.

```bash
git clone https://github.com/guitar24t/WRHS.git && cd WRHS

# Caddy with a Let's Encrypt certificate (DNS must point here, ports 80/443 open):
sudo deploy/relay/install.sh --domain relay.example.com

# Or a Cloudflare Tunnel, with no open ports. Create the tunnel in the
# Cloudflare dashboard (Networks → Tunnels); its public hostname goes to
# HTTP localhost:8080. Pass the tunnel's token:
sudo deploy/relay/install.sh --domain relay.example.com --tls cloudflare --tunnel-token <token>

# Or your own reverse proxy, pointed at 127.0.0.1:8080:
sudo deploy/relay/install.sh --tls none
```

The script checks `https://<domain>/healthz` at the end. Then manage it with:

```bash
sudo deploy/relay/install.sh add-agent '<registration entry>'   # from the agent (step 2); restarts the relay
sudo deploy/relay/install.sh list-agents
sudo deploy/relay/install.sh remove-agent 5c7f612b9b0803b5c3a6765e1bfe0cf2
sudo deploy/relay/install.sh status
journalctl -u wrhs-relay -f                                      # the relay's log
sudo deploy/relay/install.sh uninstall                           # keeps /etc/wrhs-relay; --purge removes it
```

Running the script again (after `git pull`) upgrades the relay. It keeps
the configuration and agents, and it goes back to the previous version if
the new one does not start. Files:

| Path | Contents |
|---|---|
| `/opt/wrhs-relay` | The relay code |
| `/etc/wrhs-relay/agents.json` | Registered agents |
| `/etc/wrhs-relay/relay.env` | Relay settings (the variables below); `systemctl restart wrhs-relay` after editing |
| `/etc/caddy/wrhs-relay.caddy` | The Caddy site, imported from `/etc/caddy/Caddyfile` |

### Relay settings

All are environment variables:

| Variable | Meaning |
|---|---|
| `RELAY_PORT` / `RELAY_HOST` | Listen address (default `0.0.0.0:8080`) |
| `RELAY_AGENTS_FILE` | JSON map `{agentId: sha256(relayToken)}` of agents allowed to register |
| `RELAY_TLS_CERT` / `RELAY_TLS_KEY` | Terminate TLS in the relay itself instead of behind Caddy |
| `RELAY_TRUST_PROXY=1` | Use `X-Forwarded-For` from your reverse proxy for rate limiting |
| `RELAY_OPENS_PER_MINUTE` | Session opens and resumes per client IP per minute (default 30) |
| `RELAY_MAX_SESSIONS_PER_IP` | Concurrent sessions per client IP (default 16). Raise it if many users share one proxy egress IP. |
| `RELAY_MAX_SESSIONS_PER_AGENT` | Concurrent sessions per agent (default 32) |
| `RELAY_HOSTED_CLIENT` | Path to `hosted.html`, to serve the convenience client at `/` |
| `RELAY_OPEN_REGISTRATION=1` | Accept any agent. **Development only.** |

The relay logs JSON lines with metadata only: session open/close, agent
online/offline, byte counts, and agents it turns away (`agent-rejected`, with
the reason: not in the agents file, or wrong token).

Behind Cloudflare (a tunnel or its proxy), its security features can turn
the agent away before it reaches the relay: the agent's log then shows
`relay-rejected` with `"server": "cloudflare"`. Check Browser Integrity Check,
Bot Fight Mode, WAF rules and Cloudflare Access for the relay's hostname.

## 2. Agent

**To serve a Windows PC's own desktop**, install the agent on that PC with
the Windows installer: [WINDOWS.md](WINDOWS.md). The rest of this section
covers an agent on a separate Linux machine that opens other computers on
its network.

On a machine in your private network (Linux with Docker; the agent itself
also runs anywhere Node.js 22.18+ runs):

```bash
cd deploy/agent
mkdir -p data && sudo chown 1000:1000 data   # the container runs as the unprivileged "node" user
CLI="docker compose run --rm agent node packages/agent/src/cli.ts --config /data/agent.json"

$CLI init --relay https://relay.example.com --name "Home office"
```

`init` creates `data/agent.key.json` (the agent identity; keep it secret and
back it up) and `data/agent.json`. It also prints the agent's entry for the
relay's `agents.json` (`$CLI registration` prints it again, as JSON):

```json
{ "5c7f612b9b0803b5c3a6765e1bfe0cf2": "896e805b...f8f" }
```

Add the entry to `agents.json` on the relay host (one entry per agent, in
the same `{ }`) and restart the relay: `docker compose restart relay`. It
reads the file only at startup. With the native install, run
`sudo deploy/relay/install.sh add-agent '<entry>'` instead, which does both. If you will use
guacd targets, edit `data/agent.json` and set
`"guacd": {"host": "guacd", "port": 4822}`.

Add desktops and users:

```bash
$CLI add-target --id desk --name "Desk PC" --host 192.168.1.20 --rdp-user alice
docker compose run --rm -it agent node packages/agent/src/cli.ts --config /data/agent.json add-user alice
docker compose up -d
```

`add-user` asks for a password (at least 12 characters) and prints an
`otpauth://` URI and secret for the user's authenticator app.

Notes on targets:

- **Built-in engine** (default, `"engine": "rdp"`): the browser runs the RDP
  client, and users sign in with their own Windows credentials (NLA runs in
  the browser). `--rdp-user` and `--domain` only pre-fill the prompt.
  `--security tls` turns NLA off, so the computer shows its own sign-in
  screen. Pin the host's certificate with `--cert-sha256` (the agent logs
  each host's fingerprint in `rdp-connected`), so nothing on the LAN can
  pose as it.
- **guacd engine** (`--engine guacd`): guacd connects and renders. It can
  use stored credentials (`--rdp-user/--rdp-password/--domain`) or ask the
  user. `--ignore-cert` is common for internal hosts with self-signed RDP
  certificates. Per-target options in `agent.json`:
  - `clipboard`: `both`, `copy`, `paste` or `none`;
  - `fileTransfer`: `true`/`false`;
  - `audio`: `true`/`false`;
  - `extraParams`: any extra guacd RDP parameter.
- Per-user options: `targets` (a list of ids, or `"*"`) and `deviceKeys`.

Policy (`policy` in `agent.json`, defaults shown):

```json
{
  "requireTotp": true,
  "maxAuthFailures": 5,
  "lockoutSeconds": 300,
  "authTimeoutSeconds": 120,
  "idleTimeoutSeconds": 3600,
  "maxSessionSeconds": 43200
}
```

The agent logs JSON audit events: `handshake-ok` with the device
fingerprint, `login-ok`/`login-fail`, `target-open`/`target-closed`,
`target-fail`, `rdp-connected` (with the RDP host's certificate
fingerprint), `integrity-failure`, `session-end`.

## 3. Launchers

```bash
docker compose run --rm agent node packages/agent/src/cli.ts --config /data/agent.json \
    launcher --out /data/wrhs-home-office.html
```

The command prints the file's SHA-256 and the agent fingerprint it pins.
Distribute the file over a channel you trust:

- copy it to your laptop or phone while you are on your own network;
- hand it over on a USB stick;
- or, if it must travel over an untrusted network, check its SHA-256 over
  a separate channel (read it out on a phone call, or compare it with what
  `wrhs-agent launcher` printed).

To use it, double-click the file and press **Connect**. The header shows
**End-to-end encrypted to Home office** once the agent's identity has been
verified. A generic launcher (`packages/client/dist/wrhs-launcher.html`)
also exists. It asks for the relay URL and agent key instead of having them
built in.

### Optional: device enrollment

The launcher shows a "This device" fingerprint. The agent's `handshake-ok`
log line has the same fingerprint (`device`) and the full key (`deviceKey`).
To restrict a user to known devices:

```bash
$CLI enroll-device alice <device-key-base64url>
```

## 4. Hardening checklist

- [ ] The relay uses a valid public certificate (Caddy does this) and runs
      with `RELAY_AGENTS_FILE`, never `RELAY_OPEN_REGISTRATION`.
- [ ] `agent.key.json` and `agent.json` are mode 0600 and backed up.
- [ ] guacd (if used) is not reachable from anywhere except the agent.
- [ ] Remote Desktop on the agent's own PC is blocked from the network
      (the Windows installer does this), and LAN targets pin `certSha256`.
- [ ] RDP hosts use NLA. Users have strong passwords and TOTP.
- [ ] Clipboard and file transfer are only enabled where needed.
- [ ] Launchers are distributed over trusted channels. The hosted client is
      left off unless you accept passive-only protection.
- [ ] Agent and relay logs go to your log system. Alert on
      `integrity-failure` and repeated `login-fail`.

## 5. Rotating the agent key

1. `init` a new key on a new config (or move the old `agent.key.json` aside
   and run `init` again).
2. Register the new agent id at the relay.
3. Issue new launchers.
4. Remove the old registration.

A launcher can pin several keys (`launcher --also-pin <old-or-new-key>`), so
the same file keeps working during a rollover. Note that the relay routes by
the *first* pinned key's agent id.
