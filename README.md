# WRHS: web remote desktop that the proxy cannot read

WRHS lets you use your Windows PC's desktop from a web browser on networks
you don't trust, including networks whose proxy **decrypts HTTPS**. Install
the agent on the PC (it runs as a Windows service), and from anywhere you get
that PC's desktop the way Remote Desktop gives it to you: your own session,
with the PC's screen locked while you are connected.

- **Outer layer:** plain HTTPS on port 443 (WebSocket, with an automatic
  fallback to long-polling). Corporate, hotel and school proxies pass it
  through as normal web traffic, even when they intercept TLS.
- **Inner layer:** an end-to-end encrypted, mutually authenticated
  [Noise](https://noiseprotocol.org) session between the browser and an
  agent on your own network. It uses X25519 + ML-KEM-768 (post-quantum
  hybrid) with ChaCha20-Poly1305. The proxy, and the relay in the middle,
  see only ciphertext. They cannot impersonate your agent, and they cannot
  change a single byte without the session detecting it and shutting down.

```
 Browser (offline launcher) ──HTTPS──▶ [intercepting proxy] ──HTTPS──▶ Relay ◀──HTTPS── Agent ──loopback──▶ Remote Desktop
   IronRDP (WebAssembly)                                                            (Windows service)     (this PC)
        ╰──────────────── Noise XXhfs: end-to-end encrypted, agent key pinned ───────────────╯
```

Inside the tunnel, WRHS reuses proven parts. Windows' own Remote Desktop
service produces the session. The launcher runs the RDP client: IronRDP,
compiled to WebAssembly. The agent only opens the connection and passes it
through the tunnel. Apache Guacamole's `guacd` remains available as an
alternative engine, for example for Linux hosts.

## Why a launcher file instead of a website?

If the client code were downloaded through the intercepting proxy, the proxy
could change it and take your password before anything is encrypted. So the
client is a **single self-contained HTML file** that you generate with the
agent and copy to your device over a channel you trust. You open it from
disk. It pins your agent's public key, runs only its own hash-pinned script,
and can only talk to your relay. There is nothing to install. See
[docs/DESIGN.md §4](docs/DESIGN.md#4-the-hard-part-trusting-the-code-in-the-browser).

## Features

- Pinned agent identity: an active man-in-the-middle is detected before any
  credential is sent.
- Hybrid post-quantum key exchange, so traffic the proxy archives today
  cannot be decrypted later.
- Login (password + TOTP) inside the tunnel, with lockout and replay
  protection.
- Sessions survive the proxy killing connections: the encrypted session
  resumes and lost data is retransmitted end to end.
- Size padding and keystroke-timing obfuscation (a fixed 20 ms send grid with
  chaff while typing).
- Zero-trust relay. The agent needs only outbound HTTPS, with no port
  forwarding.
- Runs on Windows as a service: starts with Windows, works at the sign-in
  screen, and installs with one PowerShell script. It turns on Remote
  Desktop with NLA and blocks it from the network, so WRHS is the only way
  in. See [docs/WINDOWS.md](docs/WINDOWS.md).
- Network Level Authentication runs in the browser: the agent never sees the
  Windows password.
- Per-user target lists. The agent can also open other PCs on its network,
  with optional certificate pinning, or use guacd.
- Works on phones and tablets: tap to click, long-press to right-click, and an
  on-screen keyboard button.
- Clear feedback: a starting screen while the remote computer signs in, a
  reconnecting overlay, warnings before idle or session-length sign-out, and
  plain-language errors. The interface passes an automated WCAG 2.1 AA check
  in light and dark mode.
- Audit log of handshakes, logins, desktops opened, and tampering.

## Repository layout

| Path | What |
|---|---|
| `packages/protocol` | Noise XXhfs handshake, encrypted record layer, transports, client connection logic (shared by browser and Node) |
| `packages/relay` | Blind relay server (WebSocket + long-poll) |
| `packages/agent` | Agent: authentication, policy, RDP gateway (RDCleanPath), guacd bridge, `wrhs-agent` CLI, launcher generator |
| `packages/client` | Browser client, built into a single HTML file with IronRDP (WebAssembly) and vendored guacamole-common-js 1.6.0 |
| `test/e2e` | End-to-end tests through a logging and tampering MITM proxy |
| `test/browser` | Real-Chromium tests of the `file://` launcher (needs Playwright) |
| `test/windows` | Windows CI check: Chromium to the runner's own Remote Desktop through the installed service |
| `deploy/windows` | Windows installer and uninstaller (`npm run package:windows`) |
| `deploy/` | Docker Compose for the relay (with Caddy), a Linux agent (with guacd), and a local demo |
| `docs/` | [Windows](docs/WINDOWS.md), [design](docs/DESIGN.md), [threat model](docs/THREAT_MODEL.md), [protocol spec](docs/PROTOCOL.md), [deployment](docs/DEPLOYMENT.md) |

## Quick start: this Windows PC

On Windows Pro, Enterprise or Server, with Node.js ≥ 22.18 installed for all
users:

```powershell
npm ci
npm run package:windows
# PowerShell as administrator:
powershell -ExecutionPolicy Bypass -File .\dist\windows\install.ps1 -RelayUrl https://relay.example.com -User alice
```

You also need a relay ([docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#1-relay)).
Everything else is in [docs/WINDOWS.md](docs/WINDOWS.md).

## Local demo (Linux, Docker)

Requirements: Node.js ≥ 22.18 and Docker. The demo uses a Linux desktop and
the guacd engine.

```bash
npm ci
npm run build
cd deploy/demo && ./setup.sh && docker compose up --build
# open deploy/demo/data/wrhs-demo-launcher.html in your browser
```

For a real deployment, see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Development

```bash
npm ci
npm run typecheck
npm test               # unit + end-to-end tests (no Docker needed)
npm run build          # builds the launcher (packages/client/dist) and the agent bundle (dist/agent)
npm run test:browser   # optional; needs Playwright + Chromium
```

The TypeScript runs directly on Node ≥ 22.18 (type stripping), so there is no
server build step. The end-to-end tests run the whole stack (client code,
relay, agent, and a fake guacd) through a man-in-the-middle proxy that
records every byte. They check that none of the secrets appear in what the
proxy saw, that tampering kills the session, that an impostor agent is
rejected before credentials are sent, and that sessions survive the proxy
cutting connections. CI also runs everything on Windows, and signs in from
Chromium to a Windows runner's own Remote Desktop through the installed
agent service.

## Status

This is a new project. The protocol is built from standard parts (Noise,
ML-KEM, ChaCha20-Poly1305), but this implementation has **not had an
independent security review yet**. Read the
[threat model](docs/THREAT_MODEL.md), especially the residual risks, before
relying on it.

WRHS protects the confidentiality of your session. It does not hide that you
are using it. Follow the policies of networks you connect from.

## License

No license has been chosen for WRHS itself yet. The vendored
guacamole-common-js is © The Apache Software Foundation, under the Apache
License 2.0 (see `packages/client/vendor/guacamole-common-js`). IronRDP
(`@devolutions/iron-remote-desktop-rdp`) is © Devolutions, under MIT or
Apache 2.0. WinSW, downloaded by the Windows installer, is under MIT.
