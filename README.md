# WRHS: web remote desktop that the proxy cannot read

WRHS lets you use your remote desktop (RDP) from a web browser on networks
you don't trust, including networks whose proxy **decrypts HTTPS**.

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
 Browser (offline launcher) ──HTTPS──▶ [intercepting proxy] ──HTTPS──▶ Relay ◀──HTTPS── Agent ── guacd ── RDP host
        ╰──────────────── Noise XXhfs: end-to-end encrypted, agent key pinned ───────────────╯
```

Inside the tunnel, WRHS reuses proven parts: Apache Guacamole's `guacd`
(FreeRDP) speaks RDP, and the official `guacamole-common-js` renders the
desktop in the browser.

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
- Per-user target lists, and per-target clipboard, file-transfer and audio
  policy, enforced in guacd.
- Audit log of handshakes, logins, desktops opened, and tampering.

## Repository layout

| Path | What |
|---|---|
| `packages/protocol` | Noise XXhfs handshake, encrypted record layer, transports, client connection logic (shared by browser and Node) |
| `packages/relay` | Blind relay server (WebSocket + long-poll) |
| `packages/agent` | Agent: authentication, policy, guacd bridge, `wrhs-agent` CLI, launcher generator |
| `packages/client` | Browser client, built into a single HTML file; vendored guacamole-common-js 1.6.0 |
| `test/e2e` | End-to-end tests through a logging and tampering MITM proxy |
| `test/browser` | Real-Chromium test of the `file://` launcher (needs Playwright) |
| `deploy/` | Docker Compose for the relay (with Caddy), the agent (with guacd), and a local demo |
| `docs/` | [Design](docs/DESIGN.md), [threat model](docs/THREAT_MODEL.md), [protocol spec](docs/PROTOCOL.md), [deployment](docs/DEPLOYMENT.md) |

## Quick start (local demo)

Requirements: Node.js ≥ 22.18 and Docker.

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
npm run build          # builds packages/client/dist/*.html
npm run test:browser   # optional; needs Playwright + Chromium
```

The TypeScript runs directly on Node ≥ 22.18 (type stripping), so there is no
server build step. The end-to-end tests run the whole stack (client code,
relay, agent, and a fake guacd) through a man-in-the-middle proxy that
records every byte. They check that none of the secrets appear in what the
proxy saw, that tampering kills the session, that an impostor agent is
rejected before credentials are sent, and that sessions survive the proxy
cutting connections.

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
License 2.0 (see `packages/client/vendor/guacamole-common-js`).
