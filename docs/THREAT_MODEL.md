# Threat model

## Assets

| Asset | Examples |
|---|---|
| Session content | Screen pixels, keystrokes, mouse input, clipboard, audio |
| User credentials | WRHS password, TOTP codes, RDP user name and password |
| Infrastructure details | Internal hostnames, target names, user names |
| Keys | Agent static key, device keys, session keys |
| Access | The ability to drive a desktop on the private network |

## Trust boundaries

```
 [browser + launcher] ==outer TLS==> [proxy] ==TLS==> [relay] <==TLS== [agent] --RDP/TLS--> [RDP host]
  trusted                             untrusted        untrusted         trusted (your network;
  \___________________________ Noise session (end to end) ____________________/   loopback for "This PC")
```

With the built-in engine, the RDP client runs in the launcher and the agent
terminates the RDP server's TLS: the RDP stream between them travels inside
the Noise session. With the guacd engine, guacd sits between the agent and
the RDP host instead.

The launcher file is trusted *if it was obtained over a trusted channel*.
The hosted page is not, because it arrives through the proxy (see
[DESIGN.md §4](DESIGN.md#4-the-hard-part-trusting-the-code-in-the-browser)).

## Adversaries

| Id | Adversary | Capabilities |
|---|---|---|
| A1 | Passive inspecting proxy | Decrypts the outer TLS; logs and archives everything |
| A2 | Active inspecting proxy | A1, plus modifies, injects, replays, drops, or impersonates any server (including the relay) |
| A3 | Malicious or compromised relay | Full control of the relay process and its host |
| A4 | Internet attacker | Can reach the relay, open sessions, guess passwords |
| A5 | Future quantum adversary | Can break X25519 in traffic archived today |
| A6 | Thief of a launcher file | Holds a copy of a user's launcher |
| A7 | Compromised client endpoint | Malware, keylogger or screen capture on the client device, or a hostile browser extension |

## Attacks and mitigations

| # | Attack | Adversary | Mitigation | Verified by |
|---|---|---|---|---|
| 1 | Read screen, keystrokes or credentials from intercepted HTTPS | A1, A2, A3 | All content is inside the Noise session (ChaCha20-Poly1305). Credentials are sent only after the agent is authenticated. | `e2e.test.ts` "proxy sees no secrets" (WebSocket and long-poll), `launcher.test.ts` (real Chromium) |
| 2 | Archive traffic, decrypt it later with a quantum computer | A5 | Hybrid X25519 + ML-KEM-768 (Noise HFS). Ephemeral keys only, so forward secrecy holds. | `noise.test.ts` |
| 3 | Impersonate the agent (MITM the inner handshake) | A2, A3 | The client checks the agent static key against the pin before sending handshake message 3. On mismatch it aborts, sends nothing more, and warns the user. | `e2e.test.ts` "active MITM posing as the agent" |
| 4 | Modify, inject or reorder records | A2, A3 | AEAD on every record (header as associated data), explicit sequence numbers, and a fatal integrity error shown to the user. | `session.test.ts`, `e2e.test.ts` "proxy that modifies traffic" |
| 5 | Replay records or a whole session | A2, A3 | Fresh ephemerals per session. In-session sequence numbers reject duplicates. Unreliable records need strictly increasing counters. | `session.test.ts` "duplicated and replayed" |
| 6 | Replace the JavaScript the user runs | A2 | Offline launcher: code is opened from disk and locked by a hash-based CSP. Hosted mode is labelled "passive protection only". | Design (§4); CSP checked in `launcher.test.ts` |
| 7 | Infer typed text from keystroke timing | A1, A2, A3 | Cadence mode: fixed 20 ms grid, equal-size records, padded chaff; the agent follows to hide echo. | `session.test.ts` "cadence mode" |
| 8 | Infer activity from record sizes | A1, A2, A3 | Bucketed padding. Small messages are indistinguishable. Large screen updates are still visible in aggregate (residual). | `e2e.test.ts` "fixed-size records" |
| 9 | Learn internal names from URLs or headers | A1, A2 | URLs contain only a random session id and a pseudonymous agent id. Target names and hosts travel inside the session. | `e2e.test.ts` (searches all captured bytes) |
| 10 | Online password guessing | A4 | TOTP, scrypt, per-account lockout, 3 attempts per session, flattened timing, per-IP session creation limits at the relay. | `agent.test.ts`, `e2e.test.ts` "wrong password" |
| 11 | Reuse an observed TOTP code | A4 | Codes are never observable on the wire (#1). Each time step is also accepted once per user. | `e2e.test.ts` "TOTP replay" |
| 12 | Register as someone else's agent at the relay | A4 | Per-agent registration tokens. Even without them, an impostor cannot complete the handshake (#3); it only causes denial of service. | Design |
| 13 | Hijack a relay session id seen in a URL | A1, A2 | Gains only the ability to drop or garble frames, which the proxy can already do. Every frame is authenticated end to end. | Design |
| 14 | Downgrade the cipher or protocol | A2 | No negotiation: one fixed protocol name, version in the prologue and hellos. | Design |
| 15 | Use a stolen launcher | A6 | The launcher contains only *public* data (relay URL, agent public key). Logging in still needs password + TOTP (and an enrolled device key if configured). | Design |
| 16 | Exploit the agent from the internet | A4 | The agent has no listening ports. Before the handshake completes it parses only Noise messages. After that, it parses only authenticated JSON, with length checks on credentials and message sizes capped by the record layer. Unauthenticated sessions time out (30 s handshake, 120 s login). | Code review |
| 17 | Abuse a session to move laterally | Authenticated user | Per-user target lists. The agent connects only to configured targets and ignores the destination the browser's RDP client names. Clipboard and file transfer policy: enforced by guacd for guacd targets, and by the RDP host's own Group Policy for built-in targets. Idle and maximum session timeouts. Audit log of logins and targets. | `agent.test.ts`, `rdp-engine.test.ts` |
| 18 | Reach the PC's Remote Desktop directly, around WRHS | Network attacker | The Windows installer blocks the RDP port from the network; the agent connects over loopback. NLA is required. | `install.ps1`, Windows CI job |
| 19 | Pose as an RDP host between the agent and a LAN target, to collect NTLM responses | Attacker on the agent's LAN | "This PC" uses loopback. For other hosts, pin the server certificate (`certSha256`); CredSSP in the browser is also bound to the certificate the agent reports, so a substitute server cannot relay the sign-in. | `rdp.test.ts` "pinned certificate" |
| 20 | Make the browser's RDP client connect elsewhere | A2, A3 | The client's WebSocket is replaced at build time by a socket over the Noise session, which accepts only addresses handed out by the client itself; the CSP allows no other connections. | `rdp.test.ts` (browser) |

## Residual risks and limitations

- **Compromised client (A7).** Out of scope. A keylogger or screen recorder
  on the client sees everything the user sees. On a device managed by the
  organization that runs the proxy, assume they can see the screen.
- **First contact.** The pin is only as good as the channel the launcher
  arrived through. Do not download it through the proxy you are trying to
  protect against, unless you check its SHA-256 out of band.
- **Hosted mode** protects against passive inspection only.
- **Metadata.** Relay hostname, timing, duration and coarse volume are
  visible (see [DESIGN.md §10](DESIGN.md#10-what-a-proxy-can-still-learn)).
- **Denial of service.** The proxy, the relay operator, or anyone who learns
  a user name can block access, or trigger the temporary account lockout.
  Lockouts expire (5 minutes by default).
- **Device key storage.** The device key is stored in IndexedDB as raw
  bytes. Other pages in the same origin could read it, and for `file://`
  that can mean other local HTML files in some browsers. It is a secondary
  factor (password + TOTP are still required); moving to non-extractable
  WebCrypto keys is on the roadmap.
- **Browser and dependency bugs.** The client relies on the browser's
  sandbox and on the code it bundles: noble, guacamole-common-js, and
  IronRDP (WebAssembly). Running WebAssembly needs `'wasm-unsafe-eval'` in
  the CSP; it allows compiling only the module the page itself provides,
  not JavaScript `eval`. All dependencies are pinned to exact versions.
- **RDP credentials in the browser.** With the built-in engine the user
  types the remote computer's password into the launcher, which runs NLA
  itself. It is protected like the WRHS password (never on the wire outside
  the Noise session, and inside RDP's own CredSSP), but a compromised
  client sees it (A7).
- **The agent's privileges.** On Windows the agent runs as LocalService and
  can read its own configuration, which holds password hashes, TOTP secrets
  and the identity key. Administrators of the PC can read it too.
- **No independent audit yet.** The protocol uses standard constructions
  (Noise, ML-KEM, ChaCha20-Poly1305), but this implementation has not been
  reviewed by a third party.
