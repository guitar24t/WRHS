# WRHS wire protocol, version 1

This document specifies the bytes on the wire. The reference implementation
is `packages/protocol`. All integers are big-endian unless noted otherwise.

## 1. Layers

```
+-------------------------------------------------------------+
| Application: control (JSON) | Guacamole or RDP stream       |
+-------------------------------------------------------------+
| Record layer: reliability, padding, channels, cadence       |  end to end
+-------------------------------------------------------------+
| Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256 handshake      |  end to end
+-------------------------------------------------------------+
| Frames over WebSocket or HTTPS long-poll (via relay)        |  hop by hop
+-------------------------------------------------------------+
| TLS (may be intercepted)                                    |  hop by hop
+-------------------------------------------------------------+
```

## 2. Frames

A *frame* is one WebSocket binary message, or one entry in a long-poll
batch. The first byte is the frame type:

| Type | Name | Direction | Seen by relay as |
|---|---|---|---|
| `0x00` | Relay control | relay → endpoint | UTF-8 JSON it generates itself |
| `0x01` | HS1 | client → agent | opaque |
| `0x02` | HS2 | agent → client | opaque |
| `0x03` | HS3 | client → agent | opaque |
| `0x10` | Record | both | opaque |

The relay forwards every frame whose first byte is not `0x00`, unchanged.
It drops `0x00` frames sent by endpoints. Maximum frame size: 71,680 bytes.

### Relay control messages (`0x00` + JSON)

```json
{"t":"session","sid":"<base64url, 18 random bytes>"}
{"t":"ready"}
{"t":"peer-gone"}
{"t":"error","code":"agent-offline|unknown-session|rate-limited|busy|bad-request|session-closed","message":"..."}
```

These messages are **not** authenticated end to end. Clients use them only
as hints: `ready` starts the handshake or resumes a session, `peer-gone`
pauses it, and `error` fails it. None of them can make a client send
plaintext or skip a check.

## 3. Outer transports

### Browser side

| Transport | Request | Notes |
|---|---|---|
| WebSocket (new) | `GET /v1/client/ws?agent=<agentId>` (Upgrade) | The relay sends `session`, then `ready` once the agent has joined |
| WebSocket (resume) | `GET /v1/client/ws?sid=<sid>` | Same session; the relay asks the agent to resync |
| Long-poll open | `POST /v1/lp/open` body `{"agent":"<agentId>"}` or `{"sid":"<sid>"}` | Response `{"sid":"..."}` |
| Long-poll send | `POST /v1/lp/<sid>/tx` body = batch | `204` |
| Long-poll receive | `POST /v1/lp/<sid>/rx` | `200` + batch, or `204` after about 25 s without data |

A *batch* is `[u32 length][frame]` repeated. Every response carries
`Cache-Control: no-store`. CORS allows any origin, because there are no
ambient credentials. A client picks WebSocket first and falls back to
long-poll if no relay frame arrives within the timeout.

### Agent side

| Channel | Request |
|---|---|
| Control | `GET /v1/agent/control?agent=<agentId>` (Upgrade), `Authorization: Bearer <relayToken>` |
| Session data | `GET /v1/agent/session/<sid>` (Upgrade), same bearer token |

The relay sends text messages on the control socket: `{"t":"open","sid":"..."}`.
On a data socket it may send the text message `{"t":"client-attached"}`.
Closing a data socket with code `4000` ends the session at the relay.

`relayToken` authorizes routing only. The relay stores
`SHA-256(relayToken)` per agent id.

## 4. Identities

- Agent static key: X25519, 32 bytes, encoded as unpadded base64url in
  configs and launchers.
- `agentId = hex(SHA-256("wrhs-agent-id:" || agentPublicKey)[0..16])`, which
  gives 32 hex characters.
- Display fingerprint:
  `upper(hex(SHA-256("wrhs-fingerprint:" || publicKey)[0..12]))`, in groups of
  4 joined by `-`.
- Device key: X25519 key generated per browser profile and used as the Noise
  initiator static key.

## 5. Handshake

Protocol name: `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256`. The prologue
is the ASCII string `WRHS/1`.

```
XXhfs:
  -> e, e1
  <- e, ee, ekem1, s, es
  -> s, se
```

- Noise revision 34, with SHA-256 as HASH and ChaCha20-Poly1305 (IETF,
  96-bit nonce = 32 zero bits + 64-bit little-endian counter).
- HFS tokens, with ML-KEM-768 (FIPS 203) as the KEM:
  - `e1`: generate a KEM key pair, write `EncryptAndHash(e1.pub)` (1184
    bytes, plus 16 if a key is set).
  - `ekem1`: `(ct, ss) = Encaps(re1)`, write `EncryptAndHash(ct)` (1088
    bytes + 16), then `MixKey(ss)`. The reader calls
    `Decaps(ct, e1.priv)` and then `MixKey`.
- Payloads:
  - HS1: empty.
  - HS2: `AgentHello` JSON `{"v":1,"name":"...","software":"..."}`.
  - HS3: `ClientHello` JSON `{"v":1,"software":"..."}`.
- **Pin check:** after reading HS2, the client compares the responder static
  key `rs` with its pinned keys. If none matches, it aborts and sends nothing
  further.
- `Split()`: the initiator sends with `c1` and the responder sends with `c2`.

## 6. Record layer

### Packet

```
0      1                9                                   N
+------+----------------+-----------------------------------+
| 0x10 | nonce (u64 BE) | ChaCha20-Poly1305(k, nonce, ad, plaintext) |
+------+----------------+-----------------------------------+
ad = bytes 0..9 (type + nonce)
```

- Bit 63 of `nonce` = 0: a **reliable** record, and `nonce` is its sequence
  number (0, 1, 2, …).
- Bit 63 = 1: an **unreliable** record. Its counter is `nonce & (2^63-1)` and
  must strictly increase.
- The AEAD nonce is the 64-bit `nonce`, encoded as in Noise (§5).

### Plaintext

```
0       1       2         3      4              12        16          16+len
+-------+-------+---------+------+--------------+---------+-----------+---------+
| kind  | flags | channel | 0x00 | ack (u64 BE) | len u32 | payload   | 0x00... |
+-------+-------+---------+------+--------------+---------+-----------+---------+
```

| kind | Name | Space | Meaning |
|---|---|---|---|
| 1 | DATA | reliable | Application data for `channel` |
| 2 | NOOP | reliable | Chaff (cadence mode) |
| 3 | CLOSE | reliable | Close; payload = UTF-8 reason |
| 4 | ACK | unreliable | Ack only |
| 5 | PING | unreliable | Payload = sender time (u64 ms) |
| 6 | PONG | unreliable | Echo of the PING payload |

| flag | Meaning |
|---|---|
| `0x01` MORE | The message continues in the next DATA record on this channel |
| `0x02` CADENCE | The sender's user is typing; the receiver may pace its own output |
| `0x04` GAP | (ACK) sent because the receiver saw a sequence gap or a duplicate |

- `ack` is the cumulative count of reliable records received in order (the
  next expected sequence number).
- **Padding:** the plaintext length is padded up to a multiple of 128 bytes
  (lengths up to 512), 512 (up to 4096), or 2048 (above that), with a
  minimum set by cadence mode. The maximum DATA payload per record is
  16 KiB.

### Rules

1. **Sender.** Seal each reliable record once and keep the sealed bytes
   until it is acknowledged. Retransmit those exact bytes: never re-encrypt
   under a nonce that was already used.
2. **Retransmission.** On RTO, or on an ACK with the GAP flag, go back N
   (retransmit all unacknowledged records). The RTO is `srtt + 4·rttvar +
   ackDelay`, clamped to [1 s, 30 s], and doubles on each timeout.
3. **Receiver, reliable records:**
   - `seq == next`: decrypt, process, then deliver any buffered successors.
   - `seq > next` (within 4096): decrypt and buffer.
   - Anything else: drop.
   - After a duplicate or a gap, send a GAP ACK at once. Otherwise send an
     ACK after 40 ms unless a record carrying the ack goes out first.
4. **Integrity.** Any authentication failure, an ack for an unsent record,
   or a malformed plaintext is fatal. The receiver sends a best-effort CLOSE
   and reports tampering.
5. **Resumption.** When a new outer connection attaches, both sides
   retransmit everything unacknowledged and send an ACK. A session with no
   outer connection for 120 s is closed.
6. **Cadence.** While active (1.5 s after the last local keystroke, or after
   a peer record flagged CADENCE), queued records leave only on 20 ms ticks.
   Idle ticks send a NOOP. Every record is padded to at least 256 bytes
   (client) or 2048 bytes (agent).

## 7. Application protocol

### Channel 1: control (JSON, one message per DATA message)

| Direction | Message |
|---|---|
| agent → client | `{"t":"auth-required","methods":["password+totp"]}` |
| client → agent | `{"t":"auth","user":"alice","password":"...","totp":"123456"}` |
| agent → client | `{"t":"auth-ok","targets":[{"id":"this-pc","name":"This PC (DESK)","protocol":"rdp","engine":"rdp","promptCredentials":true,"username":"alice"}],"limits":{"idleTimeoutSeconds":3600,"maxSessionSeconds":43200}}` |
| agent → client | `{"t":"auth-fail","message":"invalid credentials","attemptsLeft":2,"retryAfterMs":120000}` |
| client → agent | `{"t":"open","ref":3,"target":"desk","width":1920,"height":1080,"dpi":96,"timezone":"Europe/Berlin","credentials":{"username":"...","password":"...","domain":"..."}}` (`credentials` only for guacd targets) |
| agent → client | `{"t":"open-ok","ref":3,"engine":"rdp"}` / `{"t":"open-fail","message":"...","ref":3}` |
| client → agent | `{"t":"close-desktop"}`: end the current desktop but stay signed in (no reply) |
| agent → client | `{"t":"closed","message":"remote desktop disconnected","ref":3}`: the desktop ended on the remote side |

`ref` is chosen by the client (increasing per session) and echoed back, so a
`closed` notice for an earlier desktop can never close a newer one. An `open`
while a desktop is active replaces it; the replaced desktop gets no `closed`
notice. The agent always answers `open` with `open-ok` or `open-fail`.

Targets name their `engine`: `rdp` (built-in: the browser runs the RDP
client, channel 3) or `guacd` (channel 2). Older agents omit it, meaning
`guacd`. For `rdp` targets, `promptCredentials` means Network Level
Authentication is on, so the client asks for the remote computer's
credentials and uses them itself; `username` and `domain` are suggestions
for that prompt. For `guacd` targets, the client sends typed credentials in
`open`, and `promptCredentials` is false when the agent has stored ones.

### Channel 2: Guacamole

This channel carries the raw Guacamole protocol byte stream (UTF-8) after
the guacd handshake, which the agent performs. Message boundaries carry no
meaning. Client-to-agent messages contain whole instructions.

### Channel 3: RDP (built-in engine)

After `open-ok` with `engine: "rdp"`, the agent holds an open TCP connection
to the target's RDP server and waits (30 s) for the client's RDP client
(IronRDP) to start:

1. Client → agent: one **RDCleanPath** request, a DER-encoded
   `RDCleanPathPdu` (version 3390; see IronRDP's `ironrdp-rdcleanpath`)
   carrying the client's X.224 Connection Request. The agent ignores the
   request's `destination` and `proxy_auth`: the target was chosen with
   `open`, and the session is already authenticated.
2. The agent forwards the X.224 request to the server and reads its
   Connection Confirm. If the server selected TLS or CredSSP, the agent
   performs the TLS handshake (checking `certSha256` if the target pins
   one).
3. Agent → client: one RDCleanPath response: the server's X.224 Confirm, its
   certificate chain and address, or an error (`GENERAL_ERROR` with a WSA
   code, `NEGOTIATION_ERROR` with the server's Confirm).
4. From then on the channel carries the plaintext RDP byte stream in both
   directions; the agent encrypts it with the server's TLS. The client
   performs CredSSP (NLA) itself, bound to the certificate from step 3.
   Message boundaries carry no meaning; the client keeps each message under
   32 KiB.

When the server closes the connection the agent sends `closed`. After a
failed step 3 it sends nothing further: the client's RDP client reports the
reason, and the agent is ready for the next `open`. Client-to-server
fast-path PDUs (input) count as activity for the idle timeout.
