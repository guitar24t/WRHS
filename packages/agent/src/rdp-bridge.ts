// Opens an RDP connection on behalf of the browser (the gateway half of
// RDCleanPath) and returns the stream to relay afterwards.
//
// Typical use on Windows: the agent connects to the PC's own Remote Desktop
// service on a loopback address, so the browser gets a real RDP session of
// that PC (the local console locks, exactly as with mstsc).

import { connect, type Socket } from 'node:net';
import { connect as tlsConnect, type DetailedPeerCertificate, type TLSSocket } from 'node:tls';
import {
  GENERAL_ERROR,
  NEGOTIATION_ERROR,
  RDCLEANPATH_VERSION,
  encodeRdCleanPath,
  type RdCleanPathPdu,
} from './rdcleanpath.ts';

export interface RdpEndpoint {
  host: string;
  port: number;
}

export interface RdpBridge {
  /** Encoded RDCleanPath response to send to the browser. */
  response: Uint8Array;
  /**
   * Stream to relay after the response, or null if the attempt failed. It may
   * be paused: call resume() once the data listener is attached.
   */
  stream: Socket | TLSSocket | null;
  /** Protocol the server selected (0 RDP, 1 TLS, 2 CredSSP, 8 CredSSP+EarlyUserAuth). */
  selectedProtocol?: number;
  /** SHA-256 fingerprint (hex) of the server certificate, when TLS was used. */
  certSha256?: string;
  error?: string;
}

const PROTOCOL_SSL = 0x1;
const PROTOCOL_HYBRID = 0x2;
const PROTOCOL_HYBRID_EX = 0x8;

const WSA_ERRORS: Record<string, number> = {
  ECONNREFUSED: 10061,
  ETIMEDOUT: 10060,
  EHOSTUNREACH: 10065,
  ENETUNREACH: 10051,
  ECONNRESET: 10054,
  ENOTFOUND: 11001,
};

function failure(error: string, wsaLastError?: number): RdpBridge {
  return {
    response: encodeRdCleanPath({
      version: RDCLEANPATH_VERSION,
      error: { errorCode: GENERAL_ERROR, ...(wsaLastError !== undefined ? { wsaLastError } : {}) },
    }),
    stream: null,
    error,
  };
}

/** Reads exactly one TPKT-framed PDU (the X.224 Connection Confirm). */
function readTpkt(socket: Socket, timeoutMs: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => done(new Error('timed out waiting for the RDP server')), timeoutMs);
    const done = (err: Error | null, pdu?: Buffer) => {
      clearTimeout(timer);
      socket.off('data', onData);
      socket.off('error', onError);
      socket.off('close', onClose);
      if (err) reject(err);
      else resolve(pdu!);
    };
    const onData = (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length < 4) return;
      if (buf[0] !== 3) return done(new Error('RDP server sent an invalid response'));
      const len = buf.readUInt16BE(2);
      if (len < 11 || len > 1024) return done(new Error('RDP server sent an invalid response'));
      if (buf.length < len) return;
      // Nothing else is expected before the client speaks again.
      socket.pause();
      if (buf.length > len) socket.unshift(buf.subarray(len));
      done(null, buf.subarray(0, len));
    };
    const onError = (err: Error) => done(err);
    const onClose = () => done(new Error('RDP server closed the connection'));
    socket.on('data', onData);
    socket.on('error', onError);
    socket.on('close', onClose);
    socket.resume();
  });
}

/** Parses the RDP negotiation part of an X.224 Connection Confirm. */
export function parseConnectionConfirm(pdu: Uint8Array): { failure: boolean; protocol: number } {
  // TPKT (4) + X.224 CC header (7) + RDP_NEG_RSP/FAILURE (8)
  if (pdu.length < 11 || (pdu[5]! & 0xf0) !== 0xd0) throw new Error('not an X.224 Connection Confirm');
  if (pdu.length < 19) return { failure: false, protocol: 0 }; // no negotiation data: standard RDP security
  const type = pdu[11]!;
  const value = new DataView(pdu.buffer, pdu.byteOffset, pdu.byteLength).getUint32(15, true);
  if (type === 0x03) return { failure: true, protocol: value };
  return { failure: false, protocol: value };
}

function certChain(tls: TLSSocket): Uint8Array[] {
  const chain: Uint8Array[] = [];
  let cert: DetailedPeerCertificate | undefined = tls.getPeerCertificate(true);
  const seen = new Set<string>();
  while (cert?.raw && !seen.has(cert.fingerprint256)) {
    seen.add(cert.fingerprint256);
    chain.push(new Uint8Array(cert.raw));
    cert = cert.issuerCertificate;
  }
  return chain;
}

/** Opens the TCP connection to the RDP server. Rejects with a Node error (with `code`). */
export function connectRdpServer(target: RdpEndpoint, timeoutMs = 15_000): Promise<Socket> {
  return new Promise<Socket>((resolve, reject) => {
    const s = connect({ host: target.host, port: target.port });
    const timer = setTimeout(() => {
      s.destroy();
      reject(Object.assign(new Error('connection timed out'), { code: 'ETIMEDOUT' }));
    }, timeoutMs);
    s.once('connect', () => {
      clearTimeout(timer);
      // From here on an error is followed by 'close', which callers watch.
      s.removeAllListeners('error');
      s.on('error', () => {});
      s.setNoDelay(true);
      resolve(s);
    });
    s.once('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

/** RDCleanPath answer for a server that could not be reached. */
export function unreachable(target: RdpEndpoint, err: Error): RdpBridge {
  const code = (err as NodeJS.ErrnoException).code ?? '';
  return failure(`cannot reach ${target.host}:${target.port}: ${err.message}`, WSA_ERRORS[code]);
}

/** Checks that `pdu` is one TPKT-framed X.224 Connection Request. */
export function isConnectionRequest(pdu: Uint8Array): boolean {
  return (
    pdu.length >= 11 &&
    pdu[0] === 3 &&
    ((pdu[2]! << 8) | pdu[3]!) === pdu.length &&
    pdu[4] === pdu.length - 5 &&
    (pdu[5]! & 0xf0) === 0xe0
  );
}

/** Normalizes a certificate fingerprint ("AB:CD:..." or hex) for comparison. */
export function normalizeFingerprint(fp: string): string {
  return fp.replace(/[^0-9a-f]/gi, '').toLowerCase();
}

export interface NegotiateOptions {
  timeoutMs?: number;
  /** Expected SHA-256 fingerprint of the RDP server's certificate; any certificate if absent. */
  certSha256?: string;
}

/**
 * Runs the gateway half of RDCleanPath on an open connection to the RDP
 * server: forwards the browser's X.224 Connection Request, reads the
 * Confirm, and does the TLS handshake the server selected.
 *
 * `socket` is consumed: on failure it is destroyed, on success the returned
 * stream (the socket itself, or TLS on top of it) carries the session.
 */
export async function negotiateRdp(request: RdCleanPathPdu, socket: Socket, o: NegotiateOptions = {}): Promise<RdpBridge> {
  const timeoutMs = o.timeoutMs ?? 15_000;
  if (request.version !== RDCLEANPATH_VERSION) {
    socket.destroy();
    return failure(`unsupported RDCleanPath version ${request.version}`);
  }
  if (!request.x224 || !isConnectionRequest(request.x224)) {
    socket.destroy();
    return failure('missing or invalid X.224 connection request');
  }
  const serverAddr = `${socket.remoteAddress}:${socket.remotePort}`;

  // 1. Forward the browser's X.224 Connection Request; read the Confirm.
  let confirm: Buffer;
  let negotiated: { failure: boolean; protocol: number };
  try {
    socket.write(request.x224);
    confirm = await readTpkt(socket, timeoutMs);
    negotiated = parseConnectionConfirm(confirm);
  } catch (err) {
    socket.destroy();
    return failure((err as Error).message);
  }
  if (negotiated.failure) {
    socket.destroy();
    return {
      response: encodeRdCleanPath({
        version: RDCLEANPATH_VERSION,
        error: { errorCode: NEGOTIATION_ERROR },
        x224: new Uint8Array(confirm),
      }),
      stream: null,
      error: `RDP negotiation failed (code ${negotiated.protocol})`,
    };
  }

  const usesTls = (negotiated.protocol & (PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX)) !== 0;
  if (!usesTls) {
    // Standard RDP security: no TLS layer, nothing to hand over.
    return {
      response: encodeRdCleanPath({
        version: RDCLEANPATH_VERSION,
        x224: new Uint8Array(confirm),
        serverCertChain: [],
        serverAddr,
      }),
      stream: socket,
      selectedProtocol: negotiated.protocol,
    };
  }

  // 2. TLS with the RDP server. Its certificate is usually self-signed. The
  // browser binds CredSSP to the key reported here, so a substitute key is
  // caught there; pinning the fingerprint also stops a machine between the
  // agent and the server from collecting NTLM responses.
  let tls: TLSSocket;
  try {
    tls = await new Promise<TLSSocket>((resolve, reject) => {
      const t = tlsConnect({ socket, rejectUnauthorized: false });
      const timer = setTimeout(() => {
        t.destroy();
        reject(new Error('TLS handshake with the RDP server timed out'));
      }, timeoutMs);
      t.once('secureConnect', () => {
        clearTimeout(timer);
        t.removeAllListeners('error');
        t.on('error', () => {});
        resolve(t);
      });
      t.once('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });
  } catch (err) {
    socket.destroy();
    return failure(`TLS with the RDP server failed: ${(err as Error).message}`);
  }
  const chain = certChain(tls);
  const leaf = tls.getPeerCertificate();
  const fingerprint = leaf?.fingerprint256 ? normalizeFingerprint(leaf.fingerprint256) : '';
  if (o.certSha256 && normalizeFingerprint(o.certSha256) !== fingerprint) {
    tls.destroy();
    return { ...failure(`RDP server certificate ${fingerprint || '(none)'} does not match the pinned fingerprint`), certSha256: fingerprint };
  }
  tls.setNoDelay(true);
  return {
    response: encodeRdCleanPath({
      version: RDCLEANPATH_VERSION,
      x224: new Uint8Array(confirm),
      serverCertChain: chain,
      serverAddr,
    }),
    stream: tls,
    selectedProtocol: negotiated.protocol,
    certSha256: fingerprint,
  };
}

/** Connects to the RDP server and runs {@link negotiateRdp}. */
export async function openRdpBridge(request: RdCleanPathPdu, target: RdpEndpoint, o: NegotiateOptions = {}): Promise<RdpBridge> {
  let socket: Socket;
  try {
    socket = await connectRdpServer(target, o.timeoutMs);
  } catch (err) {
    return unreachable(target, err as Error);
  }
  return negotiateRdp(request, socket, o);
}
