// RDCleanPath: the small protocol IronRDP's browser client uses to ask a
// gateway (here: the agent) to open an RDP connection on its behalf.
//
// The browser sends one request carrying its X.224 Connection Request. The
// gateway connects to the RDP server, forwards that PDU, performs the TLS
// handshake itself and answers with the server's X.224 Connection Confirm
// and certificate chain. After that the gateway relays the plaintext RDP
// stream; the browser does CredSSP/NLA itself, bound to the server's key.
//
// Wire format: one DER-encoded ASN.1 SEQUENCE with EXPLICIT context tags
// (see IronRDP crates/ironrdp-rdcleanpath):
//
//   RDCleanPathPdu ::= SEQUENCE {
//     version            [0] INTEGER,          -- 3390
//     error              [1] RDCleanPathErr OPTIONAL,
//     destination        [2] UTF8String OPTIONAL,
//     proxy_auth         [3] UTF8String OPTIONAL,
//     server_auth        [4] UTF8String OPTIONAL,
//     preconnection_blob [5] UTF8String OPTIONAL,
//     x224_connection_pdu[6] OCTET STRING OPTIONAL,
//     server_cert_chain  [7] SEQUENCE OF OCTET STRING OPTIONAL,
//     server_addr        [9] UTF8String OPTIONAL }
//   RDCleanPathErr ::= SEQUENCE {
//     error_code [0] INTEGER, http_status_code [1] INTEGER OPTIONAL,
//     wsa_last_error [2] INTEGER OPTIONAL, tls_alert_code [3] INTEGER OPTIONAL }

export const RDCLEANPATH_VERSION = 3390;
export const GENERAL_ERROR = 1;
export const NEGOTIATION_ERROR = 2;

export interface RdCleanPathError {
  errorCode: number;
  httpStatusCode?: number;
  wsaLastError?: number;
  tlsAlertCode?: number;
}

export interface RdCleanPathPdu {
  version: number;
  error?: RdCleanPathError;
  destination?: string;
  proxyAuth?: string;
  serverAuth?: string;
  preconnectionBlob?: string;
  x224?: Uint8Array;
  serverCertChain?: Uint8Array[];
  serverAddr?: string;
}

// ------------------------------------------------------------------ DER

const TAG_INTEGER = 0x02;
const TAG_OCTET_STRING = 0x04;
const TAG_UTF8 = 0x0c;
const TAG_SEQUENCE = 0x30;
const ctx = (n: number) => 0xa0 | n;

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function encLength(n: number): Uint8Array {
  if (n < 0x80) return Uint8Array.of(n);
  const bytes: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

function tlv(tag: number, value: Uint8Array): Uint8Array {
  return concat([Uint8Array.of(tag), encLength(value.length), value]);
}

function encInteger(n: number): Uint8Array {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error('only non-negative integers are supported');
  const bytes: number[] = [];
  let v = n;
  do {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  } while (v > 0);
  if (bytes[0]! & 0x80) bytes.unshift(0);
  return tlv(TAG_INTEGER, Uint8Array.from(bytes));
}

const encUtf8 = (s: string) => tlv(TAG_UTF8, new TextEncoder().encode(s));

interface Node {
  tag: number;
  value: Uint8Array;
}

/** Reads one TLV at `off`; returns it and the offset just past it. */
function readTlv(buf: Uint8Array, off: number): { node: Node; next: number } {
  if (off + 2 > buf.length) throw new Error('DER: truncated');
  const tag = buf[off]!;
  let len = buf[off + 1]!;
  let p = off + 2;
  if (len & 0x80) {
    const count = len & 0x7f;
    if (count === 0 || count > 4 || p + count > buf.length) throw new Error('DER: bad length');
    len = 0;
    for (let i = 0; i < count; i++) len = len * 256 + buf[p++]!;
  }
  if (p + len > buf.length) throw new Error('DER: truncated value');
  return { node: { tag, value: buf.subarray(p, p + len) }, next: p + len };
}

function children(value: Uint8Array): Node[] {
  const out: Node[] = [];
  for (let off = 0; off < value.length; ) {
    const { node, next } = readTlv(value, off);
    out.push(node);
    off = next;
  }
  return out;
}

function expect(node: Node, tag: number, what: string): Uint8Array {
  if (node.tag !== tag) throw new Error(`DER: expected ${what}`);
  return node.value;
}

function decInteger(node: Node): number {
  const v = expect(node, TAG_INTEGER, 'INTEGER');
  if (v.length === 0 || v.length > 7 || v[0]! & 0x80) throw new Error('DER: unsupported INTEGER');
  let n = 0;
  for (const b of v) n = n * 256 + b;
  return n;
}

/** The single value inside an EXPLICIT [n] wrapper. */
function explicit(node: Node): Node {
  const inner = children(node.value);
  if (inner.length !== 1) throw new Error('DER: bad explicit tag');
  return inner[0]!;
}

// ------------------------------------------------------------------ PDU codec

export function encodeRdCleanPath(p: RdCleanPathPdu): Uint8Array {
  const fields: Uint8Array[] = [tlv(ctx(0), encInteger(p.version))];
  if (p.error) {
    const e = p.error;
    const errFields = [tlv(ctx(0), encInteger(e.errorCode))];
    if (e.httpStatusCode !== undefined) errFields.push(tlv(ctx(1), encInteger(e.httpStatusCode)));
    if (e.wsaLastError !== undefined) errFields.push(tlv(ctx(2), encInteger(e.wsaLastError)));
    if (e.tlsAlertCode !== undefined) errFields.push(tlv(ctx(3), encInteger(e.tlsAlertCode)));
    fields.push(tlv(ctx(1), tlv(TAG_SEQUENCE, concat(errFields))));
  }
  if (p.destination !== undefined) fields.push(tlv(ctx(2), encUtf8(p.destination)));
  if (p.proxyAuth !== undefined) fields.push(tlv(ctx(3), encUtf8(p.proxyAuth)));
  if (p.serverAuth !== undefined) fields.push(tlv(ctx(4), encUtf8(p.serverAuth)));
  if (p.preconnectionBlob !== undefined) fields.push(tlv(ctx(5), encUtf8(p.preconnectionBlob)));
  if (p.x224 !== undefined) fields.push(tlv(ctx(6), tlv(TAG_OCTET_STRING, p.x224)));
  if (p.serverCertChain !== undefined) {
    fields.push(tlv(ctx(7), tlv(TAG_SEQUENCE, concat(p.serverCertChain.map((c) => tlv(TAG_OCTET_STRING, c))))));
  }
  if (p.serverAddr !== undefined) fields.push(tlv(ctx(9), encUtf8(p.serverAddr)));
  return tlv(TAG_SEQUENCE, concat(fields));
}

export function decodeRdCleanPath(buf: Uint8Array): RdCleanPathPdu {
  const { node, next } = readTlv(buf, 0);
  if (next !== buf.length) throw new Error('DER: trailing data');
  const out: RdCleanPathPdu = { version: 0 };
  const utf8 = (n: Node) => new TextDecoder('utf-8', { fatal: true }).decode(expect(explicit(n), TAG_UTF8, 'UTF8String'));
  for (const f of children(expect(node, TAG_SEQUENCE, 'SEQUENCE'))) {
    switch (f.tag) {
      case ctx(0):
        out.version = decInteger(explicit(f));
        break;
      case ctx(1): {
        const e: RdCleanPathError = { errorCode: 0 };
        for (const ef of children(expect(explicit(f), TAG_SEQUENCE, 'SEQUENCE'))) {
          const v = decInteger(explicit(ef));
          if (ef.tag === ctx(0)) e.errorCode = v;
          else if (ef.tag === ctx(1)) e.httpStatusCode = v;
          else if (ef.tag === ctx(2)) e.wsaLastError = v;
          else if (ef.tag === ctx(3)) e.tlsAlertCode = v;
        }
        out.error = e;
        break;
      }
      case ctx(2):
        out.destination = utf8(f);
        break;
      case ctx(3):
        out.proxyAuth = utf8(f);
        break;
      case ctx(4):
        out.serverAuth = utf8(f);
        break;
      case ctx(5):
        out.preconnectionBlob = utf8(f);
        break;
      case ctx(6):
        out.x224 = expect(explicit(f), TAG_OCTET_STRING, 'OCTET STRING').slice();
        break;
      case ctx(7):
        out.serverCertChain = children(expect(explicit(f), TAG_SEQUENCE, 'SEQUENCE')).map((c) =>
          expect(c, TAG_OCTET_STRING, 'OCTET STRING').slice(),
        );
        break;
      case ctx(9):
        out.serverAddr = utf8(f);
        break;
      default:
        break; // unknown optional field
    }
  }
  return out;
}

/**
 * Total length of the DER PDU at the start of `buf` once its header is
 * complete, or null if more bytes are needed.
 */
export function rdCleanPathLength(buf: Uint8Array): number | null {
  if (buf.length < 2) return null;
  if (buf[0] !== TAG_SEQUENCE) throw new Error('not an RDCleanPath PDU');
  const first = buf[1]!;
  if (!(first & 0x80)) return 2 + first;
  const count = first & 0x7f;
  if (count === 0 || count > 4) throw new Error('not an RDCleanPath PDU');
  if (buf.length < 2 + count) return null;
  let len = 0;
  for (let i = 0; i < count; i++) len = len * 256 + buf[2 + i]!;
  return 2 + count + len;
}
