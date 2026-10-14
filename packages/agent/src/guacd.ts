// Minimal guacd client: performs the Guacamole protocol handshake for an RDP
// connection and then hands back the raw socket. After the handshake the
// agent only copies bytes; guacd (FreeRDP) does all RDP work, and the
// browser renders with the official guacamole-common-js client.

import { connect, type Socket } from 'node:net';

/** Guacamole element lengths are counted in Unicode code points. */
function cpLength(s: string): number {
  let n = 0;
  for (const _ of s) n++;
  return n;
}

export function encodeInstruction(elements: string[]): string {
  return elements.map((e) => `${cpLength(e)}.${e}`).join(',') + ';';
}

/**
 * Parse complete instructions from the front of a string. `ends[i]` is the
 * string index just past instruction i; `consumed` is the last of those.
 */
export function parseInstructions(data: string): { instructions: string[][]; ends: number[]; consumed: number } {
  const instructions: string[][] = [];
  const ends: number[] = [];
  let pos = 0;
  let start = 0;
  let current: string[] = [];
  while (pos < data.length) {
    const dot = data.indexOf('.', pos);
    if (dot < 0) break;
    const lenStr = data.slice(pos, dot);
    if (!/^\d{1,8}$/.test(lenStr)) throw new Error('malformed Guacamole instruction');
    const len = Number(lenStr);
    let end = dot + 1;
    for (let i = 0; i < len; i++) {
      if (end >= data.length) return { instructions, ends, consumed: start };
      end += data.codePointAt(end)! > 0xffff ? 2 : 1;
    }
    if (end >= data.length) return { instructions, ends, consumed: start };
    current.push(data.slice(dot + 1, end));
    const term = data[end];
    if (term === ',') {
      pos = end + 1;
    } else if (term === ';') {
      instructions.push(current);
      current = [];
      pos = end + 1;
      start = pos;
      ends.push(pos);
    } else {
      throw new Error('malformed Guacamole instruction');
    }
  }
  return { instructions, ends, consumed: start };
}

export interface GuacdConnectOptions {
  host: string;
  port: number;
  protocol: 'rdp';
  /** Connection parameters by name (hostname, port, username, ...). */
  params: Record<string, string>;
  width: number;
  height: number;
  dpi: number;
  timezone?: string;
  timeoutMs?: number;
}

const KNOWN_VERSIONS = new Set(['VERSION_1_0_0', 'VERSION_1_1_0', 'VERSION_1_3_0', 'VERSION_1_5_0']);

export interface GuacdConnection {
  socket: Socket;
  /** Bytes received after "ready" that belong to the client. */
  leftover: Buffer;
  connectionId: string;
}

export function connectGuacd(o: GuacdConnectOptions): Promise<GuacdConnection> {
  return new Promise((resolve, reject) => {
    const socket = connect({ host: o.host, port: o.port });
    let buf = Buffer.alloc(0);
    let phase: 'args' | 'ready' = 'args';
    const timer = setTimeout(() => fail(new Error('guacd handshake timed out')), o.timeoutMs ?? 15_000);

    function fail(err: Error) {
      clearTimeout(timer);
      socket.removeAllListeners('data');
      socket.destroy();
      reject(err);
    }

    const send = (...elements: string[]) => socket.write(encodeInstruction(elements));

    socket.once('connect', () => send('select', o.protocol));
    socket.on('error', (err) => fail(new Error(`guacd: ${err.message}`)));
    socket.on('close', () => fail(new Error('guacd closed the connection during handshake')));

    socket.on('data', (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length > 1024 * 1024) return fail(new Error('guacd handshake too large'));
      // A trailing partial UTF-8 sequence may decode to U+FFFD, but it sits
      // after the last complete instruction, so it never affects parsing.
      const text = buf.toString('utf8');
      let parsed;
      try {
        parsed = parseInstructions(text);
      } catch (err) {
        return fail(err as Error);
      }
      for (let i = 0; i < parsed.instructions.length; i++) {
        const [opcode, ...args] = parsed.instructions[i]!;
        if (opcode === 'error') return fail(new Error(`guacd error: ${args[0] ?? 'unknown'}`));
        if (phase === 'args' && opcode === 'args') {
          const values = args.map((name, idx) => {
            if (idx === 0 && name.startsWith('VERSION_')) return KNOWN_VERSIONS.has(name) ? name : 'VERSION_1_5_0';
            return o.params[name] ?? '';
          });
          send('size', String(o.width), String(o.height), String(o.dpi));
          send('audio', 'audio/L16', 'audio/L8');
          send('video');
          send('image', 'image/png', 'image/jpeg', 'image/webp');
          if (o.timezone) send('timezone', o.timezone);
          send('connect', ...values);
          phase = 'ready';
          continue;
        }
        if (phase === 'ready' && opcode === 'ready') {
          // Everything after this instruction belongs to the browser.
          const consumedBytes = Buffer.byteLength(text.slice(0, parsed.ends[i]), 'utf8');
          clearTimeout(timer);
          socket.removeAllListeners('data');
          socket.removeAllListeners('close');
          socket.removeAllListeners('error');
          socket.pause();
          resolve({ socket, leftover: buf.subarray(consumedBytes), connectionId: args[0] ?? '' });
          return;
        }
      }
    });
  });
}

/** Map a target definition to guacd RDP parameters. */
export function rdpParams(t: {
  hostname: string;
  port?: number;
  domain?: string;
  username?: string;
  password?: string;
  security?: string;
  ignoreCert?: boolean;
  clipboard?: 'both' | 'copy' | 'paste' | 'none';
  fileTransfer?: boolean;
  audio?: boolean;
  extraParams?: Record<string, string>;
}, size: { width: number; height: number; dpi: number }): Record<string, string> {
  const clipboard = t.clipboard ?? 'both';
  const p: Record<string, string> = {
    hostname: t.hostname,
    port: String(t.port ?? 3389),
    domain: t.domain ?? '',
    username: t.username ?? '',
    password: t.password ?? '',
    security: t.security ?? 'any',
    'ignore-cert': t.ignoreCert ? 'true' : 'false',
    width: String(size.width),
    height: String(size.height),
    dpi: String(size.dpi),
    'resize-method': 'display-update',
    'disable-copy': clipboard === 'both' || clipboard === 'copy' ? 'false' : 'true',
    'disable-paste': clipboard === 'both' || clipboard === 'paste' ? 'false' : 'true',
    'disable-audio': t.audio === false ? 'true' : 'false',
    'enable-drive': t.fileTransfer ? 'true' : 'false',
    'disable-download': t.fileTransfer ? 'false' : 'true',
    'disable-upload': t.fileTransfer ? 'false' : 'true',
    'enable-printing': 'false',
    'enable-wallpaper': 'false',
    'enable-font-smoothing': 'true',
  };
  return { ...p, ...(t.extraParams ?? {}) };
}
