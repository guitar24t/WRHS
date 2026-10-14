// WRHS browser client.
//
// This file is bundled, together with the vendored guacamole-common-js, into
// a single self-contained HTML file. Nothing is loaded from the network
// except encrypted frames, so a launcher opened from disk cannot be altered
// by a proxy in transit.

import Guacamole from '../vendor/guacamole-common-js/guacamole-common.js';
import {
  AppChannel,
  AuthError,
  ClientConnection,
  IntegrityError,
  PinMismatchError,
  RelayError,
  decodeKey,
  fingerprint,
  type ConnectionState,
  type SecureSession,
  type SessionOptions,
  type TargetInfo,
  type KeyPair,
} from '@wrhs/protocol';
import { createEncryptedTunnel } from './tunnel.ts';
import { loadDeviceKey } from './device-key.ts';

interface LauncherConfig {
  relayUrl?: string;
  agentKeys?: string[];
  name?: string;
  hosted?: boolean;
}

const SOFTWARE = 'wrhs-web/0.1.0';

const CLIENT_SESSION_OPTIONS: SessionOptions = {
  // While typing, send on a fixed 20 ms grid with padded chaff so the proxy
  // cannot recover keystroke timing.
  cadence: { intervalMs: 20, holdMs: 1500, minPlaintext: 256, followPeer: false },
};

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;

const config: LauncherConfig = (() => {
  try {
    return JSON.parse($('wrhs-config').textContent || '{}') as LauncherConfig;
  } catch {
    return {};
  }
})();

let deviceKey: KeyPair | null = null;
let conn: ClientConnection | null = null;
let app: AppChannel | null = null;
let session: SecureSession | null = null;
let guac: GuacClient | null = null;
let pendingTarget: TargetInfo | null = null;
let agentName = '';

const views = ['view-connect', 'view-login', 'view-targets', 'view-closed', 'remote'] as const;
function show(view: (typeof views)[number]): void {
  for (const v of views) $(v).hidden = v !== view;
}

function message(id: string, text: string | null, kind: 'error' | 'warn' | '' = 'error'): void {
  const el = $(id);
  el.hidden = !text;
  el.textContent = text ?? '';
  el.className = `msg ${kind}`;
}

function security(kind: 'ok' | 'warn' | 'bad', text: string): void {
  const badge = $('security');
  badge.className = `badge ${kind}`;
  $('security-text').textContent = text;
}

function storage(): Storage | null {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------ setup

function initConnectView(): void {
  if (config.hosted) $('hosted-banner').hidden = false;
  const keys = config.agentKeys ?? [];
  if (config.relayUrl && keys.length > 0) {
    $('profile').hidden = false;
    $('profile-name').textContent = config.name ?? 'Remote agent';
    $('profile-relay').textContent = new URL(config.relayUrl).host;
    try {
      $('profile-fp').textContent = fingerprint(decodeKey(keys[0]!));
    } catch {
      $('profile-fp').textContent = 'invalid key in launcher';
    }
  } else {
    $('manual').hidden = false;
    const s = storage();
    $<HTMLInputElement>('relay-url').value = s?.getItem('wrhs.relay') ?? (config.hosted ? location.origin : '');
    $<HTMLInputElement>('agent-key').value = s?.getItem('wrhs.agentKey') ?? '';
  }
  show('view-connect');
}

function resolveTarget(): { relayUrl: string; keys: Uint8Array[] } {
  if (config.relayUrl && config.agentKeys?.length) {
    return { relayUrl: config.relayUrl, keys: config.agentKeys.map(decodeKey) };
  }
  const relayUrl = $<HTMLInputElement>('relay-url').value.trim();
  const key = $<HTMLInputElement>('agent-key').value.trim();
  const u = new URL(relayUrl);
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(u.hostname))) {
    throw new Error('The relay URL must use https://');
  }
  const keys = [decodeKey(key)];
  storage()?.setItem('wrhs.relay', relayUrl);
  storage()?.setItem('wrhs.agentKey', key);
  return { relayUrl, keys };
}

// ------------------------------------------------------------------ connect

async function connect(): Promise<void> {
  message('connect-msg', null);
  let target;
  try {
    target = resolveTarget();
  } catch (err) {
    return message('connect-msg', (err as Error).message);
  }
  const btn = $<HTMLButtonElement>('connect-btn');
  btn.disabled = true;
  security('warn', 'Connecting…');
  if (!deviceKey) {
    const d = await loadDeviceKey();
    deviceKey = d.key;
    showDevice(d.persistent);
  }
  conn = new ClientConnection({
    relayUrl: target.relayUrl,
    agentPublicKeys: target.keys,
    deviceKey,
    software: SOFTWARE,
    session: CLIENT_SESSION_OPTIONS,
  });
  conn.on('state', onConnectionState);
  conn.on('transport', () => updateDetails());
  try {
    session = await conn.open();
  } catch (err) {
    btn.disabled = false;
    return failConnect(err as Error);
  }
  btn.disabled = false;
  agentName = conn.agentHello?.name ?? 'agent';
  updateDetails();
  session.on('rtt', () => updateDetails());
  session.on('close', (info) => onSessionClosed(info.reason, info.error));
  app = new AppChannel(session);
  app.on('control', (m) => {
    if (m.t === 'closed') {
      stopRemote();
      show('view-targets');
      message('targets-msg', m.message, 'warn');
    }
  });
  const methods = await app.authMethods();
  $('totp-row').hidden = !methods.includes('password+totp');
  show('view-login');
  $('user').focus();
}

function showDevice(persistent: boolean): void {
  if (!deviceKey) return;
  $('device').textContent = `This device: ${fingerprint(deviceKey.publicKey)}${persistent ? '' : ' (temporary key)'}`;
}

function failConnect(err: Error): void {
  if (err instanceof PinMismatchError) {
    security('bad', 'Identity check failed');
    showClosed(
      'Possible interception detected',
      'The server did not prove it is your agent (its key does not match the one pinned in this launcher). ' +
        'Someone on the network may be trying to intercept the connection. Nothing was sent. ' +
        'Do not retry from this network until you have checked with your administrator.',
    );
    return;
  }
  security('warn', 'Not connected');
  const text =
    err instanceof RelayError && err.code === 'agent-offline'
      ? 'The agent is not connected to the relay right now.'
      : `Could not connect: ${err.message}`;
  message('connect-msg', text);
}

function onConnectionState(state: ConnectionState, detail?: string): void {
  if (state === 'open') security('ok', `End-to-end encrypted to ${conn?.agentHello?.name ?? agentName ?? 'agent'}`);
  else if (state === 'reconnecting') security('warn', 'Reconnecting… (session preserved)');
  else if (state === 'handshaking') security('warn', 'Verifying agent identity…');
  updateDetails(detail);
}

function updateDetails(detail?: string): void {
  if (!conn) return;
  const parts: string[] = [];
  if (session) parts.push(`agent ${fingerprint(session.remoteStatic)}`);
  parts.push('Noise XXhfs · X25519 + ML-KEM-768');
  if (conn.transportKind) parts.push(conn.transportKind === 'websocket' ? 'WebSocket' : 'HTTPS long-poll');
  if (session?.rttMs != null) parts.push(`${Math.round(session.rttMs)} ms`);
  if (detail && conn.state === 'reconnecting') parts.push(detail);
  $('details').textContent = parts.join(' · ');
}

function onSessionClosed(reason: string, error?: Error): void {
  stopRemote();
  if (error instanceof IntegrityError) {
    security('bad', 'Tampering detected');
    showClosed(
      'Connection terminated: traffic was modified',
      'Data arriving from the network failed its integrity check, which means something between you and the agent ' +
        'altered it. The session was closed to protect you; nothing altered was used.',
    );
    return;
  }
  security('warn', 'Disconnected');
  showClosed('Disconnected', reason);
}

function showClosed(title: string, text: string): void {
  $('closed-title').textContent = title;
  message('closed-msg', text, 'warn');
  show('view-closed');
}

// ------------------------------------------------------------------ login

async function login(ev: SubmitEvent): Promise<void> {
  ev.preventDefault();
  if (!app) return;
  message('login-msg', null);
  const user = $<HTMLInputElement>('user').value.trim();
  const pw = $<HTMLInputElement>('password');
  const totp = $<HTMLInputElement>('totp').value.trim();
  try {
    const targets = await app.login(user, pw.value, totp || undefined);
    pw.value = '';
    renderTargets(targets);
    show('view-targets');
  } catch (err) {
    pw.value = '';
    $<HTMLInputElement>('totp').value = '';
    const e = err as Error;
    const extra = err instanceof AuthError && err.retryAfterMs ? ` Try again in ${Math.ceil(err.retryAfterMs / 1000)} s.` : '';
    message('login-msg', `${e.message}.${extra}`);
  }
}

function renderTargets(targets: TargetInfo[]): void {
  const list = $('target-list');
  list.replaceChildren();
  if (targets.length === 0) message('targets-msg', 'No desktops are assigned to your account.', 'warn');
  for (const t of targets) {
    const li = document.createElement('li');
    const b = document.createElement('button');
    b.type = 'button';
    const proto = document.createElement('span');
    proto.className = 'proto';
    proto.textContent = t.protocol;
    b.append(proto, document.createTextNode(t.name));
    b.addEventListener('click', () => chooseTarget(t));
    li.append(b);
    list.append(li);
  }
}

function chooseTarget(t: TargetInfo): void {
  message('targets-msg', null);
  if (t.promptCredentials) {
    pendingTarget = t;
    $('creds-target').textContent = t.name;
    $('rdp-creds').hidden = false;
    $('rdp-user').focus();
    return;
  }
  void openTarget(t);
}

async function openTarget(t: TargetInfo, credentials?: { username?: string; password?: string; domain?: string }): Promise<void> {
  if (!app) return;
  show('remote');
  const el = $('display');
  const density = window.devicePixelRatio || 1;
  try {
    await app.open({
      target: t.id,
      width: Math.round(el.clientWidth * density),
      height: Math.round(el.clientHeight * density),
      dpi: Math.round(96 * density),
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      ...(credentials ? { credentials } : {}),
    });
  } catch (err) {
    show('view-targets');
    message('targets-msg', (err as Error).message);
    return;
  }
  startRemote();
}

// ------------------------------------------------------------------ remote desktop

let keyboard: GuacKeyboard | null = null;
let resizeTimer: ReturnType<typeof setTimeout> | null = null;

function startRemote(): void {
  if (!app || !session) return;
  const s = session;
  const container = $('display');
  const client = new Guacamole.Client(createEncryptedTunnel(app));
  guac = client;
  const display = client.getDisplay();
  container.replaceChildren(display.getElement());

  const fit = () => {
    const w = display.getWidth();
    const h = display.getHeight();
    if (!w || !h) return;
    display.scale(Math.min(container.clientWidth / w, container.clientHeight / h));
  };
  display.onresize = fit;

  client.onerror = (status) => {
    stopRemote();
    show('view-targets');
    message('targets-msg', `Remote desktop error: ${status.message ?? status.code}`);
  };
  client.onclipboard = (stream, mimetype) => {
    if (!/^text\//.test(mimetype)) return;
    const reader = new Guacamole.StringReader(stream);
    let text = '';
    reader.ontext = (t) => (text += t);
    reader.onend = () => void navigator.clipboard?.writeText(text).catch(() => {});
  };

  const mouse = new Guacamole.Mouse(display.getElement());
  mouse.onEach(['mousedown', 'mouseup', 'mousemove'], (e) => client.sendMouseState(e.state, true));

  keyboard ??= new Guacamole.Keyboard(container);
  keyboard.onkeydown = (keysym) => {
    s.markInteractive();
    guac?.sendKeyEvent(1, keysym);
    return false;
  };
  keyboard.onkeyup = (keysym) => {
    s.markInteractive();
    guac?.sendKeyEvent(0, keysym);
  };

  client.connect();
  container.focus();
  container.addEventListener('mousedown', () => container.focus());
  fit();
}

function stopRemote(): void {
  if (keyboard) {
    keyboard.onkeydown = null;
    keyboard.onkeyup = null;
    keyboard.reset();
  }
  guac?.disconnect();
  guac = null;
  $('display').replaceChildren();
}

function onDisplayResize(): void {
  if (!guac) return;
  if (resizeTimer) clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => {
    const el = $('display');
    const density = window.devicePixelRatio || 1;
    guac?.sendSize(Math.round(el.clientWidth * density), Math.round(el.clientHeight * density));
    const d = guac?.getDisplay();
    if (d && d.getWidth()) d.scale(Math.min(el.clientWidth / d.getWidth(), el.clientHeight / d.getHeight()));
  }, 250);
}

function sendCtrlAltDel(): void {
  const keys = [0xffe3, 0xffe9, 0xffff];
  for (const k of keys) guac?.sendKeyEvent(1, k);
  for (const k of keys.reverse()) guac?.sendKeyEvent(0, k);
}

async function sendClipboard(): Promise<void> {
  if (!guac) return;
  let text: string | null = null;
  try {
    text = await navigator.clipboard.readText();
  } catch {
    text = window.prompt('Text to send to the remote clipboard:');
  }
  if (!text) return;
  const writer = new Guacamole.StringWriter(guac.createClipboardStream('text/plain'));
  writer.sendText(text);
  writer.sendEnd();
  $('display').focus();
}

// ------------------------------------------------------------------ wiring

$('connect-btn').addEventListener('click', () => void connect());
$('manual').addEventListener('submit', (e) => {
  e.preventDefault();
  void connect();
});
$('login-form').addEventListener('submit', (e) => void login(e as SubmitEvent));
$('rdp-creds').addEventListener('submit', (e) => {
  e.preventDefault();
  const t = pendingTarget;
  if (!t) return;
  const pass = $<HTMLInputElement>('rdp-pass');
  const creds = {
    username: $<HTMLInputElement>('rdp-user').value,
    password: pass.value,
    domain: $<HTMLInputElement>('rdp-domain').value,
  };
  pass.value = '';
  $('rdp-creds').hidden = true;
  void openTarget(t, creds);
});
$('disconnect-btn').addEventListener('click', () => conn?.close('disconnected by user'));
$('cad-btn').addEventListener('click', sendCtrlAltDel);
$('paste-btn').addEventListener('click', () => void sendClipboard());
$('full-btn').addEventListener('click', () => void $('remote').requestFullscreen?.().catch(() => {}));
$('reconnect-btn').addEventListener('click', () => {
  conn = null;
  app = null;
  session = null;
  $('details').textContent = '';
  security('warn', 'Not connected');
  initConnectView();
});
new ResizeObserver(onDisplayResize).observe($('display'));
window.addEventListener('beforeunload', () => conn?.close('page closed'));

initConnectView();
void loadDeviceKey().then((d) => {
  deviceKey ??= d.key;
  showDevice(d.persistent);
});
