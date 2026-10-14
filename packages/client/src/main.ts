// WRHS browser client.
//
// This file is bundled, together with the RDP client (IronRDP, WebAssembly)
// and the vendored guacamole-common-js, into a single self-contained HTML
// file. Nothing is loaded from the network except encrypted frames, so a
// launcher opened from disk cannot be altered by a proxy in transit.

import {
  AppChannel,
  ClientConnection,
  decodeKey,
  fingerprint,
  type ConnectionState,
  type KeyPair,
  type SecureSession,
  type SessionOptions,
  type TargetInfo,
} from '@wrhs/protocol';
import { loadDeviceKey } from './device-key.ts';
import { remoteSize, type DesktopView, type RemoteElements } from './desktop-common.ts';
import { GuacamoleDesktop } from './guac-view.ts';
import { RdpDesktop, loadRdpEngine } from './rdp-view.ts';
import {
  describeAuthError,
  describeClose,
  describeConnectError,
  describeKeyError,
  describeRelayUrlError,
  formatCountdown,
  type Notice,
  type Tone,
} from './messages.ts';

interface LauncherConfig {
  relayUrl?: string;
  agentKeys?: string[];
  name?: string;
  hosted?: boolean;
}

const SOFTWARE = 'wrhs-web/0.2.0';

const CLIENT_SESSION_OPTIONS: SessionOptions = {
  // While typing, send on a fixed 20 ms grid with padded chaff so the proxy
  // cannot recover keystroke timing.
  cadence: { intervalMs: 20, holdMs: 1500, minPlaintext: 256, followPeer: false },
};

const IDLE_WARNING_MS = 60_000;
const MAX_SESSION_WARNING_MS = 5 * 60_000;

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const input = (id: string) => $<HTMLInputElement>(id);

const config: LauncherConfig = (() => {
  try {
    return JSON.parse($('wrhs-config').textContent || '{}') as LauncherConfig;
  } catch {
    return {};
  }
})();

// ------------------------------------------------------------------ state

let deviceKey: KeyPair | null = null;
let devicePersistent = false;
let conn: ClientConnection | null = null;
let app: AppChannel | null = null;
let session: SecureSession | null = null;
let remote: DesktopView | null = null;
let targets: TargetInfo[] = [];
let pendingTarget: TargetInfo | null = null;
/** Desktop that ended unexpectedly, offered for one-click reopening. */
let reopenTarget: TargetInfo | null = null;
/** True while a desktop is open (or opening) from the user's point of view. */
let desktopActive = false;
let closedShown = false;
let relayHost = '';
let connectedAt = 0;
let lastRemoteInput = 0;
let sessionTimer: ReturnType<typeof setInterval> | null = null;

// ------------------------------------------------------------------ helpers

const VIEWS = ['view-connect', 'view-login', 'view-targets', 'view-closed', 'remote'] as const;
type View = (typeof VIEWS)[number];
let currentView: View = 'view-connect';

function show(view: View, focus?: HTMLElement | null): void {
  currentView = view;
  for (const v of VIEWS) $(v).hidden = v !== view;
  const target = focus ?? $(view).querySelector<HTMLElement>('h1');
  target?.focus();
}

function message(id: string, text: string | null, tone: Tone = 'error'): void {
  const el = $(id);
  el.className = `msg ${tone}`;
  el.textContent = text ?? '';
}

function badge(kind: 'ok' | 'warn' | 'bad', short: string, long = ''): void {
  $('security').className = `badge ${kind}`;
  const t = $('security-text');
  t.replaceChildren(document.createTextNode(short));
  if (long) {
    const span = document.createElement('span');
    span.className = 'long';
    span.textContent = long;
    t.append(span);
  }
}

function title(state: string): void {
  document.title = `${state} · WRHS`;
}

function storage(): Storage | null {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

let toastTimer: ReturnType<typeof setTimeout> | null = null;
function toast(text: string): void {
  const el = $('toast');
  el.textContent = text;
  el.hidden = false;
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (el.hidden = true), 4000);
}

function agentLabel(): string {
  return conn?.agentHello?.name || config.name || 'your agent';
}

// ------------------------------------------------------------------ connect view

function initConnectView(): void {
  if (config.hosted) $('hosted-banner').hidden = false;
  resetHeader();
  badge('warn', 'Not connected');
  title(config.name ?? 'Connect');
  const keys = config.agentKeys ?? [];
  if (config.relayUrl && keys.length > 0) {
    $('profile').hidden = false;
    $('profile-name').textContent = config.name ?? 'Remote agent';
    $('profile-relay').textContent = new URL(config.relayUrl).host;
    try {
      $('profile-fp').textContent = fingerprint(decodeKey(keys[0]!));
    } catch {
      $('profile-fp').textContent = 'invalid key in this launcher';
    }
    show('view-connect', $('connect-btn'));
  } else {
    $('manual').hidden = false;
    const s = storage();
    if (!input('relay-url').value) input('relay-url').value = s?.getItem('wrhs.relay') ?? (config.hosted ? location.origin : '');
    if (!input('agent-key').value) input('agent-key').value = s?.getItem('wrhs.agentKey') ?? '';
    previewKeyFingerprint();
    show('view-connect', input('relay-url').value ? $('connect-btn') : input('relay-url'));
  }
}

/** Show the fingerprint of a pasted key so it can be checked against the admin's copy. */
function previewKeyFingerprint(): void {
  const raw = input('agent-key').value.trim();
  const hint = $('agent-key-fp');
  if (!raw) {
    hint.textContent = '';
    return;
  }
  try {
    hint.textContent = `Key fingerprint ${fingerprint(decodeKey(raw))}. Check it matches the one your administrator gave you.`;
  } catch {
    hint.textContent = 'Not a complete agent key yet.';
  }
}

function invalid(field: HTMLInputElement, text: string): null {
  field.setAttribute('aria-invalid', 'true');
  message('connect-msg', text);
  field.focus();
  return null;
}

function resolveTarget(): { relayUrl: string; keys: Uint8Array[] } | null {
  if (config.relayUrl && config.agentKeys?.length) {
    return { relayUrl: config.relayUrl, keys: config.agentKeys.map(decodeKey) };
  }
  const urlField = input('relay-url');
  const keyField = input('agent-key');
  urlField.removeAttribute('aria-invalid');
  keyField.removeAttribute('aria-invalid');
  const relayUrl = urlField.value.trim();
  let u: URL;
  try {
    u = new URL(relayUrl);
  } catch {
    return invalid(urlField, describeRelayUrlError(relayUrl));
  }
  const local = ['localhost', '127.0.0.1'].includes(u.hostname);
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && local)) return invalid(urlField, describeRelayUrlError(relayUrl));
  let key: Uint8Array;
  try {
    key = decodeKey(keyField.value);
  } catch {
    return invalid(keyField, describeKeyError());
  }
  storage()?.setItem('wrhs.relay', relayUrl);
  storage()?.setItem('wrhs.agentKey', keyField.value.trim());
  return { relayUrl, keys: [key] };
}

async function connect(): Promise<void> {
  message('connect-msg', null);
  const target = resolveTarget();
  if (!target) return;
  relayHost = new URL(target.relayUrl).host;
  const btn = $<HTMLButtonElement>('connect-btn');
  btn.disabled = true;
  btn.textContent = 'Connecting…';
  badge('warn', 'Connecting…');
  title('Connecting…');
  closedShown = false;
  if (!deviceKey) await ensureDeviceKey();
  conn = new ClientConnection({
    relayUrl: target.relayUrl,
    agentPublicKeys: target.keys,
    deviceKey: deviceKey!,
    software: SOFTWARE,
    session: CLIENT_SESSION_OPTIONS,
  });
  conn.on('state', onConnectionState);
  conn.on('transport', () => refreshDetails());
  try {
    session = await conn.open();
  } catch (err) {
    btn.disabled = false;
    btn.textContent = 'Connect';
    return failConnect(err as Error);
  }
  btn.disabled = false;
  btn.textContent = 'Connect';
  connectedAt = lastRemoteInput = Date.now();
  session.on('rtt', () => refreshDetails());
  session.on('close', (info) => onSessionClosed(info.reason, info.error, false));
  app = new AppChannel(session);
  app.on('control', (m) => {
    // Ignore notices about a desktop that was already closed or replaced.
    if (m.t !== 'closed' || (m.ref !== undefined && m.ref !== app?.lastOpenRef)) return;
    if (remote?.remoteClosed) remote.remoteClosed();
    else onRemoteEnded();
  });
  $('signout-btn').hidden = false;
  $('details-btn').hidden = false;
  refreshDetails();
  let methods: string[];
  try {
    methods = await app.authMethods();
  } catch {
    return; // session closed; onSessionClosed shows why
  }
  const needsTotp = methods.includes('password+totp');
  $('totp-row').hidden = !needsTotp;
  input('totp').required = needsTotp;
  message('login-msg', null);
  const savedUser = storage()?.getItem('wrhs.user') ?? '';
  if (savedUser && !input('user').value) input('user').value = savedUser;
  show('view-login', input('user').value ? input('password') : input('user'));
  title(`Sign in · ${agentLabel()}`);
  startSessionTimer();
}

let deviceKeyLoad: Promise<void> | null = null;

/** Load (or create) this browser's device key exactly once. */
function ensureDeviceKey(): Promise<void> {
  deviceKeyLoad ??= loadDeviceKey().then((d) => {
    deviceKey = d.key;
    devicePersistent = d.persistent;
    showDeviceKey();
  });
  return deviceKeyLoad;
}

function showDeviceKey(): void {
  if (!deviceKey) return;
  const text = `${fingerprint(deviceKey.publicKey)}${devicePersistent ? '' : ' (temporary: this browser cannot store it)'}`;
  $('device').textContent = text;
  $('d-device').textContent = text;
}

function failConnect(err: Error): void {
  const result = describeConnectError(err, relayHost);
  conn = null;
  session = null;
  if (typeof result === 'string') {
    badge('warn', 'Not connected');
    title('Not connected');
    message('connect-msg', result);
    return;
  }
  badge('bad', 'Identity check failed');
  showClosed(result);
}

function onConnectionState(state: ConnectionState): void {
  switch (state) {
    case 'connecting':
      badge('warn', 'Connecting…');
      break;
    case 'handshaking':
      badge('warn', 'Verifying agent…');
      break;
    case 'open':
      badge('ok', 'Encrypted', ` to ${agentLabel()}`);
      $('reconnect-overlay').hidden = true;
      if (currentView === 'remote') title(`${reopenTarget?.name ?? 'Desktop'} · ${agentLabel()}`);
      break;
    case 'reconnecting':
      badge('warn', 'Reconnecting…');
      if (currentView === 'remote') $('reconnect-overlay').hidden = false;
      title('Reconnecting…');
      break;
    case 'closed':
      break;
  }
  refreshDetails();
}

// ------------------------------------------------------------------ header

function resetHeader(): void {
  $('signout-btn').hidden = true;
  $('details-btn').hidden = true;
  toggleDetails(false);
  $('session-banner').hidden = true;
}

function refreshDetails(): void {
  $('d-agent').textContent = agentLabel();
  $('d-fp').textContent = session ? fingerprint(session.remoteStatic) : '';
  $('d-transport').textContent =
    conn?.transportKind === 'websocket' ? 'WebSocket over HTTPS' : conn?.transportKind === 'longpoll' ? 'HTTPS long-polling' : '';
  $('d-rtt').textContent = session?.rttMs != null ? `${Math.round(session.rttMs)} ms` : 'measuring…';
}

function toggleDetails(open?: boolean): void {
  const btn = $('details-btn');
  const next = open ?? btn.getAttribute('aria-expanded') !== 'true';
  btn.setAttribute('aria-expanded', String(next));
  $('details-panel').hidden = !next;
  if (next) refreshDetails();
}

// ------------------------------------------------------------------ sign in

async function login(ev: SubmitEvent): Promise<void> {
  ev.preventDefault();
  if (!app) return;
  message('login-msg', null);
  const userField = input('user');
  const pw = input('password');
  const totpField = input('totp');
  const user = userField.value.trim();
  const code = totpField.value.replace(/\s+/g, '');
  if (!user) return void (message('login-msg', 'Enter your user name.'), userField.focus());
  if (!pw.value) return void (message('login-msg', 'Enter your password.'), pw.focus());
  if (totpField.required && !/^\d{6}$/.test(code)) {
    totpField.setAttribute('aria-invalid', 'true');
    message('login-msg', 'Enter the 6-digit code from your authenticator app.');
    totpField.focus();
    return;
  }
  totpField.removeAttribute('aria-invalid');
  const btn = $<HTMLButtonElement>('login-btn');
  btn.disabled = true;
  btn.textContent = 'Signing in…';
  try {
    targets = await app.login(user, pw.value, code || undefined);
    storage()?.setItem('wrhs.user', user);
    pw.value = '';
    totpField.value = '';
    renderTargets();
    showTargets(targets.length ? null : 'No desktops are assigned to your account. Ask your administrator.', 'warn');
    // Compile the RDP client while the user picks a desktop.
    if (targets.some((t) => t.engine === 'rdp')) void loadRdpEngine().catch(() => {});
  } catch (err) {
    pw.value = '';
    totpField.value = '';
    if (session?.closed || closedShown) return;
    message('login-msg', describeAuthError(err));
    pw.focus();
  } finally {
    btn.disabled = false;
    btn.textContent = 'Sign in';
  }
}

// ------------------------------------------------------------------ desktop list

function renderTargets(): void {
  const list = $('target-list');
  list.replaceChildren();
  for (const t of targets) {
    const li = document.createElement('li');
    const b = document.createElement('button');
    b.type = 'button';
    b.dataset.target = t.id;
    b.setAttribute('aria-pressed', 'false');
    const name = document.createElement('span');
    name.className = 'name';
    name.textContent = t.name;
    const proto = document.createElement('span');
    proto.className = 'proto';
    proto.textContent = t.protocol;
    b.append(name, proto);
    b.addEventListener('click', () => chooseTarget(t));
    li.append(b);
    list.append(li);
  }
}

function resetCredsForm(): void {
  pendingTarget = null;
  $('rdp-creds').hidden = true;
  input('rdp-user').value = '';
  input('rdp-pass').value = '';
  input('rdp-domain').value = '';
  for (const b of $('target-list').querySelectorAll('button')) b.setAttribute('aria-pressed', 'false');
}

function showTargets(text: string | null = null, tone: Tone = 'warn'): void {
  resetCredsForm();
  message('targets-msg', text, tone);
  const reopen = $<HTMLButtonElement>('reopen-btn');
  reopen.hidden = !reopenTarget || !text;
  if (reopenTarget) reopen.textContent = `Reconnect to ${reopenTarget.name}`;
  title(agentLabel());
  show('view-targets', text && !reopen.hidden ? reopen : null);
}

function chooseTarget(t: TargetInfo): void {
  message('targets-msg', null);
  $('reopen-btn').hidden = true;
  if (t.promptCredentials) {
    resetCredsForm();
    pendingTarget = t;
    $('target-list').querySelector(`button[data-target="${CSS.escape(t.id)}"]`)?.setAttribute('aria-pressed', 'true');
    $('creds-target').textContent = t.name;
    $('rdp-creds').hidden = false;
    input('rdp-user').value = t.username ?? '';
    input('rdp-domain').value = t.domain ?? '';
    (t.username ? input('rdp-pass') : input('rdp-user')).focus();
    return;
  }
  void openTarget(t);
}

async function openTarget(t: TargetInfo, credentials?: { username?: string; password?: string; domain?: string }): Promise<void> {
  if (!app || !session) return;
  desktopActive = true;
  reopenTarget = t;
  $('loading-text').textContent = `Connecting to ${t.name}…`;
  $('loading-overlay').hidden = false;
  $('remote-title').textContent = `Remote desktop: ${t.name}`;
  show('remote', $('display'));
  title(`${t.name} · ${agentLabel()}`);
  let engine: 'rdp' | 'guacd';
  try {
    ({ engine } = await app.open({
      target: t.id,
      ...remoteSize($('display')),
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      // The built-in RDP client signs in itself; only guacd needs them.
      ...(credentials && t.engine !== 'rdp' ? { credentials } : {}),
    }));
  } catch {
    $('loading-overlay').hidden = true;
    if (session?.closed || closedShown || !desktopActive) return;
    desktopActive = false;
    showTargets(`Could not open ${t.name}. The computer may be turned off or unreachable from the agent.`, 'error');
    return;
  }
  if (!desktopActive || currentView !== 'remote') {
    // The user left while the agent was connecting.
    app.closeDesktop();
    return;
  }
  const els: RemoteElements = {
    container: $('display'),
    loading: $('loading-overlay'),
    loadingText: $('loading-text'),
    softKeyboard: $<HTMLTextAreaElement>('soft-kbd'),
  };
  remote =
    engine === 'rdp'
      ? new RdpDesktop(
          app,
          session,
          els,
          { onError: (msg) => onRemoteEnded(msg, 'error') },
          {
            username: credentials?.username ?? '',
            password: credentials?.password ?? '',
            ...(credentials?.domain ? { domain: credentials.domain } : {}),
            // For the built-in engine the agent asks for credentials exactly when NLA is on.
            nla: t.promptCredentials,
            name: t.name,
          },
        )
      : new GuacamoleDesktop(app, session, els, {
          onError: (msg) => onRemoteEnded(`The remote desktop reported an error: ${msg}`),
        });
  remote.start();
}

/** The remote desktop connection ended (the agent or the view says so). */
function onRemoteEnded(text = `The remote desktop session ended.`, tone: Tone = 'warn'): void {
  if (!desktopActive) return;
  desktopActive = false;
  stopRemote();
  // Tell the agent too, in case only the browser side noticed.
  app?.closeDesktop();
  showTargets(text, tone);
}

function closeDesktop(): void {
  desktopActive = false;
  reopenTarget = null;
  stopRemote();
  app?.closeDesktop();
  showTargets();
}

function stopRemote(): void {
  if (remote) lastRemoteInput = Math.max(lastRemoteInput, remote.lastInputAt);
  remote?.stop();
  remote = null;
  $('loading-overlay').hidden = true;
  $('reconnect-overlay').hidden = true;
  if (document.fullscreenElement) void document.exitFullscreen().catch(() => {});
}

// ------------------------------------------------------------------ closing

function signOut(): void {
  if (!conn) return;
  const c = conn;
  onSessionClosed('signed out', undefined, true);
  c.close('signed out');
}

function onSessionClosed(reason: string, error: Error | undefined, userInitiated: boolean): void {
  if (closedShown) return;
  closedShown = true;
  desktopActive = false;
  stopRemote();
  stopSessionTimer();
  resetHeader();
  const notice = describeClose(reason, error, userInitiated);
  if (notice.security) badge('bad', 'Tampering detected');
  else badge('warn', userInitiated ? 'Signed out' : 'Disconnected');
  showClosed(notice);
}

let closedAction: 'reconnect' | 'start' = 'reconnect';

function showClosed(n: Notice): void {
  $('closed-title').textContent = n.title;
  message('closed-msg', n.text, n.tone);
  const btn = $('reconnect-btn');
  btn.textContent = n.action;
  // After a security event the safe choice should not look like the default.
  btn.className = n.security ? 'secondary' : 'primary';
  closedAction = n.security ? 'start' : 'reconnect';
  title(n.title);
  show('view-closed');
}

function resetSession(): void {
  conn = null;
  app = null;
  session = null;
  remote = null;
  targets = [];
  reopenTarget = null;
  closedShown = false;
  message('connect-msg', null);
}

// ------------------------------------------------------------------ session warnings

function startSessionTimer(): void {
  stopSessionTimer();
  sessionTimer = setInterval(updateSessionBanner, 1000);
}

function stopSessionTimer(): void {
  if (sessionTimer) clearInterval(sessionTimer);
  sessionTimer = null;
  $('session-banner').hidden = true;
}

function updateSessionBanner(): void {
  const limits = app?.limits;
  const banner = $('session-banner');
  if (!limits || !session || session.closed) {
    banner.hidden = true;
    return;
  }
  const now = Date.now();
  const lastInput = Math.max(lastRemoteInput, remote?.lastInputAt ?? 0);
  const idleLeft = limits.idleTimeoutSeconds > 0 ? limits.idleTimeoutSeconds * 1000 - (now - lastInput) : Infinity;
  const maxLeft = limits.maxSessionSeconds > 0 ? limits.maxSessionSeconds * 1000 - (now - connectedAt) : Infinity;
  let text = '';
  if (idleLeft <= IDLE_WARNING_MS) {
    text = remote
      ? `You’ll be signed out in ${formatCountdown(idleLeft)} because of inactivity. Move the mouse or press a key to stay signed in.`
      : `You’ll be signed out in ${formatCountdown(idleLeft)} because of inactivity.`;
  } else if (maxLeft <= MAX_SESSION_WARNING_MS) {
    text = `This session reaches its time limit in ${formatCountdown(maxLeft)}. Save your work.`;
  }
  if (banner.textContent !== text) banner.textContent = text;
  banner.hidden = !text;
}

// ------------------------------------------------------------------ remote toolbar

async function pasteText(): Promise<void> {
  if (!remote) return;
  let text: string | null = null;
  try {
    text = await navigator.clipboard.readText();
  } catch {
    text = window.prompt('Text to send to the remote computer’s clipboard:');
  }
  remote.focus();
  if (!text) return;
  remote.sendClipboardText(text);
  toast('Text sent to the remote clipboard. Paste it there with Ctrl+V.');
}

async function toggleFullscreen(): Promise<void> {
  if (document.fullscreenElement) {
    await document.exitFullscreen().catch(() => {});
    return;
  }
  try {
    await $('remote').requestFullscreen();
    // Let shortcuts such as Alt+Tab and Ctrl+W reach the remote computer
    // (Chromium; hold Esc to leave full screen).
    await (navigator as unknown as { keyboard?: { lock?: () => Promise<void> } }).keyboard?.lock?.();
  } catch {
    // Full screen or keyboard lock not available.
  }
  remote?.focus();
}

function onFullscreenChange(): void {
  const full = Boolean(document.fullscreenElement);
  const label = full ? 'Exit full screen' : 'Full screen';
  $('full-label').textContent = label;
  $('full-btn').setAttribute('aria-label', label);
  remote?.resize();
  if (!full) (navigator as unknown as { keyboard?: { unlock?: () => void } }).keyboard?.unlock?.();
}

// ------------------------------------------------------------------ wiring

$('connect-form').addEventListener('submit', (e) => {
  e.preventDefault();
  void connect();
});
input('agent-key').addEventListener('input', previewKeyFingerprint);
$('login-form').addEventListener('submit', (e) => void login(e as SubmitEvent));
$('rdp-creds').addEventListener('submit', (e) => {
  e.preventDefault();
  const t = pendingTarget;
  if (!t) return;
  const creds = {
    username: input('rdp-user').value.trim(),
    password: input('rdp-pass').value,
    domain: input('rdp-domain').value.trim(),
  };
  resetCredsForm();
  void openTarget(t, creds);
});
$('creds-cancel').addEventListener('click', () => {
  resetCredsForm();
  $('target-list').querySelector<HTMLElement>('button')?.focus();
});
$('reopen-btn').addEventListener('click', () => {
  if (reopenTarget) chooseTarget(reopenTarget);
});
$('signout-btn').addEventListener('click', signOut);
$('details-btn').addEventListener('click', () => toggleDetails());
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !$('details-panel').hidden) {
    toggleDetails(false);
    $('details-btn').focus();
  }
});
document.addEventListener('click', (e) => {
  const t = e.target as Node;
  if (!$('details-panel').hidden && !$('details-panel').contains(t) && !$('details-btn').contains(t)) toggleDetails(false);
});
$('close-desktop-btn').addEventListener('click', closeDesktop);
$('cad-btn').addEventListener('click', () => {
  remote?.sendCtrlAltDel();
  remote?.focus();
});
$('paste-btn').addEventListener('click', () => void pasteText());
$('kbd-btn').addEventListener('click', () => remote?.showSoftKeyboard());
$('full-btn').addEventListener('click', () => void toggleFullscreen());
document.addEventListener('fullscreenchange', onFullscreenChange);
$('reconnect-btn').addEventListener('click', () => {
  resetSession();
  if (closedAction === 'reconnect') {
    initConnectView();
    void connect();
  } else {
    initConnectView();
  }
});
new ResizeObserver(() => remote?.resize()).observe($('display'));
window.addEventListener('beforeunload', (e) => {
  // Closing the tab ends the session; ask first while a desktop is open.
  if (remote) {
    e.preventDefault();
    e.returnValue = '';
  }
});
window.addEventListener('pagehide', () => conn?.close('page closed'));

initConnectView();
void ensureDeviceKey();
