// Desktop view for the built-in RDP engine. The RDP client itself is
// IronRDP compiled to WebAssembly; it renders into our canvas and talks to
// the RDP server through the encrypted session (see rdp-socket.ts), with
// the agent opening the actual connection. This file wires input, clipboard,
// sizing and the "starting" state around it.

import * as rdp from '@devolutions/iron-remote-desktop-rdp';
import type { AppChannel, SecureSession } from '@wrhs/protocol';
import {
  isTouchDevice,
  showSoftKeyboard,
  watchForFirstPicture,
  wireSoftKeyboard,
  type DesktopView,
  type RemoteCallbacks,
  type RemoteElements,
} from './desktop-common.ts';
import { describeRdpEnd, describeRdpError } from './messages.ts';
import { bindRdpTunnel } from './rdp-socket.ts';
import { SC, scancode } from './scancodes.ts';

type RdpSession = Awaited<ReturnType<InstanceType<typeof rdp.Backend.SessionBuilder>['connect']>>;
type DeviceEvent = ReturnType<typeof rdp.Backend.DeviceEvent.keyPressed>;

let engineLoad: Promise<void> | null = null;

/** Compiles the RDP client once. Safe to call early to save time later. */
export function loadRdpEngine(): Promise<void> {
  engineLoad ??= rdp.init('WARN').catch((err: unknown) => {
    engineLoad = null;
    throw err;
  });
  return engineLoad;
}

export interface RdpOptions {
  /** Empty when the remote computer should show its own sign-in screen. */
  username: string;
  password: string;
  domain?: string;
  /** Sign in with Network Level Authentication (CredSSP). */
  nla: boolean;
  /** Display name of the remote computer, for messages. */
  name: string;
}

/** RDP wants an even width (and 4-aligned avoids padding quirks) within 200..8192. */
function desktopSize(width: number, height: number): { width: number; height: number } {
  return {
    width: Math.min(8192, Math.max(320, Math.floor(width / 4) * 4)),
    height: Math.min(8192, Math.max(200, Math.floor(height / 2) * 2)),
  };
}

/** Longest wait for the RDP connection sequence (sign-in happens after it). */
const CONNECT_TIMEOUT_MS = 60_000;
/** After the agent reports the end, how long the RDP client gets to explain it. */
const CLOSE_GRACE_MS = 3000;

const LONG_PRESS_MS = 600;
const DRAG_THRESHOLD_PX = 10;
const BUTTON_LEFT = 0;
const BUTTON_RIGHT = 2;

export class RdpDesktop implements DesktopView {
  readonly #app: AppChannel;
  readonly #secure: SecureSession;
  readonly #els: RemoteElements;
  readonly #cb: RemoteCallbacks;
  readonly #o: RdpOptions;
  readonly #touch = isTouchDevice();
  #session: RdpSession | null = null;
  #canvas: HTMLCanvasElement | null = null;
  #tunnel: { url: string; dispose(): void } | null = null;
  #stopped = false;
  #ready = false;
  #ended = false;
  #resizeTimer: ReturnType<typeof setTimeout> | null = null;
  #scaleTimer: ReturnType<typeof setTimeout> | null = null;
  #locks: string | null = null;
  readonly #cleanup: (() => void)[] = [];
  lastInputAt = Date.now();

  constructor(app: AppChannel, session: SecureSession, els: RemoteElements, cb: RemoteCallbacks, o: RdpOptions) {
    this.#app = app;
    this.#secure = session;
    this.#els = els;
    this.#cb = cb;
    this.#o = o;
  }

  get ready(): boolean {
    return this.#ready;
  }

  start(): void {
    this.#setLoading(true, 'Starting the remote desktop…');
    this.#run().catch((err: unknown) => this.#fail(describeRdpError(err, this.#o.name)));
  }

  stop(): void {
    if (this.#stopped) return;
    this.#stopped = true;
    for (const c of this.#cleanup) c();
    if (this.#resizeTimer) clearTimeout(this.#resizeTimer);
    if (this.#scaleTimer) clearTimeout(this.#scaleTimer);
    try {
      this.#session?.releaseAllInputs();
      this.#session?.shutdown();
    } catch {
      // Already gone.
    }
    this.#session = null;
    this.#tunnel?.dispose();
    this.#els.container.replaceChildren();
    this.#els.softKeyboard.blur();
    this.#setLoading(false);
  }

  /** The container changed size: refit now, tell the remote side shortly after. */
  resize(): void {
    if (this.#stopped) return;
    this.#fit();
    if (this.#resizeTimer) clearTimeout(this.#resizeTimer);
    this.#resizeTimer = setTimeout(() => this.#requestSize(), 400);
  }

  sendCtrlAltDel(): void {
    this.#input();
    this.#apply([
      rdp.Backend.DeviceEvent.keyPressed(SC.ctrl),
      rdp.Backend.DeviceEvent.keyPressed(SC.alt),
      rdp.Backend.DeviceEvent.keyPressed(SC.del),
      rdp.Backend.DeviceEvent.keyReleased(SC.del),
      rdp.Backend.DeviceEvent.keyReleased(SC.alt),
      rdp.Backend.DeviceEvent.keyReleased(SC.ctrl),
    ]);
  }

  sendClipboardText(text: string): void {
    const data = new rdp.Backend.ClipboardData();
    data.addText('text/plain', text);
    void this.#session?.onClipboardPaste(data).catch(() => {});
  }

  showSoftKeyboard(): void {
    showSoftKeyboard(this.#els.softKeyboard);
  }

  focus(): void {
    this.#els.container.focus();
  }

  remoteClosed(): void {
    // Let the RDP client read what the server sent last (often the reason,
    // such as a rejected password), then see the connection close.
    this.#tunnel?.dispose();
    setTimeout(() => this.#end(`The remote desktop session on ${this.#o.name} ended.`), CLOSE_GRACE_MS);
  }

  // ---------------------------------------------------------------- session

  async #run(): Promise<void> {
    await loadRdpEngine();
    if (this.#stopped) return;
    const { container } = this.#els;
    const canvas = document.createElement('canvas');
    canvas.className = 'rdp-canvas';
    this.#canvas = canvas;
    container.replaceChildren(canvas);
    // The first connection uses CSS pixels; high-density screens switch to
    // device pixels with matching scaling once the session runs.
    const size = desktopSize(container.clientWidth || 1024, container.clientHeight || 768);
    canvas.width = size.width;
    canvas.height = size.height;
    this.#fit();
    this.#watchCanvasSize(canvas);

    this.#tunnel = bindRdpTunnel(this.#app);
    const o = this.#o;
    const builder = new rdp.Backend.SessionBuilder()
      .username(o.username)
      .password(o.password)
      .serverDomain(o.domain ?? '')
      // The agent decides which computer this connects to; the name is only
      // used inside the RDP handshake.
      .destination('remote-desktop')
      .proxyAddress(this.#tunnel.url)
      // The encrypted session is already signed in; the agent ignores this.
      .authToken('wrhs')
      .desktopSize(new rdp.Backend.DesktopSize(size.width, size.height))
      .renderCanvas(canvas)
      .setCursorStyleCallbackContext(this)
      .setCursorStyleCallback((style: string, url?: string, x?: number, y?: number) => this.#setCursor(style, url, x, y))
      .remoteClipboardChangedCallback((data: InstanceType<typeof rdp.Backend.ClipboardData>) => this.#onRemoteClipboard(data))
      .forceClipboardUpdateCallback(() => {
        void this.#session?.onClipboardPaste(new rdp.Backend.ClipboardData()).catch(() => {});
      })
      .extension(rdp.enableCredssp(o.nla))
      .extension(rdp.displayControl(true))
      // Keep each message well under the agent's per-message limit.
      .extension(rdp.outboundMessageSizeLimit(32 * 1024));
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error('timeout')), CONNECT_TIMEOUT_MS);
    });
    let session: RdpSession;
    try {
      session = await Promise.race([builder.connect(), timeout]);
    } catch (err) {
      if ((err as Error)?.message === 'timeout') {
        this.#tunnel.dispose();
        return this.#fail(`${o.name} did not finish connecting in time.`);
      }
      throw err;
    } finally {
      clearTimeout(timer);
    }
    if (this.#stopped) {
      session.shutdown();
      return;
    }
    this.#session = session;
    this.#wireInput(canvas);
    this.#watchForFirstPicture();
    this.#scheduleDeviceScale(0);
    session.run().then(
      (info) => this.#end(describeRdpEnd(info.reason(), o.name)),
      (err: unknown) => this.#end(describeRdpError(err, o.name)),
    );
  }

  #end(message: string): void {
    if (this.#stopped || this.#ended) return;
    this.#ended = true;
    this.#cb.onError(message);
  }

  #fail(message: string): void {
    if (this.#stopped) return;
    this.#setLoading(false);
    this.#end(message);
  }

  /** Size we want the remote desktop to be, with the matching scale factor. */
  #wantedSize(): { width: number; height: number; scale: number } | null {
    const el = this.#els.container;
    if (!el.clientWidth || !el.clientHeight) return null;
    const dpr = window.devicePixelRatio || 1;
    // Scaling only pays off on clearly high-density screens; Windows accepts 100..500 %.
    const density = dpr >= 1.25 ? Math.min(dpr, 5) : 1;
    return { ...desktopSize(el.clientWidth * density, el.clientHeight * density), scale: Math.round(density * 100) };
  }

  #requestSize(): void {
    const want = this.#wantedSize();
    const s = this.#session;
    if (!want || !s || !this.#canvas) return;
    if (want.width === this.#canvas.width && want.height === this.#canvas.height) return;
    s.resize(want.width, want.height, want.scale);
  }

  /**
   * Display Control only works once its channel is up, a moment after the
   * session starts, so retry a few times until the desktop has the size.
   */
  #scheduleDeviceScale(attempt: number): void {
    if (attempt >= 8 || this.#stopped) return;
    this.#scaleTimer = setTimeout(() => {
      const want = this.#wantedSize();
      if (!want || !this.#canvas || (want.width === this.#canvas.width && want.height === this.#canvas.height)) return;
      this.#requestSize();
      this.#scheduleDeviceScale(attempt + 1);
    }, attempt === 0 ? 1500 : 2000);
  }

  /** Scale the canvas (always at remote resolution) to fit the container. */
  #fit(): void {
    const c = this.#canvas;
    const el = this.#els.container;
    if (!c || !c.width || !c.height || !el.clientWidth || !el.clientHeight) return;
    const scale = Math.min(el.clientWidth / c.width, el.clientHeight / c.height);
    c.style.width = `${Math.floor(c.width * scale)}px`;
    c.style.height = `${Math.floor(c.height * scale)}px`;
  }

  #watchCanvasSize(canvas: HTMLCanvasElement): void {
    const mo = new MutationObserver(() => this.#fit());
    mo.observe(canvas, { attributes: true, attributeFilter: ['width', 'height'] });
    this.#cleanup.push(() => mo.disconnect());
  }

  #watchForFirstPicture(): void {
    this.#cleanup.push(
      watchForFirstPicture({
        canvas: () => this.#canvas,
        connected: () => !this.#stopped && this.#session !== null,
        ready: () => {
          this.#ready = true;
          this.#setLoading(false);
          this.#cb.onReady?.();
        },
        slow: () => {
          this.#els.loadingText.textContent = 'Still starting… signing in to the remote computer can take a little while.';
        },
      }),
    );
  }

  #setLoading(on: boolean, text?: string): void {
    this.#els.loading.hidden = !on;
    if (text) this.#els.loadingText.textContent = text;
  }

  #setCursor(style: string, url?: string, x?: number, y?: number): void {
    const c = this.#canvas;
    if (!c) return;
    if (style === 'hidden') c.style.cursor = 'none';
    else if (style === 'url' && url && /^data:image\//.test(url)) c.style.cursor = `url("${url}") ${Math.round(x ?? 0)} ${Math.round(y ?? 0)}, default`;
    else c.style.cursor = 'default';
  }

  #onRemoteClipboard(data: InstanceType<typeof rdp.Backend.ClipboardData>): void {
    for (const item of data.items()) {
      if (item.mimeType() !== 'text/plain') continue;
      const value = item.value() as unknown;
      if (typeof value === 'string') void navigator.clipboard?.writeText(value).catch(() => {});
      return;
    }
  }

  // ---------------------------------------------------------------- input

  #input(): void {
    this.lastInputAt = Date.now();
    this.#secure.markInteractive();
  }

  #apply(events: DeviceEvent[]): void {
    const s = this.#session;
    if (!s || this.#stopped) return;
    const tx = new rdp.Backend.InputTransaction();
    for (const e of events) tx.addEvent(e);
    s.applyInputs(tx);
  }

  /** Remote desktop coordinates for a point in the page. */
  #point(e: { clientX: number; clientY: number }): { x: number; y: number } {
    const c = this.#canvas!;
    const r = c.getBoundingClientRect();
    const x = ((e.clientX - r.left) * c.width) / (r.width || 1);
    const y = ((e.clientY - r.top) * c.height) / (r.height || 1);
    return { x: Math.round(Math.min(c.width - 1, Math.max(0, x))), y: Math.round(Math.min(c.height - 1, Math.max(0, y))) };
  }

  #move(e: { clientX: number; clientY: number }): DeviceEvent {
    const p = this.#point(e);
    return rdp.Backend.DeviceEvent.mouseMove(p.x, p.y);
  }

  /** Keep the remote Caps/Num/Scroll Lock in step with this keyboard. */
  #syncLocks(e: KeyboardEvent | MouseEvent): void {
    const s = this.#session;
    if (!s || typeof e.getModifierState !== 'function') return;
    const caps = e.getModifierState('CapsLock');
    const num = e.getModifierState('NumLock');
    const scroll = e.getModifierState('ScrollLock');
    const kana = e.getModifierState('KanaMode');
    const key = `${+caps}${+num}${+scroll}${+kana}`;
    if (key === this.#locks) return;
    this.#locks = key;
    s.synchronizeLockKeys(scroll, num, caps, kana);
  }

  #wireInput(canvas: HTMLCanvasElement): void {
    const { container } = this.#els;
    const on = <K extends keyof HTMLElementEventMap>(
      el: HTMLElement,
      type: K,
      fn: (e: HTMLElementEventMap[K]) => void,
      opts?: AddEventListenerOptions,
    ) => {
      el.addEventListener(type, fn as EventListener, opts);
      this.#cleanup.push(() => el.removeEventListener(type, fn as EventListener, opts));
    };

    // Keyboard: physical keys as scancodes, so the remote keyboard layout applies.
    const LOCK_KEYS = new Set(['CapsLock', 'NumLock', 'ScrollLock', 'KanaMode']);
    const onKey = (e: KeyboardEvent) => {
      const sc = scancode(e.code);
      if (sc === undefined) return;
      e.preventDefault();
      const down = e.type === 'keydown';
      if (LOCK_KEYS.has(e.code)) {
        // The key itself toggles the remote state; just remember the new one.
        if (!down) this.#locks = null;
      } else if (down) this.#syncLocks(e);
      this.#input();
      this.#apply([down ? rdp.Backend.DeviceEvent.keyPressed(sc) : rdp.Backend.DeviceEvent.keyReleased(sc)]);
    };
    on(container, 'keydown', onKey);
    on(container, 'keyup', onKey);
    const release = () => {
      try {
        this.#session?.releaseAllInputs();
      } catch {
        // Session gone.
      }
    };
    on(container, 'blur', release);
    const onVisibility = () => document.hidden && release();
    document.addEventListener('visibilitychange', onVisibility);
    this.#cleanup.push(() => document.removeEventListener('visibilitychange', onVisibility));

    // Mouse and pen.
    on(canvas, 'pointerdown', (e) => {
      container.focus();
      if (e.pointerType === 'touch') return this.#touchDown(e);
      e.preventDefault();
      canvas.setPointerCapture(e.pointerId);
      this.#syncLocks(e);
      this.#input();
      this.#apply([this.#move(e), rdp.Backend.DeviceEvent.mouseButtonPressed(e.button)]);
    });
    on(canvas, 'pointermove', (e) => {
      if (e.pointerType === 'touch') return this.#touchMove(e);
      this.lastInputAt = Date.now();
      this.#apply([this.#move(e)]);
    });
    on(canvas, 'pointerup', (e) => {
      if (e.pointerType === 'touch') return this.#touchUp(e);
      this.#input();
      this.#apply([this.#move(e), rdp.Backend.DeviceEvent.mouseButtonReleased(e.button)]);
    });
    on(canvas, 'pointercancel', (e) => {
      if (e.pointerType === 'touch') return this.#touchCancel(e);
      release();
    });
    on(canvas, 'contextmenu', (e) => e.preventDefault());
    on(
      canvas,
      'wheel',
      (e) => {
        e.preventDefault();
        const vertical = e.deltaY !== 0;
        const amount = vertical ? e.deltaY : e.deltaX;
        if (!amount) return;
        const unit = e.deltaMode === 1 ? 1 : e.deltaMode === 2 ? 2 : 0;
        this.#input();
        this.#apply([this.#move(e), rdp.Backend.DeviceEvent.wheelRotations(vertical, -amount, unit)]);
      },
      { passive: false },
    );

    // Phone and tablet keyboard.
    this.#cleanup.push(
      wireSoftKeyboard(this.#els.softKeyboard, {
        type: (text) => {
          this.#input();
          const events: DeviceEvent[] = [];
          for (const ch of text) {
            events.push(rdp.Backend.DeviceEvent.unicodePressed(ch), rdp.Backend.DeviceEvent.unicodeReleased(ch));
          }
          this.#apply(events);
        },
        press: (key) => {
          const sc = scancode(key)!;
          this.#input();
          this.#apply([rdp.Backend.DeviceEvent.keyPressed(sc), rdp.Backend.DeviceEvent.keyReleased(sc)]);
        },
      }),
    );

    if (!this.#touch) container.focus();
  }

  // Touch: a tap clicks, a long press right-clicks, a drag drags with the
  // left button, and two fingers scroll.
  #touches = new Map<number, { x: number; y: number; startX: number; startY: number }>();
  #touchMode: 'pending' | 'drag' | 'scroll' | 'done' = 'done';
  #longPress: ReturnType<typeof setTimeout> | null = null;

  #touchDown(e: PointerEvent): void {
    e.preventDefault();
    this.#touches.set(e.pointerId, { x: e.clientX, y: e.clientY, startX: e.clientX, startY: e.clientY });
    if (this.#touches.size === 1) {
      this.#touchMode = 'pending';
      this.#input();
      this.#apply([this.#move(e)]);
      this.#longPress = setTimeout(() => {
        if (this.#touchMode !== 'pending') return;
        this.#touchMode = 'done';
        this.#click(BUTTON_RIGHT);
      }, LONG_PRESS_MS);
    } else if (this.#touches.size === 2) {
      if (this.#touchMode === 'drag') this.#apply([rdp.Backend.DeviceEvent.mouseButtonReleased(BUTTON_LEFT)]);
      this.#touchMode = 'scroll';
      this.#clearLongPress();
    }
  }

  #touchMove(e: PointerEvent): void {
    const t = this.#touches.get(e.pointerId);
    if (!t) return;
    const dy = e.clientY - t.y;
    t.x = e.clientX;
    t.y = e.clientY;
    if (this.#touchMode === 'scroll') {
      if (Math.abs(dy) >= 1) {
        this.#input();
        this.#apply([rdp.Backend.DeviceEvent.wheelRotations(true, dy * 2, 0)]);
      }
      return;
    }
    if (this.#touchMode === 'pending' && Math.hypot(e.clientX - t.startX, e.clientY - t.startY) > DRAG_THRESHOLD_PX) {
      this.#clearLongPress();
      this.#touchMode = 'drag';
      this.#apply([rdp.Backend.DeviceEvent.mouseButtonPressed(BUTTON_LEFT)]);
    }
    if (this.#touchMode === 'drag') {
      this.#input();
      this.#apply([this.#move(e)]);
    }
  }

  #touchUp(e: PointerEvent): void {
    if (!this.#touches.delete(e.pointerId)) return;
    if (this.#touches.size > 0) return;
    this.#clearLongPress();
    if (this.#touchMode === 'pending') this.#click(BUTTON_LEFT);
    else if (this.#touchMode === 'drag') this.#apply([this.#move(e), rdp.Backend.DeviceEvent.mouseButtonReleased(BUTTON_LEFT)]);
    this.#touchMode = 'done';
  }

  #touchCancel(e: PointerEvent): void {
    this.#touches.delete(e.pointerId);
    this.#clearLongPress();
    if (this.#touchMode === 'drag') this.#apply([rdp.Backend.DeviceEvent.mouseButtonReleased(BUTTON_LEFT)]);
    if (this.#touches.size === 0) this.#touchMode = 'done';
  }

  #clearLongPress(): void {
    if (this.#longPress) clearTimeout(this.#longPress);
    this.#longPress = null;
  }

  #click(button: number): void {
    this.#input();
    this.#apply([rdp.Backend.DeviceEvent.mouseButtonPressed(button), rdp.Backend.DeviceEvent.mouseButtonReleased(button)]);
  }
}
