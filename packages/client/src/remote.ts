// The remote desktop view: Guacamole client wiring, input (mouse, touch,
// keyboard, on-screen keyboard), cursor, clipboard and the "starting" state.

import Guacamole from '../vendor/guacamole-common-js/guacamole-common.js';
import type { AppChannel, SecureSession } from '@wrhs/protocol';
import { createEncryptedTunnel } from './tunnel.ts';

export const KEYSYM = {
  ctrl: 0xffe3,
  alt: 0xffe9,
  del: 0xffff,
  backspace: 0xff08,
  enter: 0xff0d,
  tab: 0xff09,
  escape: 0xff1b,
  left: 0xff51,
  up: 0xff52,
  right: 0xff53,
  down: 0xff54,
} as const;

/** Keys a hardware keyboard can send to the on-screen keyboard field that are not text. */
const SPECIAL_KEYS: Record<string, number> = {
  Backspace: KEYSYM.backspace,
  Enter: KEYSYM.enter,
  Tab: KEYSYM.tab,
  Escape: KEYSYM.escape,
  Delete: KEYSYM.del,
  ArrowLeft: KEYSYM.left,
  ArrowUp: KEYSYM.up,
  ArrowRight: KEYSYM.right,
  ArrowDown: KEYSYM.down,
};

export const isTouchDevice = (): boolean =>
  (typeof matchMedia === 'function' && matchMedia('(pointer: coarse)').matches) || navigator.maxTouchPoints > 0;

export interface RemoteElements {
  container: HTMLElement;
  loading: HTMLElement;
  loadingText: HTMLElement;
  softKeyboard: HTMLTextAreaElement;
}

export interface RemoteCallbacks {
  /** The Guacamole client reported an error (the session itself may still be fine). */
  onError(message: string): void;
  /** The first picture arrived (or we gave up waiting for one). */
  onReady?(): void;
}

// One keyboard listener for the page: Guacamole.Keyboard has no way to detach.
let sharedKeyboard: GuacKeyboard | null = null;

export class RemoteDesktop {
  readonly #client: GuacClient;
  readonly #session: SecureSession;
  readonly #els: RemoteElements;
  readonly #cb: RemoteCallbacks;
  readonly #keyboard: GuacKeyboard;
  readonly #touch = isTouchDevice();
  #state = 0;
  #stopped = false;
  #ready = false;
  #resizeTimer: ReturnType<typeof setTimeout> | null = null;
  readonly #cleanup: (() => void)[] = [];
  /** Time of the last input sent to the remote desktop (for idle warnings). */
  lastInputAt = Date.now();

  constructor(app: AppChannel, session: SecureSession, els: RemoteElements, cb: RemoteCallbacks) {
    this.#session = session;
    this.#els = els;
    this.#cb = cb;
    this.#client = new Guacamole.Client(createEncryptedTunnel(app));
    sharedKeyboard ??= new Guacamole.Keyboard(els.container);
    this.#keyboard = sharedKeyboard;
  }

  get ready(): boolean {
    return this.#ready;
  }

  start(): void {
    const { container } = this.#els;
    const client = this.#client;
    const display = client.getDisplay();
    const displayEl = display.getElement();
    container.replaceChildren(displayEl);
    this.#setLoading(true, 'Starting the remote desktop…');

    display.onresize = () => this.#fit();
    client.onstatechange = (s) => (this.#state = s);
    client.onerror = (status) => this.#cb.onError(status.message ?? `error ${status.code}`);
    client.onclipboard = (stream, mimetype) => {
      if (!/^text\//.test(mimetype)) return;
      const reader = new Guacamole.StringReader(stream);
      let text = '';
      reader.ontext = (t) => (text += t);
      reader.onend = () => void navigator.clipboard?.writeText(text).catch(() => {});
    };

    // Pointer input. Touch taps become clicks, a long press is a right click.
    const mouse = new Guacamole.Mouse(displayEl);
    mouse.onEach(['mousedown', 'mouseup', 'mousemove'], (e) => this.#sendMouse(e.state));
    const touch = new Guacamole.Mouse.Touchscreen(displayEl);
    touch.onEach(['mousedown', 'mouseup', 'mousemove'], (e) => this.#sendMouse(e.state));

    // Show the remote cursor as the local cursor, so there is exactly one
    // pointer. Touch devices have no local pointer: keep the drawn one.
    display.oncursor = (canvas, x, y) => {
      display.showCursor(this.#touch || !mouse.setCursor(canvas, x, y));
    };

    this.#keyboard.onkeydown = (keysym) => {
      this.#input();
      this.#client.sendKeyEvent(1, keysym);
      return false;
    };
    this.#keyboard.onkeyup = (keysym) => {
      this.#input();
      this.#client.sendKeyEvent(0, keysym);
    };

    this.#wireSoftKeyboard();
    const focus = () => container.focus();
    container.addEventListener('mousedown', focus);
    this.#cleanup.push(() => container.removeEventListener('mousedown', focus));

    client.connect();
    if (!this.#touch) container.focus();
    this.#fit();
    this.#watchForFirstPicture();
  }

  /** Close the remote desktop (the encrypted session stays signed in). */
  stop(): void {
    if (this.#stopped) return;
    this.#stopped = true;
    this.#keyboard.onkeydown = null;
    this.#keyboard.onkeyup = null;
    this.#keyboard.reset();
    for (const c of this.#cleanup) c();
    if (this.#resizeTimer) clearTimeout(this.#resizeTimer);
    this.#client.disconnect();
    this.#els.container.replaceChildren();
    this.#els.softKeyboard.blur();
    this.#setLoading(false);
  }

  /** The container changed size: refit now, tell the remote side shortly after. */
  resize(): void {
    if (this.#stopped) return;
    this.#fit();
    if (this.#resizeTimer) clearTimeout(this.#resizeTimer);
    this.#resizeTimer = setTimeout(() => {
      const { width, height } = remoteSize(this.#els.container);
      if (width > 0 && height > 0) this.#client.sendSize(width, height);
    }, 300);
  }

  sendCtrlAltDel(): void {
    const keys = [KEYSYM.ctrl, KEYSYM.alt, KEYSYM.del];
    this.#input();
    for (const k of keys) this.#client.sendKeyEvent(1, k);
    for (const k of [...keys].reverse()) this.#client.sendKeyEvent(0, k);
  }

  sendClipboardText(text: string): void {
    const writer = new Guacamole.StringWriter(this.#client.createClipboardStream('text/plain'));
    writer.sendText(text);
    writer.sendEnd();
  }

  /** Raise the phone/tablet keyboard (must run inside a user gesture). */
  showSoftKeyboard(): void {
    const ta = this.#els.softKeyboard;
    ta.value = ' ';
    ta.focus();
    ta.setSelectionRange(1, 1);
  }

  focus(): void {
    this.#els.container.focus();
  }

  // ---------------------------------------------------------------- internals

  #input(): void {
    this.lastInputAt = Date.now();
    this.#session.markInteractive();
  }

  #sendMouse(state: unknown): void {
    this.lastInputAt = Date.now();
    this.#client.sendMouseState(state, true);
  }

  #fit(): void {
    const display = this.#client.getDisplay();
    const w = display.getWidth();
    const h = display.getHeight();
    const { container } = this.#els;
    if (!w || !h || !container.clientWidth || !container.clientHeight) return;
    display.scale(Math.min(container.clientWidth / w, container.clientHeight / h));
  }

  /**
   * Phone and tablet keyboards do not produce reliable key events, so text
   * goes through a hidden field: each insertion is typed into the remote
   * desktop and the field is reset. A single space stays in the field so
   * Backspace always has something to delete (and so fires an event).
   */
  #wireSoftKeyboard(): void {
    const ta = this.#els.softKeyboard;
    const reset = () => {
      ta.value = ' ';
      ta.setSelectionRange(1, 1);
    };
    const type = (text: string) => {
      this.#input();
      this.#keyboard.type(text);
    };
    const press = (keysym: number) => {
      this.#input();
      this.#keyboard.press(keysym);
      this.#keyboard.release(keysym);
    };
    const onBeforeInput = (e: InputEvent) => {
      switch (e.inputType) {
        case 'insertText':
        case 'insertReplacementText':
        case 'insertFromPaste':
          e.preventDefault();
          if (e.data) type(e.data);
          break;
        case 'insertLineBreak':
        case 'insertParagraph':
          e.preventDefault();
          press(KEYSYM.enter);
          break;
        case 'deleteContentBackward':
          e.preventDefault();
          press(KEYSYM.backspace);
          break;
        case 'deleteContentForward':
          e.preventDefault();
          press(KEYSYM.del);
          break;
        default:
          // Composition (IME) input cannot be cancelled; handled on compositionend.
          break;
      }
    };
    const onCompositionEnd = (e: CompositionEvent) => {
      if (e.data) type(e.data);
      reset();
    };
    const onKeyDown = (e: KeyboardEvent) => {
      const keysym = SPECIAL_KEYS[e.key];
      if (keysym === undefined || e.isComposing) return;
      e.preventDefault();
      press(keysym);
    };
    // Fallback for browsers that skip (or do not let us cancel) beforeinput.
    const onInput = (e: Event) => {
      if ((e as InputEvent).isComposing) return;
      const v = ta.value;
      if (v === ' ') return;
      if (v === '') press(KEYSYM.backspace);
      else type(v.startsWith(' ') ? v.slice(1) : v);
      reset();
    };
    ta.addEventListener('beforeinput', onBeforeInput);
    ta.addEventListener('compositionend', onCompositionEnd);
    ta.addEventListener('keydown', onKeyDown);
    ta.addEventListener('input', onInput);
    this.#cleanup.push(() => {
      ta.removeEventListener('beforeinput', onBeforeInput);
      ta.removeEventListener('compositionend', onCompositionEnd);
      ta.removeEventListener('keydown', onKeyDown);
      ta.removeEventListener('input', onInput);
    });
  }

  /**
   * Keep the "starting" overlay until something visible is drawn. Signing
   * in to a remote computer can take several seconds of black screen.
   */
  #watchForFirstPicture(): void {
    const probe = document.createElement('canvas');
    probe.width = probe.height = 24;
    const ctx = probe.getContext('2d', { willReadFrequently: true });
    const started = Date.now();
    let connectedAt = 0;
    const tick = () => {
      if (this.#stopped || this.#ready) return;
      const now = Date.now();
      if (this.#state === Guacamole.Client.State.CONNECTED) {
        connectedAt ||= now;
        if (now - connectedAt > 20_000 || (ctx && this.#hasVisiblePixels(ctx))) return this.#markReady();
      }
      if (now - started > 8000) {
        this.#els.loadingText.textContent = 'Still starting… signing in to the remote computer can take a little while.';
      }
      setTimeout(tick, 300);
    };
    setTimeout(tick, 300);
  }

  #hasVisiblePixels(ctx: CanvasRenderingContext2D): boolean {
    const src = this.#client.getDisplay().getDefaultLayer().getCanvas();
    if (!src.width || !src.height) return false;
    ctx.clearRect(0, 0, 24, 24);
    ctx.drawImage(src, 0, 0, 24, 24);
    const px = ctx.getImageData(0, 0, 24, 24).data;
    for (let i = 0; i < px.length; i += 4) if (px[i]! + px[i + 1]! + px[i + 2]! > 40) return true;
    return false;
  }

  #markReady(): void {
    this.#ready = true;
    this.#setLoading(false);
    this.#cb.onReady?.();
  }

  #setLoading(on: boolean, text?: string): void {
    this.#els.loading.hidden = !on;
    if (text) this.#els.loadingText.textContent = text;
  }
}

/** Remote screen size for a container, in device pixels. */
export function remoteSize(el: HTMLElement): { width: number; height: number; dpi: number } {
  const density = window.devicePixelRatio || 1;
  return {
    width: Math.round(el.clientWidth * density),
    height: Math.round(el.clientHeight * density),
    dpi: Math.round(96 * density),
  };
}
