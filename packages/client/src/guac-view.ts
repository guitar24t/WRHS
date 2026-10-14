// Desktop view for the guacd engine: Guacamole client wiring, input (mouse,
// touch, keyboard, on-screen keyboard), cursor, clipboard and the
// "starting" state.

import Guacamole from '../vendor/guacamole-common-js/guacamole-common.js';
import type { AppChannel, SecureSession } from '@wrhs/protocol';
import { createEncryptedTunnel } from './tunnel.ts';
import {
  isTouchDevice,
  remoteSize,
  showSoftKeyboard,
  watchForFirstPicture,
  wireSoftKeyboard,
  type DesktopView,
  type RemoteCallbacks,
  type RemoteElements,
  type SoftKey,
} from './desktop-common.ts';

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

const SOFT_KEYSYMS: Record<SoftKey, number> = {
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

// One keyboard listener for the page: Guacamole.Keyboard has no way to detach.
let sharedKeyboard: GuacKeyboard | null = null;

export class GuacamoleDesktop implements DesktopView {
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

    this.#cleanup.push(
      wireSoftKeyboard(this.#els.softKeyboard, {
        type: (text) => {
          this.#input();
          this.#keyboard.type(text);
        },
        press: (key) => {
          this.#input();
          this.#keyboard.press(SOFT_KEYSYMS[key]);
          this.#keyboard.release(SOFT_KEYSYMS[key]);
        },
      }),
    );
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
    showSoftKeyboard(this.#els.softKeyboard);
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
   * Keep the "starting" overlay until something visible is drawn. Signing
   * in to a remote computer can take several seconds of black screen.
   */
  #watchForFirstPicture(): void {
    this.#cleanup.push(
      watchForFirstPicture({
        canvas: () => this.#client.getDisplay().getDefaultLayer().getCanvas(),
        connected: () => !this.#stopped && this.#state === Guacamole.Client.State.CONNECTED,
        ready: () => this.#markReady(),
        slow: () => {
          this.#els.loadingText.textContent = 'Still starting… signing in to the remote computer can take a little while.';
        },
      }),
    );
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
