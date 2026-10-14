// Pieces shared by the two desktop views (built-in RDP and Guacamole).

export const isTouchDevice = (): boolean =>
  (typeof matchMedia === 'function' && matchMedia('(pointer: coarse)').matches) || navigator.maxTouchPoints > 0;

export interface RemoteElements {
  container: HTMLElement;
  loading: HTMLElement;
  loadingText: HTMLElement;
  softKeyboard: HTMLTextAreaElement;
}

export interface RemoteCallbacks {
  /** The desktop failed or ended; `message` says why, for the user. */
  onError(message: string): void;
  /** The first picture arrived (or we gave up waiting for one). */
  onReady?(): void;
}

/** What main.ts needs from a desktop view. */
export interface DesktopView {
  readonly ready: boolean;
  /** Time of the last input sent to the remote desktop (for idle warnings). */
  readonly lastInputAt: number;
  start(): void;
  stop(): void;
  resize(): void;
  sendCtrlAltDel(): void;
  sendClipboardText(text: string): void;
  showSoftKeyboard(): void;
  focus(): void;
  /**
   * The agent says the connection to the remote computer ended. A view that
   * can explain why (the RDP client may have the server's reason) reports it
   * through onError; otherwise main.ts shows a generic notice.
   */
  remoteClosed?(): void;
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

export type SoftKey = 'Backspace' | 'Enter' | 'Tab' | 'Escape' | 'Delete' | 'ArrowLeft' | 'ArrowUp' | 'ArrowRight' | 'ArrowDown';
const SOFT_KEYS = new Set<string>(['Backspace', 'Enter', 'Tab', 'Escape', 'Delete', 'ArrowLeft', 'ArrowUp', 'ArrowRight', 'ArrowDown']);

/** Raise the phone/tablet keyboard (must run inside a user gesture). */
export function showSoftKeyboard(ta: HTMLTextAreaElement): void {
  ta.value = ' ';
  ta.focus();
  ta.setSelectionRange(1, 1);
}

/**
 * Phone and tablet keyboards do not produce reliable key events, so text
 * goes through a hidden field: each insertion is typed into the remote
 * desktop and the field is reset. A single space stays in the field so
 * Backspace always has something to delete (and so fires an event).
 * Returns a function that removes the listeners.
 */
export function wireSoftKeyboard(
  ta: HTMLTextAreaElement,
  h: { type(text: string): void; press(key: SoftKey): void },
): () => void {
  const reset = () => {
    ta.value = ' ';
    ta.setSelectionRange(1, 1);
  };
  const onBeforeInput = (e: InputEvent) => {
    switch (e.inputType) {
      case 'insertText':
      case 'insertReplacementText':
      case 'insertFromPaste':
        e.preventDefault();
        if (e.data) h.type(e.data);
        break;
      case 'insertLineBreak':
      case 'insertParagraph':
        e.preventDefault();
        h.press('Enter');
        break;
      case 'deleteContentBackward':
        e.preventDefault();
        h.press('Backspace');
        break;
      case 'deleteContentForward':
        e.preventDefault();
        h.press('Delete');
        break;
      default:
        // Composition (IME) input cannot be cancelled; handled on compositionend.
        break;
    }
  };
  const onCompositionEnd = (e: CompositionEvent) => {
    if (e.data) h.type(e.data);
    reset();
  };
  const onKeyDown = (e: KeyboardEvent) => {
    if (!SOFT_KEYS.has(e.key) || e.isComposing) return;
    e.preventDefault();
    h.press(e.key as SoftKey);
  };
  // Fallback for browsers that skip (or do not let us cancel) beforeinput.
  const onInput = (e: Event) => {
    if ((e as InputEvent).isComposing) return;
    const v = ta.value;
    if (v === ' ') return;
    if (v === '') h.press('Backspace');
    else h.type(v.startsWith(' ') ? v.slice(1) : v);
    reset();
  };
  ta.addEventListener('beforeinput', onBeforeInput);
  ta.addEventListener('compositionend', onCompositionEnd);
  ta.addEventListener('keydown', onKeyDown);
  ta.addEventListener('input', onInput);
  return () => {
    ta.removeEventListener('beforeinput', onBeforeInput);
    ta.removeEventListener('compositionend', onCompositionEnd);
    ta.removeEventListener('keydown', onKeyDown);
    ta.removeEventListener('input', onInput);
  };
}

/** True when a downscaled copy of `src` has anything brighter than near-black. */
export function hasVisiblePixels(src: HTMLCanvasElement, probe: CanvasRenderingContext2D): boolean {
  if (!src.width || !src.height) return false;
  probe.clearRect(0, 0, 24, 24);
  probe.drawImage(src, 0, 0, 24, 24);
  const px = probe.getImageData(0, 0, 24, 24).data;
  for (let i = 0; i < px.length; i += 4) if (px[i]! + px[i + 1]! + px[i + 2]! > 40) return true;
  return false;
}

/**
 * Calls `ready` once `canvas()` shows something, or `connected()` has been
 * true for 20 s (a black desktop is possible). Updates the "starting" text
 * after 8 s. Returns a function that stops watching.
 */
export function watchForFirstPicture(o: {
  canvas(): HTMLCanvasElement | null;
  connected(): boolean;
  ready(): void;
  slow(): void;
}): () => void {
  const probe = document.createElement('canvas');
  probe.width = probe.height = 24;
  const ctx = probe.getContext('2d', { willReadFrequently: true });
  const started = Date.now();
  let connectedAt = 0;
  let slowShown = false;
  let timer: ReturnType<typeof setTimeout> | null = null;
  const tick = () => {
    const now = Date.now();
    if (o.connected()) {
      connectedAt ||= now;
      const c = o.canvas();
      if (now - connectedAt > 20_000 || (ctx && c && hasVisiblePixels(c, ctx))) return o.ready();
    }
    if (!slowShown && now - started > 8000) {
      slowShown = true;
      o.slow();
    }
    timer = setTimeout(tick, 300);
  };
  timer = setTimeout(tick, 300);
  return () => {
    if (timer) clearTimeout(timer);
  };
}
