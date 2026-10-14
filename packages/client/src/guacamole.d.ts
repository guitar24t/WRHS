// Minimal typings for the parts of guacamole-common-js the client uses.
declare module '*/guacamole-common.js' {
  const Guacamole: GuacamoleNS;
  export default Guacamole;
}

interface GuacTunnel {
  state: number;
  uuid: string | null;
  setState(state: number): void;
  connect(data?: string): void;
  disconnect(): void;
  sendMessage(...elements: unknown[]): void;
  oninstruction: ((opcode: string, args: string[]) => void) | null;
  onstatechange: ((state: number) => void) | null;
  onerror: ((status: GuacStatus) => void) | null;
}

interface GuacStatus {
  code: number;
  message?: string;
}

interface GuacDisplay {
  getElement(): HTMLElement;
  getWidth(): number;
  getHeight(): number;
  scale(s: number): void;
  getScale(): number;
  showCursor(shown: boolean): void;
  onresize: ((w: number, h: number) => void) | null;
}

interface GuacClient {
  connect(data?: string): void;
  disconnect(): void;
  getDisplay(): GuacDisplay;
  sendSize(w: number, h: number): void;
  sendKeyEvent(pressed: 0 | 1, keysym: number): void;
  sendMouseState(state: unknown, applyDisplayScale?: boolean): void;
  createClipboardStream(mimetype: string): unknown;
  onstatechange: ((state: number) => void) | null;
  onerror: ((status: GuacStatus) => void) | null;
  onclipboard: ((stream: unknown, mimetype: string) => void) | null;
  onname: ((name: string) => void) | null;
}

interface GuacKeyboard {
  onkeydown: ((keysym: number) => boolean | void) | null;
  onkeyup: ((keysym: number) => void) | null;
  reset(): void;
}

interface GuacMouse {
  onEach(types: string[], fn: (e: { state: unknown }) => void): void;
}

interface GuacamoleNS {
  Tunnel: { new (): GuacTunnel; State: { CONNECTING: number; OPEN: number; CLOSED: number; UNSTABLE: number } };
  Client: { new (tunnel: GuacTunnel): GuacClient; State: Record<string, number> };
  Parser: {
    new (): { receive(packet: string): void; oninstruction: ((opcode: string, args: string[]) => void) | null };
    toInstruction(elements: ArrayLike<unknown>): string;
  };
  Keyboard: new (element: HTMLElement | Document) => GuacKeyboard;
  Mouse: new (element: HTMLElement) => GuacMouse;
  Status: { new (code: number, message?: string): GuacStatus; Code: Record<string, number> };
  StringReader: new (stream: unknown) => { ontext: ((t: string) => void) | null; onend: (() => void) | null };
  StringWriter: new (stream: unknown) => { sendText(t: string): void; sendEnd(): void };
}
