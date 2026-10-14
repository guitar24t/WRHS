// A Guacamole tunnel that carries instructions inside the end-to-end
// encrypted session instead of a plain WebSocket/HTTP connection.

import Guacamole from '../vendor/guacamole-common-js/guacamole-common.js';
import type { AppChannel } from '@wrhs/protocol';

export function createEncryptedTunnel(app: AppChannel): GuacTunnel {
  const tunnel = new Guacamole.Tunnel();
  const parser = new Guacamole.Parser();
  const decoder = new TextDecoder();
  parser.oninstruction = (opcode, args) => tunnel.oninstruction?.(opcode, args);

  const off = app.on('guac', (data) => {
    if (tunnel.state === Guacamole.Tunnel.State.CLOSED) return;
    try {
      parser.receive(decoder.decode(data, { stream: true }));
    } catch (err) {
      fail(Guacamole.Status.Code.SERVER_ERROR ?? 0x0200, (err as Error).message);
    }
  });
  app.session.on('close', (info) => fail(Guacamole.Status.Code.UPSTREAM_UNAVAILABLE ?? 0x0201, info.reason));

  function fail(code: number, message: string) {
    if (tunnel.state === Guacamole.Tunnel.State.CLOSED) return;
    tunnel.onerror?.(new Guacamole.Status(code, message));
    tunnel.setState(Guacamole.Tunnel.State.CLOSED);
    off();
  }

  tunnel.connect = () => tunnel.setState(Guacamole.Tunnel.State.OPEN);
  tunnel.disconnect = () => {
    off();
    tunnel.setState(Guacamole.Tunnel.State.CLOSED);
  };
  tunnel.sendMessage = (...elements: unknown[]) => {
    if (tunnel.state !== Guacamole.Tunnel.State.OPEN || elements.length === 0 || !app.session.writable) return;
    app.sendGuac(Guacamole.Parser.toInstruction(elements));
  };
  return tunnel;
}
