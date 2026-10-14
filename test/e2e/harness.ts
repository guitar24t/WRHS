import { createHash } from 'node:crypto';
import { createRelay, type Relay } from '@wrhs/relay';
import {
  createAgent,
  DEFAULT_POLICY,
  generateTotpSecret,
  hashPassword,
  totpCode,
  type AgentConfig,
  type RelayLink,
} from '@wrhs/agent';
import { agentIdFromPublicKey, generateKeyPair, type KeyPair } from '@wrhs/protocol';
import { startFakeGuacd, type FakeGuacd } from './fake-guacd.ts';
import { PROTOCOL_HYBRID, startFakeRdpServer, type FakeRdpServer } from './fake-rdp-server.ts';
import { startMitm, type Mitm } from './mitm-proxy.ts';

export const PASSWORD = 'SECRET-correct-horse-battery';
export const RDP_USER = 'SECRET-RDP-USER';
export const RDP_PASS = 'SECRET-RDP-PASS-9f8e7d';
export const INTERNAL_HOST = 'SECRET-INTERNAL-HOST.corp.example';
export const DESKTOP_NAME = 'SECRET-DESKTOP-NAME';

export const RDP_TARGET_NAME = 'SECRET-THIS-PC-NAME';

export interface Stack {
  guacd: FakeGuacd;
  /** Present when started with `rdp: true`: target "this-pc" (built-in engine) points at it. */
  rdpServer: FakeRdpServer | null;
  relay: Relay;
  relayUrl: string;
  agent: RelayLink;
  agentKey: KeyPair;
  mitm: Mitm;
  totpSecret: string;
  agentLog: Record<string, unknown>[];
  currentTotp(): string;
  close(): Promise<void>;
}

export async function startStack(
  overrides: { policy?: Partial<AgentConfig['policy']>; banner?: string[][]; rdp?: boolean } = {},
): Promise<Stack> {
  const guacd = await startFakeGuacd({
    bannerAfterReady: overrides.banner ?? [['name', DESKTOP_NAME], ['size', '0', '1024', '768']],
  });
  // Like Windows with Network Level Authentication: TLS, then CredSSP.
  const rdpServer = overrides.rdp ? await startFakeRdpServer({ protocol: PROTOCOL_HYBRID }) : null;
  const agentKey = generateKeyPair();
  const token = 'relay-token-' + Math.random().toString(36).slice(2);
  const agentTokens = new Map([[agentIdFromPublicKey(agentKey.publicKey), createHash('sha256').update(token).digest()]]);
  const relay = createRelay({ agentTokens, longPollWaitMs: 2000 });
  const relayPort = await relay.listen(0, '127.0.0.1');
  const relayUrl = `http://127.0.0.1:${relayPort}`;
  const totpSecret = generateTotpSecret();
  const config: AgentConfig = {
    name: 'test-agent',
    relayUrl,
    relayToken: token,
    keyFile: '',
    guacd: { host: '127.0.0.1', port: guacd.port },
    users: [{ name: 'alice', passwordHash: await hashPassword(PASSWORD), totpSecret, targets: '*' }],
    targets: [
      { id: 'office-pc', name: 'Office PC', protocol: 'rdp', engine: 'guacd', hostname: INTERNAL_HOST, port: 3389, security: 'nla', ignoreCert: true },
      ...(rdpServer
        ? [{ id: 'this-pc', name: RDP_TARGET_NAME, protocol: 'rdp' as const, hostname: '127.0.0.1', port: rdpServer.port, username: RDP_USER }]
        : []),
    ],
    policy: { ...DEFAULT_POLICY, ...overrides.policy },
  };
  const agentLog: Record<string, unknown>[] = [];
  const agent = createAgent(config, agentKey, { log: (event, fields) => agentLog.push({ event, ...fields }) });
  agent.start();
  await agent.online();
  const mitm = await startMitm(relayUrl);
  return {
    guacd,
    rdpServer,
    relay,
    relayUrl,
    agent,
    agentKey,
    mitm,
    totpSecret,
    agentLog,
    currentTotp: () => totpCode(totpSecret, Math.floor(Date.now() / 30_000)),
    async close() {
      agent.stop();
      await mitm.close();
      await relay.close();
      await guacd.close();
      await rdpServer?.close();
    },
  };
}

export async function waitFor(cond: () => boolean, timeoutMs = 10_000, what = 'condition'): Promise<void> {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > timeoutMs) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 10));
  }
}
