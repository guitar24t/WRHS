// Agent configuration (JSON). Paths are resolved relative to the config file.

import { readFileSync, writeFileSync, renameSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

export interface UserConfig {
  name: string;
  passwordHash: string;
  totpSecret?: string;
  /** Target ids this user may open, or "*" for all. */
  targets: string[] | '*';
  /** Optional allow-list of client device keys (base64url). Empty/absent = any device. */
  deviceKeys?: string[];
}

export interface TargetConfig {
  id: string;
  name: string;
  protocol: 'rdp';
  hostname: string;
  port?: number;
  domain?: string;
  /** Stored RDP credentials. If username is absent, the client is asked for credentials. */
  username?: string;
  password?: string;
  security?: 'any' | 'nla' | 'nla-ext' | 'tls' | 'rdp' | 'vmconnect';
  ignoreCert?: boolean;
  clipboard?: 'both' | 'copy' | 'paste' | 'none';
  fileTransfer?: boolean;
  audio?: boolean;
  extraParams?: Record<string, string>;
}

export interface AgentConfig {
  name: string;
  relayUrl: string;
  /** Secret the relay uses to authorize this agent's registration (routing only). */
  relayToken: string;
  keyFile: string;
  guacd: { host: string; port: number };
  users: UserConfig[];
  targets: TargetConfig[];
  policy: {
    requireTotp: boolean;
    maxAuthFailures: number;
    lockoutSeconds: number;
    /** Close sessions that are not authenticated within this time. */
    authTimeoutSeconds: number;
    /** Close sessions with no user input for this long. 0 disables. */
    idleTimeoutSeconds: number;
    /** Hard cap on session length (limits key lifetime too). */
    maxSessionSeconds: number;
  };
}

export const DEFAULT_POLICY: AgentConfig['policy'] = {
  requireTotp: true,
  maxAuthFailures: 5,
  lockoutSeconds: 300,
  authTimeoutSeconds: 120,
  idleTimeoutSeconds: 3600,
  maxSessionSeconds: 12 * 3600,
};

export function loadConfig(path: string): AgentConfig {
  const raw = JSON.parse(readFileSync(path, 'utf8')) as Partial<AgentConfig>;
  const cfg: AgentConfig = {
    name: raw.name ?? 'wrhs-agent',
    relayUrl: req(raw.relayUrl, 'relayUrl'),
    relayToken: req(raw.relayToken, 'relayToken'),
    keyFile: resolve(dirname(path), raw.keyFile ?? 'agent.key.json'),
    guacd: { host: raw.guacd?.host ?? '127.0.0.1', port: raw.guacd?.port ?? 4822 },
    users: raw.users ?? [],
    targets: raw.targets ?? [],
    policy: { ...DEFAULT_POLICY, ...(raw.policy ?? {}) },
  };
  const url = new URL(cfg.relayUrl);
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new Error('relayUrl must be http(s)');
  const ids = new Set<string>();
  for (const t of cfg.targets) {
    if (!t.id || ids.has(t.id)) throw new Error(`duplicate or missing target id: ${t.id}`);
    if (t.protocol !== 'rdp') throw new Error(`target ${t.id}: only protocol "rdp" is supported`);
    if (!t.hostname) throw new Error(`target ${t.id}: hostname is required`);
    ids.add(t.id);
  }
  for (const u of cfg.users) {
    if (!u.name || !u.passwordHash?.startsWith('scrypt$')) throw new Error(`user ${u.name}: invalid passwordHash`);
    if (cfg.policy.requireTotp && !u.totpSecret) throw new Error(`user ${u.name}: TOTP is required by policy`);
  }
  return cfg;
}

function req<T>(v: T | undefined, name: string): T {
  if (v === undefined || v === null || v === '') throw new Error(`config: ${name} is required`);
  return v;
}

/** Read-modify-write the raw JSON (keeps fields we do not model). */
export function updateConfigFile(path: string, fn: (raw: Record<string, unknown>) => void): void {
  const raw = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
  fn(raw);
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, JSON.stringify(raw, null, 2) + '\n', { mode: 0o600 });
  renameSync(tmp, path);
}
