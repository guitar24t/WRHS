#!/usr/bin/env node
// wrhs-agent command line.

import { createHash, randomBytes } from 'node:crypto';
import { existsSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { parseArgs } from 'node:util';
import { agentIdFromPublicKey, decodeKey, encodeKey, fingerprint } from '@wrhs/protocol';
import { generateTotpSecret, hashPassword, otpauthUri } from './auth.ts';
import { DEFAULT_POLICY, loadConfig, updateConfigFile, type TargetConfig, type UserConfig } from './config.ts';
import { createKey, loadKey } from './keys.ts';
import { renderLauncher } from './launcher.ts';
import { runAgent } from './agent.ts';

const USAGE = `wrhs-agent <command> [options]

Commands
  init        --relay <https://relay> [--name <name>]      create identity key + config
  add-user    <name> [--targets a,b|*] [--no-totp]         add a user (prompts for password)
  add-target  --id <id> --name <name> --host <host> [--port 3389] [--security any|nla|tls|rdp]
              [--ignore-cert] [--rdp-user <u> --rdp-password <p> --domain <d>]
  enroll-device <user> <device-key>                        restrict a user to a device key
  launcher    --out <file.html> [--public-url <url>] [--also-pin <key>]...
                                                           write a personalized offline launcher
                                                           (--public-url: relay URL as browsers see it;
                                                            --also-pin: extra agent keys, for key rollover)
  show                                                     print identity and relay registration
  registration                                             print this agent's relay entry as JSON
  run                                                      connect to the relay and serve sessions

Global options
  --config <path>   agent config file (default ./agent.json or $WRHS_AGENT_CONFIG)
`;

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    config: { type: 'string' },
    relay: { type: 'string' },
    name: { type: 'string' },
    targets: { type: 'string' },
    'no-totp': { type: 'boolean' },
    id: { type: 'string' },
    host: { type: 'string' },
    port: { type: 'string' },
    security: { type: 'string' },
    'ignore-cert': { type: 'boolean' },
    'rdp-user': { type: 'string' },
    'rdp-password': { type: 'string' },
    domain: { type: 'string' },
    out: { type: 'string' },
    'public-url': { type: 'string' },
    'also-pin': { type: 'string', multiple: true },
    help: { type: 'boolean', short: 'h' },
  },
});

const configPath = resolve(values.config ?? process.env.WRHS_AGENT_CONFIG ?? 'agent.json');
const [command, ...args] = positionals;

async function promptPassword(question: string): Promise<string> {
  if (process.env.WRHS_PASSWORD) return process.env.WRHS_PASSWORD;
  const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  const out = rl as unknown as { _writeToOutput: (s: string) => void; output: NodeJS.WriteStream };
  let muted = false;
  out._writeToOutput = (s: string) => {
    if (!muted || s.includes(question)) out.output.write(s);
  };
  const answer = await new Promise<string>((r) => {
    rl.question(question, r);
    muted = true;
  });
  rl.close();
  process.stdout.write('\n');
  return answer;
}

function printIdentity(): void {
  const cfg = loadConfig(configPath);
  const key = loadKey(cfg.keyFile);
  const agentId = agentIdFromPublicKey(key.publicKey);
  console.log(`Agent name:        ${cfg.name}`);
  console.log(`Relay:             ${cfg.relayUrl}`);
  console.log(`Agent id:          ${agentId}`);
  console.log(`Agent public key:  ${encodeKey(key.publicKey)}`);
  console.log(`Fingerprint:       ${fingerprint(key.publicKey)}`);
  console.log('');
  console.log('Relay registration (add to the relay\'s RELAY_AGENTS_FILE):');
  console.log(`  "${agentId}": "${createHash('sha256').update(cfg.relayToken).digest('hex')}"`);
}

async function main(): Promise<void> {
  if (values.help || !command) {
    console.log(USAGE);
    return;
  }
  switch (command) {
    case 'init': {
      if (!values.relay) throw new Error('--relay is required');
      if (existsSync(configPath)) throw new Error(`${configPath} already exists`);
      const keyFile = resolve(dirname(configPath), 'agent.key.json');
      createKey(keyFile);
      const raw = {
        name: values.name ?? 'wrhs-agent',
        relayUrl: values.relay,
        relayToken: randomBytes(32).toString('base64url'),
        keyFile: 'agent.key.json',
        guacd: { host: '127.0.0.1', port: 4822 },
        users: [],
        targets: [],
        policy: DEFAULT_POLICY,
      };
      writeFileSync(configPath, JSON.stringify(raw, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
      console.log(`Created ${configPath} and ${keyFile}\n`);
      printIdentity();
      console.log('\nNext: wrhs-agent add-target ..., wrhs-agent add-user <name>, wrhs-agent launcher --out launcher.html');
      return;
    }
    case 'add-user': {
      const name = args[0];
      if (!name || !/^[A-Za-z0-9._@-]{1,64}$/.test(name)) throw new Error('usage: add-user <name>');
      const pw = await promptPassword(`Password for ${name}: `);
      const passwordHash = await hashPassword(pw);
      const totpSecret = values['no-totp'] ? undefined : generateTotpSecret();
      const targets = !values.targets || values.targets === '*' ? '*' : values.targets.split(',').map((s) => s.trim());
      updateConfigFile(configPath, (raw) => {
        const users = (raw.users as UserConfig[] | undefined) ?? [];
        if (users.some((u) => u.name.toLowerCase() === name.toLowerCase())) throw new Error(`user ${name} exists`);
        users.push({ name, passwordHash, ...(totpSecret ? { totpSecret } : {}), targets });
        raw.users = users;
      });
      console.log(`Added user ${name}.`);
      if (totpSecret) {
        const cfg = loadConfig(configPath);
        console.log('\nAdd this to the user\'s authenticator app (scan as QR code or enter the secret):');
        console.log(`  ${otpauthUri(totpSecret, name, `WRHS ${cfg.name}`)}`);
        console.log(`  secret: ${totpSecret}`);
      }
      return;
    }
    case 'add-target': {
      if (!values.id || !values.name || !values.host) throw new Error('--id, --name and --host are required');
      const t: TargetConfig = {
        id: values.id,
        name: values.name,
        protocol: 'rdp',
        hostname: values.host,
        port: values.port ? Number(values.port) : 3389,
        security: (values.security as TargetConfig['security']) ?? 'any',
        ignoreCert: Boolean(values['ignore-cert']),
        clipboard: 'both',
        fileTransfer: false,
        audio: true,
      };
      if (values['rdp-user']) t.username = values['rdp-user'];
      if (values['rdp-password']) t.password = values['rdp-password'];
      if (values.domain) t.domain = values.domain;
      updateConfigFile(configPath, (raw) => {
        const targets = (raw.targets as TargetConfig[] | undefined) ?? [];
        if (targets.some((x) => x.id === t.id)) throw new Error(`target ${t.id} exists`);
        targets.push(t);
        raw.targets = targets;
      });
      console.log(`Added target ${t.id}.`);
      return;
    }
    case 'enroll-device': {
      const [user, deviceKey] = args;
      if (!user || !deviceKey) throw new Error('usage: enroll-device <user> <device-key>');
      updateConfigFile(configPath, (raw) => {
        const u = ((raw.users as UserConfig[] | undefined) ?? []).find((x) => x.name === user);
        if (!u) throw new Error(`no user ${user}`);
        u.deviceKeys = [...new Set([...(u.deviceKeys ?? []), deviceKey])];
      });
      console.log(`User ${user} may now only sign in from enrolled devices.`);
      return;
    }
    case 'launcher': {
      if (!values.out) throw new Error('--out is required');
      const cfg = loadConfig(configPath);
      const key = loadKey(cfg.keyFile);
      const r = renderLauncher({
        relayUrl: values['public-url'] ?? cfg.relayUrl,
        agentPublicKeys: [key.publicKey, ...(values['also-pin'] ?? []).map(decodeKey)],
        name: cfg.name,
      });
      writeFileSync(values.out, r.html);
      console.log(`Wrote ${values.out}`);
      console.log(`  SHA-256:      ${r.sha256}`);
      console.log(`  pins agent:   ${r.fingerprint}`);
      console.log('Copy it to the client device over a trusted channel and open it from disk.');
      return;
    }
    case 'show':
      printIdentity();
      return;
    case 'registration': {
      const cfg = loadConfig(configPath);
      const id = agentIdFromPublicKey(loadKey(cfg.keyFile).publicKey);
      console.log(JSON.stringify({ [id]: createHash('sha256').update(cfg.relayToken).digest('hex') }, null, 2));
      return;
    }
    case 'run': {
      const link = runAgent(configPath);
      for (const sig of ['SIGINT', 'SIGTERM'] as const) {
        process.on(sig, () => {
          link.stop();
          setTimeout(() => process.exit(0), 500).unref();
        });
      }
      return;
    }
    default:
      console.error(USAGE);
      process.exitCode = 2;
  }
}

main().catch((err: Error) => {
  console.error(`error: ${err.message}`);
  process.exitCode = 1;
});
