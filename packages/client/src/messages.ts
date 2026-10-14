// Turns protocol errors and close reasons into text people can act on.
// Kept free of DOM access so it can be unit tested in Node.

import { AuthError, IntegrityError, PinMismatchError, RelayError } from '@wrhs/protocol';

export type Tone = 'error' | 'warn' | 'info';

export interface Notice {
  title: string;
  text: string;
  tone: Tone;
  /** Label for the main button on the closed screen. */
  action: string;
  /** True for security events: the UI must not nudge the user to retry. */
  security?: boolean;
}

export function describeKeyError(): string {
  return 'That doesn’t look like an agent key. It is the 43-character “Agent public key” shown by wrhs-agent show.';
}

export function describeRelayUrlError(raw: string): string {
  if (!raw.trim()) return 'Enter the relay address, for example https://relay.example.com.';
  return 'The relay address must start with https://, for example https://relay.example.com.';
}

/** Errors while connecting, before the encrypted session exists. */
export function describeConnectError(err: Error, relayHost: string): Notice | string {
  if (err instanceof PinMismatchError) {
    return {
      title: 'Possible interception detected',
      text:
        'The server did not prove it is your agent: its key does not match the one built into this launcher. ' +
        'Someone on this network may be trying to intercept your connection. Nothing was sent. ' +
        'Do not try again from this network until you have checked with your administrator.',
      tone: 'error',
      action: 'Back to start',
      security: true,
    };
  }
  if (err instanceof RelayError) {
    switch (err.code) {
      case 'agent-offline':
        return 'Your agent is not connected to the relay right now. Check that the agent is running, then try again.';
      case 'rate-limited':
        return 'Too many connection attempts from this network. Wait a minute, then try again.';
      case 'busy':
        return 'The agent is handling too many sessions right now. Try again shortly.';
      default:
        return `The relay refused the connection (${err.code}).`;
    }
  }
  if (/unsupported|expected handshake/.test(err.message)) {
    return 'The agent could not complete the secure handshake. It may be running a different WRHS version.';
  }
  return `Can’t reach the relay at ${relayHost}. Check your network connection, or the relay may be down.`;
}

/** Failed sign-in attempt. */
export function describeAuthError(err: unknown): string {
  if (!(err instanceof AuthError)) return 'Sign-in failed: the connection was lost.';
  if (err.message === 'account temporarily locked') {
    const minutes = Math.max(1, Math.ceil((err.retryAfterMs ?? 60_000) / 60_000));
    return `Too many failed sign-ins for this account. Try again in about ${minutes} minute${minutes === 1 ? '' : 's'}.`;
  }
  if (err.message === 'too many attempts in progress') {
    return 'Another sign-in for this account is in progress. Wait a moment, then try again.';
  }
  let text = 'Sign-in failed. Check your user name, password and authenticator code.';
  if (err.attemptsLeft === 1) text += ' One attempt left before you need to reconnect.';
  else if (err.attemptsLeft !== undefined && err.attemptsLeft > 1) text += ` ${err.attemptsLeft} attempts left.`;
  return text;
}

const CLOSE_REASONS: Record<string, string> = {
  'too many failed logins': 'Too many failed sign-in attempts on this connection.',
  'authentication timeout': 'Sign-in took too long, so the agent closed the connection.',
  'handshake timeout': 'The secure connection could not be completed in time.',
  'idle timeout': 'You were signed out after a period of inactivity.',
  'maximum session length reached': 'The session reached its maximum length and was closed.',
  'agent shutting down': 'The agent is shutting down or restarting.',
  'relay closed the session': 'The relay ended the session.',
  'lost connection to relay': 'The agent lost its connection to the relay.',
  'relay no longer knows this session': 'The connection was lost for too long and the session expired.',
  'session expired': 'The connection was lost for too long and the session expired.',
  'peer unreachable': 'The connection to your agent was lost for too long.',
  'internal error': 'The agent hit an internal error and closed the session.',
};

/** The encrypted session ended. */
export function describeClose(reason: string, error: Error | undefined, userInitiated: boolean): Notice {
  if (error instanceof IntegrityError) {
    return {
      title: 'Connection stopped: traffic was modified',
      text:
        'Data arriving from the network failed its integrity check, so something between you and your agent ' +
        'changed it. The session was closed to protect you; nothing that was changed was used.',
      tone: 'error',
      action: 'Back to start',
      security: true,
    };
  }
  if (userInitiated) {
    return { title: 'Signed out', text: 'You signed out. Your session on the agent has ended.', tone: 'info', action: 'Connect again' };
  }
  const known = CLOSE_REASONS[reason];
  return {
    title: 'Disconnected',
    text: known ?? (reason ? `The connection was closed (${reason}).` : 'The connection was closed.'),
    tone: 'warn',
    action: 'Connect again',
  };
}

export function formatCountdown(ms: number): string {
  const s = Math.max(0, Math.ceil(ms / 1000));
  if (s < 90) return `${s} second${s === 1 ? '' : 's'}`;
  const m = Math.round(s / 60);
  return `${m} minute${m === 1 ? '' : 's'}`;
}

/** What the browser RDP client (IronRDP) throws: an IronError, or a plain Error. */
interface RdpErrorLike {
  kind?: () => number;
  backtrace?: () => string;
  rdcleanpathDetails?: () => { wsaErrorCode?: number; tlsAlertCode?: number } | undefined;
}

const RDP_KIND = { wrongPassword: 1, logonFailure: 2, accessDenied: 3, rdcleanpath: 4, proxyConnect: 5, negotiation: 6 } as const;

/** The built-in RDP client could not connect, or failed later. */
export function describeRdpError(err: unknown, name: string): string {
  const e = (err ?? {}) as RdpErrorLike;
  let kind = -1;
  let detail = '';
  try {
    kind = typeof e.kind === 'function' ? e.kind() : -1;
    detail = typeof e.backtrace === 'function' ? e.backtrace() : err instanceof Error ? err.message : '';
  } catch {
    // The error object is no longer usable.
  }
  const wrongCredentials =
    `${name} did not accept the user name or password. Use the account you sign in to that computer with ` +
    '(for a Microsoft account: its email address and password, not the PIN).';
  if (kind === RDP_KIND.wrongPassword || kind === RDP_KIND.logonFailure) return wrongCredentials;
  if (kind === RDP_KIND.accessDenied) {
    return `${name} does not let this account connect remotely. It must be an administrator or in the Remote Desktop Users group.`;
  }
  if (kind === RDP_KIND.rdcleanpath) {
    let wsa: number | undefined;
    try {
      wsa = e.rdcleanpathDetails?.()?.wsaErrorCode;
    } catch {
      wsa = undefined;
    }
    if (wsa === 10061) return `Remote Desktop is not accepting connections on ${name}. Check that Remote Desktop is turned on.`;
    if (wsa === 10060) return `${name} did not answer in time. It may be turned off or asleep.`;
    if (/certificate .* does not match/.test(detail)) {
      return `${name} presented an unexpected certificate, so the agent stopped the connection. Ask your administrator to check it.`;
    }
    return `The agent could not start a remote desktop on ${name}.`;
  }
  if (kind === RDP_KIND.proxyConnect) return 'The encrypted connection was interrupted while the remote desktop was starting.';
  if (kind === RDP_KIND.negotiation) {
    return `${name} refused the connection’s security settings (for example, it requires Network Level Authentication). Ask your administrator to check the agent’s settings for this computer.`;
  }
  if (/LOGON_DENIED|logon failure|wrong password|0xc000006d|STATUS_LOGON_FAILURE/i.test(detail)) return wrongCredentials;
  if (/ACCOUNT_RESTRICTION|PASSWORD_EXPIRED|PASSWORD_MUST_CHANGE|0xc0000224|0xc0000071/i.test(detail)) {
    return `${name} needs the password of this account to be changed. Sign in at that computer once to change it.`;
  }
  return `The remote desktop connection to ${name} failed.`;
}

/** The RDP session ended normally; `reason` is the server's explanation. */
export function describeRdpEnd(reason: string, name: string): string {
  const r = reason.trim().replace(/\.$/, '');
  return r ? `The remote desktop session on ${name} ended: ${r}.` : `The remote desktop session on ${name} ended.`;
}
