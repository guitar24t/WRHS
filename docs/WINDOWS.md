# WRHS on Windows: serve this PC's desktop

This is the main way to run WRHS. Install the agent on the Windows PC you
want to reach. From a browser anywhere, you then get that PC's desktop the
way Remote Desktop gives it to you:

- **Your own session.** Windows' own Remote Desktop service draws the
  desktop at the browser's size. Only the session is sent, not the PC's
  monitors.
- **The PC locks.** While you are connected, the PC's screen shows the lock
  screen, exactly as with a Remote Desktop connection. Your apps keep running
  when you close the desktop; reconnecting picks up where you left off.
- **Works unattended.** The agent is a Windows service: it starts with
  Windows, before anyone signs in, and restarts after failures.

```
 Browser ──HTTPS──▶ [proxy] ──▶ Relay ◀──HTTPS── WRHS Agent service ──loopback──▶ Remote Desktop (this PC)
    ╰────── end-to-end encrypted (Noise), then RDP with NLA inside it ──────╯
```

The agent opens a connection to this PC's own Remote Desktop service on
127.0.0.1 and passes it, through the end-to-end encrypted session, to the
RDP client in your browser (IronRDP, built into the launcher). You sign in
with your Windows account; Network Level Authentication runs in your
browser. Remote Desktop itself is blocked from the network, so WRHS is the
only way in.

## Requirements

- **Windows 10 or 11 Pro, Enterprise or Education, or Windows Server.**
  Windows Home cannot host Remote Desktop sessions; the installer checks.
- **Node.js 22.18 or later, installed for all users** (from
  [nodejs.org](https://nodejs.org) or `winget install OpenJS.NodeJS.LTS`).
- A **relay** reachable from the internet over HTTPS (see
  [DEPLOYMENT.md §1](DEPLOYMENT.md#1-relay)). The PC needs only outbound
  HTTPS to it; nothing is opened inbound.
- The service wrapper ([WinSW](https://github.com/winsw/winsw) 2.12.0) is
  downloaded from GitHub during installation and checked against a pinned
  SHA-256. Offline: pass `-WinSWPath` with a copy of `WinSW.NET461.exe`
  (it runs on the .NET Framework built into Windows).

## Install

1. Build the package (on any machine with the repository):

   ```bash
   npm ci
   npm run package:windows      # creates dist/windows
   ```

   Copy `dist/windows` to the PC.

2. On the PC, open **PowerShell as administrator** in that folder:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\install.ps1 -RelayUrl https://relay.example.com -User alice
   ```

   - It asks for alice's WRHS password and prints the authenticator setup
     (an `otpauth://` link and the secret) for her phone.
   - At the end it prints the agent's identity and its **relay
     registration** entry. Add it to the relay's `agents.json` and restart
     the relay (`docker compose restart relay`, or with the native relay
     install: `sudo deploy/relay/install.sh add-agent '<entry>'`). To print
     the entry again:
     `node "$env:ProgramFiles\WRHS\wrhs-agent.mjs" registration --config "$env:ProgramData\WRHS\agent.json"`.
   - It writes **WRHS launcher.html** to your desktop.

3. Copy the launcher to the devices you will connect from, over a channel
   you trust (USB stick, your own laptop before you travel). Open it from
   disk, sign in with the WRHS user and authenticator code, choose **This
   PC**, and sign in with your Windows account.

### Installer options

| Option | Meaning |
|---|---|
| `-RelayUrl <url>` | Relay address. Required the first time. |
| `-PublicRelayUrl <url>` | Relay address as browsers reach it, if it differs. |
| `-Name <name>` | Agent name shown to users (default: computer name). |
| `-User <name>` | Create a WRHS user (password from the prompt or `$env:WRHS_PASSWORD`). |
| `-RemoteDesktopUser <account>` | Add a Windows account to "Remote Desktop Users". Administrators can already connect. |
| `-AllowNetworkRdp` | Keep Remote Desktop reachable from the local network too, for regular Remote Desktop clients. Remembered for upgrades. |
| `-BlockNetworkRdp` | Block Remote Desktop from the network again, or block it even though someone is connected over the network now. |
| `-LauncherOut <file>` | Where to write the launcher. |
| `-WinSWPath <file>` | Use a local copy of the service wrapper. |
| `-NodePath <node.exe>` | Node.js to run the agent with (default: the one on PATH). |

Running `install.ps1` again upgrades the agent. The configuration, users and
identity key are kept, so existing launchers keep working.

### Regular Remote Desktop on the local network too

By default the installer blocks Remote Desktop from the network, so WRHS is
the only way in. If people on your network also connect with a regular
Remote Desktop client, keep it open:

```powershell
.\install.ps1 -RelayUrl https://relay.example.com -User alice -AllowNetworkRdp
.\install.ps1 -AllowNetworkRdp      # on an installed PC: opens it again
.\install.ps1 -BlockNetworkRdp      # back to WRHS only
```

The choice is kept when you upgrade. If someone is connected over the network
when the installer would block Remote Desktop, it stops without changing
anything, because blocking would disconnect them. Rerun it with one of the
two options.

## What the installer changes

| Where | Change |
|---|---|
| Remote Desktop | Turned on (`fDenyTSConnections = 0`), with Network Level Authentication required (`UserAuthentication = 1`). |
| Windows Firewall | Windows' built-in "Remote Desktop" rules are disabled, and rules `WRHS-Block-RDP-TCP/UDP` block the RDP port from the network. Windows Firewall does not filter loopback, so the agent still connects. With `-AllowNetworkRdp`: no WRHS rules, and Windows' "Remote Desktop" rules are turned on, as Settings does. |
| `%ProgramFiles%\WRHS` | The agent (`wrhs-agent.mjs`), the launcher template, and the service wrapper and its XML. |
| `%ProgramData%\WRHS` | `agent.json` (users, targets, policy), `agent.key.json` (identity key) and `logs\`. Only Administrators and SYSTEM have access; the service can read, and write its logs. |
| Services | **WRHS Agent** (`WRHSAgent`): automatic start, restart on failure, runs as `NT AUTHORITY\LocalService`. |

The previous Remote Desktop and firewall settings are recorded in
`%ProgramData%\WRHS\install-state.json`. `uninstall.ps1` puts them back.

## Day-to-day

Everything goes through the agent CLI with the installed configuration:

```powershell
# Shortcut used below:
function wrhs { & node "$env:ProgramFiles\WRHS\wrhs-agent.mjs" @args --config "$env:ProgramData\WRHS\agent.json" }

wrhs add-user bob                    # another WRHS user (prompts for a password)
wrhs launcher --out bob.html         # a launcher to hand out
wrhs enroll-device bob <device-key>  # restrict bob to one browser
wrhs show                            # identity, fingerprint, relay registration
Restart-Service WRHSAgent            # after editing agent.json
```

Logs are in `%ProgramData%\WRHS\logs` (`wrhs-agent-service.out.log` has the
agent's JSON audit log: sign-ins, desktops opened, failures).

### Which Windows accounts can sign in

The same accounts that can use Remote Desktop: administrators, plus members
of **Remote Desktop Users**. For a Microsoft account, sign in with its email
address and password (not the Windows Hello PIN), and leave the domain
empty. The account needs a password, and Windows must allow password
sign-in. Turn off *Settings → Accounts → Sign-in options → "For improved
security, only allow Windows Hello sign-in for Microsoft accounts on this
device"*. If you have only used a PIN on the PC so far, sign in there once
with the password.

### Other computers on the network

The agent can also open other PCs on its network:

```powershell
wrhs add-target --id office --name "Office PC" --host office-pc.corp.example --rdp-user alice
```

Remote Desktop must be enabled on that PC. The agent connects to it over
the LAN, so pin its certificate. Otherwise a machine between the agent and
that PC could pose as it and collect a crackable NTLM response:

1. The agent logs the certificate fingerprint of every connection
   (`rdp-connected ... certSha256`).
2. Put it in the target as `"certSha256": "..."`, or add it with
   `--cert-sha256`.

### Clipboard and drive policy

The built-in engine copies text both ways through RDP's clipboard channel.
To restrict it, use Windows' own Remote Desktop policies on the PC
(Group Policy: *Computer Configuration → Administrative Templates →
Windows Components → Remote Desktop Services → Remote Desktop Session Host →
Device and Resource Redirection*). Windows enforces those, whatever the
client does.

## Uninstall

```powershell
powershell -ExecutionPolicy Bypass -File .\uninstall.ps1             # keeps configuration and key
powershell -ExecutionPolicy Bypass -File .\uninstall.ps1 -RemoveData # deletes them too
```

## Troubleshooting

| Symptom | Check |
|---|---|
| "Your agent is not connected to the relay" | The last `relay-…` line in `wrhs-agent-service.out.log`: `relay-rejected` comes with a hint (401: the relay registration is missing or different; `"server": "cloudflare"`: Cloudflare's security settings). The agent keeps retrying, so it connects within 30 s of being added to the relay. |
| "Remote Desktop is not accepting connections on This PC" | `Get-Service TermService`; Remote Desktop on in Settings → System → Remote Desktop. |
| "This PC did not accept the user name or password" | Use the Windows account's password (not the PIN). For a Microsoft account, use its email address. |
| "This PC does not let this account connect remotely" | Add the account to Remote Desktop Users (`-RemoteDesktopUser`). |
| Service stops right away | `%ProgramData%\WRHS\logs\*.err.log`; Node.js must be installed for all users. |

## How it is tested

Every change runs the `windows (real Remote Desktop)` CI job on a Windows
Server runner:

1. It installs the service with `install.ps1` and starts a relay.
2. Chromium opens the launcher, signs in, opens **This PC** and signs in to
   the runner's own Remote Desktop with a fresh Windows account.
3. It checks that Windows reports an active Remote Desktop session for that
   account and that the desktop is drawn.
4. It closes the desktop (the session disconnects) and uninstalls.

The driver is [`test/windows/rdp-integration.ts`](../test/windows/rdp-integration.ts).
