<#
.SYNOPSIS
Installs the WRHS agent on this PC as a Windows service that serves this PC's
desktop to the WRHS browser client.

.DESCRIPTION
What it does:
  * Checks that this edition of Windows can host Remote Desktop sessions
    (Pro, Enterprise, Education or Server; Home cannot).
  * Turns on Remote Desktop with Network Level Authentication.
  * Blocks Remote Desktop from the network (unless -AllowNetworkRdp), so the
    only way in is through WRHS: the agent connects to it over loopback.
  * Copies the agent to %ProgramFiles%\WRHS. Its configuration and identity
    key live in %ProgramData%\WRHS, readable only by Administrators, SYSTEM
    and the service.
  * Creates the "This PC" desktop and, with -User, a WRHS user.
  * Installs and starts the "WRHS Agent" service: starts with Windows,
    restarts after failures, runs as NT AUTHORITY\LocalService.
  * Writes a personalized launcher file for your devices.

Running it again upgrades the agent and keeps the configuration and key.
Requires Node.js 22.18 or later, installed for all users.

.PARAMETER RelayUrl
Relay address, for example https://relay.example.com. Required the first time.

.PARAMETER PublicRelayUrl
Relay address as browsers reach it, if different from -RelayUrl.

.PARAMETER Name
Agent name shown to users. Default: this computer's name.

.PARAMETER User
Create this WRHS user. Asks for the password (or reads $env:WRHS_PASSWORD) and
prints the authenticator app setup.

.PARAMETER RemoteDesktopUser
Windows account to add to "Remote Desktop Users". Administrators can already
connect; other accounts need this.

.PARAMETER AllowNetworkRdp
Leave Remote Desktop reachable from the local network as well.

.PARAMETER LauncherOut
Where to write the launcher. Default: WRHS launcher.html on your desktop.

.PARAMETER WinSWPath
Use this copy of WinSW.NET461.exe 2.12.0 (the service wrapper) instead of
downloading it. Its SHA-256 is checked either way.

.PARAMETER NodePath
node.exe to run the agent with. Default: the one on PATH.

.EXAMPLE
.\install.ps1 -RelayUrl https://relay.example.com -User alice
#>
[CmdletBinding()]
param(
  [string]$RelayUrl,
  [string]$PublicRelayUrl,
  [string]$Name = $env:COMPUTERNAME,
  [string]$User,
  [string]$RemoteDesktopUser,
  [switch]$AllowNetworkRdp,
  [string]$LauncherOut,
  [string]$WinSWPath,
  [string]$NodePath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$ServiceId = 'WRHSAgent'
$AppDir = Join-Path $env:ProgramFiles 'WRHS'
$DataDir = Join-Path $env:ProgramData 'WRHS'
$LogDir = Join-Path $DataDir 'logs'
$ConfigPath = Join-Path $DataDir 'agent.json'
$StatePath = Join-Path $DataDir 'install-state.json'
# The .NET Framework build: runs on the framework built into Windows, as a
# plain executable (the self-contained builds unpack themselves at start).
$WinSWUrl = 'https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW.NET461.exe'
$WinSWSha256 = 'B5066B7BBDFBA1293E5D15CDA3CAAEA88FBEAB35BD5B38C41C913D492AADFC4F'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path

# Well-known SIDs, so this works in every display language.
$SidSystem = 'S-1-5-18'
$SidLocalService = 'S-1-5-19'
$SidAdministrators = 'S-1-5-32-544'
$SidRemoteDesktopUsers = 'S-1-5-32-555'
# Resource name of Windows' built-in "Remote Desktop" firewall rule group.
$RdpFirewallGroup = '@FirewallAPI.dll,-28752'

function Step([string]$Message) { Write-Host "==> $Message" -ForegroundColor Cyan }

function Invoke-Agent {
  # Runs the agent CLI against the installed configuration.
  & $NodePath (Join-Path $AppDir 'wrhs-agent.mjs') @args --config $ConfigPath
  if ($LASTEXITCODE -ne 0) { throw "wrhs-agent $($args -join ' ') failed (exit code $LASTEXITCODE)" }
}

# ---------------------------------------------------------------- checks

Step 'Checking this computer'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run this script from an elevated PowerShell ("Run as administrator").'
}

$edition = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID
if ($edition -match '^Core') {
  throw "This edition of Windows ($edition, i.e. Windows Home) cannot host Remote Desktop sessions. WRHS needs Windows Pro, Enterprise, Education or Server."
}
Write-Host "    Windows edition: $edition"

if (-not $NodePath) {
  $cmd = Get-Command node.exe -ErrorAction SilentlyContinue
  if ($cmd) { $NodePath = $cmd.Source }
}
if (-not $NodePath -or -not (Test-Path $NodePath)) {
  throw 'Node.js 22.18 or later is required. Install it for all users (https://nodejs.org, or: winget install OpenJS.NodeJS.LTS) and run this again.'
}
$NodePath = (Resolve-Path $NodePath).Path
$nodeVersion = [version]((& $NodePath --version).Trim().TrimStart('v'))
if ($nodeVersion -lt [version]'22.18.0') { throw "Node.js $nodeVersion is too old; 22.18 or later is required." }
if ($NodePath.StartsWith($env:USERPROFILE, [StringComparison]::OrdinalIgnoreCase)) {
  throw "Node.js at $NodePath is installed for one user only; the service cannot run it. Install Node.js for all users."
}
Write-Host "    Node.js $nodeVersion at $NodePath"

$bundle = Join-Path $Here 'wrhs-agent.mjs'
$template = Join-Path $Here 'launcher.template.html'
foreach ($f in @($bundle, $template)) {
  if (-not (Test-Path $f)) { throw "$f is missing. Run this script from the WRHS Windows package (npm run package:windows)." }
}
if (-not (Test-Path $ConfigPath) -and -not $RelayUrl) { throw '-RelayUrl is required for the first installation.' }

# ---------------------------------------------------------------- folders

Step "Installing files to $AppDir"
foreach ($d in @($AppDir, $DataDir, $LogDir)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
# Configuration and key: Administrators and SYSTEM full control, the service
# (LocalService) read-only, nobody else. Logs: the service may write.
& icacls.exe $DataDir /inheritance:r /grant:r "*${SidSystem}:(OI)(CI)F" "*${SidAdministrators}:(OI)(CI)F" "*${SidLocalService}:(OI)(CI)RX" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not set permissions on $DataDir" }
& icacls.exe $LogDir /grant:r "*${SidLocalService}:(OI)(CI)M" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not set permissions on $LogDir" }

$existing = Get-Service -Name $ServiceId -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -ne 'Stopped') {
  Step 'Stopping the running agent for the upgrade'
  Stop-Service -Name $ServiceId -Force
  (Get-Service -Name $ServiceId).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}
Copy-Item -Force $bundle, $template -Destination $AppDir

# ---------------------------------------------------------------- Remote Desktop

Step 'Turning on Remote Desktop with Network Level Authentication'
$tsKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$rdpTcpKey = "$tsKey\WinStations\RDP-Tcp"
if (-not (Test-Path $StatePath)) {
  # Remember how things were, so uninstall.ps1 can put them back.
  $state = [ordered]@{
    fDenyTSConnections = (Get-ItemProperty $tsKey).fDenyTSConnections
    UserAuthentication = (Get-ItemProperty $rdpTcpKey).UserAuthentication
    enabledFirewallRules = @(Get-NetFirewallRule -Group $RdpFirewallGroup -ErrorAction SilentlyContinue |
      Where-Object { $_.Enabled -eq 'True' } | ForEach-Object { $_.Name })
  }
  $state | ConvertTo-Json | Set-Content -Encoding UTF8 -Path $StatePath
}
Set-ItemProperty -Path $tsKey -Name fDenyTSConnections -Value 0 -Type DWord
Set-ItemProperty -Path $rdpTcpKey -Name UserAuthentication -Value 1 -Type DWord
$rdpPort = [int](Get-ItemProperty $rdpTcpKey).PortNumber
Start-Service -Name TermService

if ($AllowNetworkRdp) {
  Write-Host '    Remote Desktop stays reachable from the local network (-AllowNetworkRdp).'
} else {
  Step "Blocking Remote Desktop (port $rdpPort) from the network; WRHS reaches it over loopback"
  Get-NetFirewallRule -Group $RdpFirewallGroup -ErrorAction SilentlyContinue | Disable-NetFirewallRule
  Remove-NetFirewallRule -Name 'WRHS-Block-RDP-TCP', 'WRHS-Block-RDP-UDP' -ErrorAction SilentlyContinue
  # Windows Firewall does not filter loopback traffic, so these leave the agent's connection alone.
  New-NetFirewallRule -Name 'WRHS-Block-RDP-TCP' -DisplayName 'WRHS: block Remote Desktop from the network (TCP)' `
    -Direction Inbound -Protocol TCP -LocalPort $rdpPort -Action Block -Profile Any | Out-Null
  New-NetFirewallRule -Name 'WRHS-Block-RDP-UDP' -DisplayName 'WRHS: block Remote Desktop from the network (UDP)' `
    -Direction Inbound -Protocol UDP -LocalPort $rdpPort -Action Block -Profile Any | Out-Null
}

$listening = $false
for ($i = 0; $i -lt 30 -and -not $listening; $i++) {
  $tcp = New-Object Net.Sockets.TcpClient
  try { $tcp.Connect('127.0.0.1', $rdpPort); $listening = $true } catch { Start-Sleep -Seconds 1 } finally { $tcp.Dispose() }
}
if (-not $listening) { throw "Remote Desktop is not accepting connections on 127.0.0.1:$rdpPort." }

if ($RemoteDesktopUser) {
  Step "Allowing $RemoteDesktopUser to use Remote Desktop"
  $group = Get-LocalGroup -SID $SidRemoteDesktopUsers
  if (-not (Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*\$RemoteDesktopUser" -or $_.Name -eq $RemoteDesktopUser })) {
    Add-LocalGroupMember -Group $group -Member $RemoteDesktopUser
  }
}

# ---------------------------------------------------------------- configuration

if (Test-Path $ConfigPath) {
  Step "Keeping the existing configuration in $ConfigPath"
  $config = Get-Content -Raw -Path $ConfigPath | ConvertFrom-Json
  $targetIds = @($config.targets | ForEach-Object { $_.id })
  if ($targetIds -notcontains 'this-pc') { Invoke-Agent add-target --this-pc }
} else {
  Step "Creating the configuration and identity key in $DataDir"
  Invoke-Agent init --relay $RelayUrl --name $Name --this-pc
}

if ($User) {
  Step "Adding WRHS user $User"
  $setPassword = -not $env:WRHS_PASSWORD
  if ($setPassword) {
    $secure = Read-Host "Password for WRHS user $User" -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { $env:WRHS_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
  }
  try { Invoke-Agent add-user $User } finally { if ($setPassword) { Remove-Item Env:WRHS_PASSWORD } }
}

# ---------------------------------------------------------------- service

Step 'Installing the WRHS Agent service'
$serviceExe = Join-Path $AppDir 'wrhs-agent-service.exe'
$haveWrapper = (Test-Path $serviceExe) -and ((Get-FileHash -Algorithm SHA256 $serviceExe).Hash -eq $WinSWSha256)
if (-not $haveWrapper) {
  $download = Join-Path $env:TEMP "WinSW-$([guid]::NewGuid()).exe"
  if ($WinSWPath) {
    Copy-Item -Force $WinSWPath $download
  } else {
    Write-Host "    Downloading the service wrapper (WinSW 2.12.0) from $WinSWUrl"
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -UseBasicParsing -Uri $WinSWUrl -OutFile $download
  }
  $hash = (Get-FileHash -Algorithm SHA256 $download).Hash
  if ($hash -ne $WinSWSha256) {
    Remove-Item -Force $download
    throw "The service wrapper does not have the expected SHA-256 ($hash). Not installing it."
  }
  if ($existing) { & $serviceExe uninstall | Out-Null; $existing = $null }
  Move-Item -Force $download $serviceExe
}

$x = { param([string]$s) [Security.SecurityElement]::Escape($s) }
$agentJs = Join-Path $AppDir 'wrhs-agent.mjs'
@"
<service>
  <id>$ServiceId</id>
  <name>WRHS Agent</name>
  <description>Serves this PC's desktop to the WRHS browser client through an end-to-end encrypted relay.</description>
  <executable>$(& $x $NodePath)</executable>
  <arguments>"$(& $x $agentJs)" run --config "$(& $x $ConfigPath)"</arguments>
  <workingdirectory>$(& $x $DataDir)</workingdirectory>
  <startmode>Automatic</startmode>
  <onfailure action="restart" delay="10 sec"/>
  <onfailure action="restart" delay="30 sec"/>
  <onfailure action="restart" delay="60 sec"/>
  <resetfailure>1 hour</resetfailure>
  <stoptimeout>10 sec</stoptimeout>
  <logpath>$(& $x $LogDir)</logpath>
  <log mode="roll-by-size">
    <sizeThreshold>10240</sizeThreshold>
    <keepFiles>8</keepFiles>
  </log>
</service>
"@ | Set-Content -Encoding UTF8 -Path (Join-Path $AppDir 'wrhs-agent-service.xml')

if (-not (Get-Service -Name $ServiceId -ErrorAction SilentlyContinue)) {
  & $serviceExe install
  if ($LASTEXITCODE -ne 0) { throw 'Installing the service failed.' }
} else {
  & $serviceExe refresh
  if ($LASTEXITCODE -ne 0) { throw 'Updating the service failed.' }
}
# Least privilege: the agent only reads its configuration and talks to the network.
$change = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceId'" |
  Invoke-CimMethod -MethodName Change -Arguments @{ StartName = 'NT AUTHORITY\LocalService'; StartPassword = '' }
if ($change.ReturnValue -ne 0) { throw "Could not set the service account (error $($change.ReturnValue))." }
try {
  Start-Service -Name $ServiceId
  (Get-Service -Name $ServiceId).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
} catch {
  Write-Host 'The service did not start. Details:' -ForegroundColor Yellow
  Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceId'" |
    Format-List Name, State, ExitCode, ServiceSpecificExitCode, StartName, PathName | Out-String | Write-Host
  Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; StartTime = (Get-Date).AddMinutes(-5) } -MaxEvents 10 -ErrorAction SilentlyContinue |
    Format-List TimeCreated, Id, Message | Out-String | Write-Host
  Get-ChildItem -Path $LogDir -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "--- $($_.Name)"; Get-Content -Tail 30 $_.FullName }
  throw
}

# ---------------------------------------------------------------- launcher and summary

if (-not $LauncherOut) { $LauncherOut = Join-Path ([Environment]::GetFolderPath('Desktop')) 'WRHS launcher.html' }
Step "Writing the launcher to $LauncherOut"
if ($PublicRelayUrl) { Invoke-Agent launcher --out $LauncherOut --public-url $PublicRelayUrl } else { Invoke-Agent launcher --out $LauncherOut }

Step 'Done'
Invoke-Agent show
Write-Host ''
Write-Host 'Next:'
Write-Host '  1. Add the relay registration line above to the relay''s agents file (if not done yet).'
Write-Host '  2. Copy the launcher to your devices over a channel you trust, and open it from disk.'
Write-Host '  3. Sign in with your WRHS user and authenticator code, choose "This PC", and sign in'
Write-Host '     with your Windows account. This PC''s screen locks while you are connected.'
Write-Host "Service logs: $LogDir"
