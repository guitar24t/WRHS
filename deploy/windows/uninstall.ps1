<#
.SYNOPSIS
Removes the WRHS agent service and puts Remote Desktop back the way it was.

.DESCRIPTION
Stops and removes the "WRHS Agent" service, deletes %ProgramFiles%\WRHS,
removes the WRHS firewall rules and restores the Remote Desktop and firewall
settings recorded at installation.

The configuration and identity key in %ProgramData%\WRHS are kept, so a
later installation keeps the same identity and existing launchers keep
working. Use -RemoveData to delete them too.

.PARAMETER RemoveData
Also delete %ProgramData%\WRHS (configuration, users, identity key, logs).
#>
[CmdletBinding()]
param([switch]$RemoveData)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$ServiceId = 'WRHSAgent'
$AppDir = Join-Path $env:ProgramFiles 'WRHS'
$DataDir = Join-Path $env:ProgramData 'WRHS'
$StatePath = Join-Path $DataDir 'install-state.json'
# Resource name of Windows' built-in "Remote Desktop" firewall rule group.
$RdpFirewallGroup = '@FirewallAPI.dll,-28752'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run this script from an elevated PowerShell ("Run as administrator").'
}

$service = Get-Service -Name $ServiceId -ErrorAction SilentlyContinue
if ($service) {
  Write-Host '==> Removing the WRHS Agent service'
  if ($service.Status -ne 'Stopped') {
    Stop-Service -Name $ServiceId -Force
    (Get-Service -Name $ServiceId).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
  }
  $serviceExe = Join-Path $AppDir 'wrhs-agent-service.exe'
  if (Test-Path $serviceExe) { & $serviceExe uninstall | Out-Null } else { & sc.exe delete $ServiceId | Out-Null }
  for ($i = 0; $i -lt 20 -and (Get-Service -Name $ServiceId -ErrorAction SilentlyContinue); $i++) { Start-Sleep -Milliseconds 500 }
}

Write-Host '==> Removing firewall rules'
Remove-NetFirewallRule -Name 'WRHS-Block-RDP-TCP', 'WRHS-Block-RDP-UDP' -ErrorAction SilentlyContinue

if (Test-Path $StatePath) {
  Write-Host '==> Restoring the previous Remote Desktop settings'
  $state = Get-Content -Raw -Path $StatePath | ConvertFrom-Json
  $tsKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
  if ($null -ne $state.fDenyTSConnections) { Set-ItemProperty -Path $tsKey -Name fDenyTSConnections -Value ([int]$state.fDenyTSConnections) -Type DWord }
  if ($null -ne $state.UserAuthentication) {
    Set-ItemProperty -Path "$tsKey\WinStations\RDP-Tcp" -Name UserAuthentication -Value ([int]$state.UserAuthentication) -Type DWord
  }
  # Exactly the rules that were on before: the installer may have turned on others.
  $wasEnabled = @($state.enabledFirewallRules)
  foreach ($rule in @(Get-NetFirewallRule -Group $RdpFirewallGroup -ErrorAction SilentlyContinue)) {
    if ($wasEnabled -contains $rule.Name) { $rule | Enable-NetFirewallRule } else { $rule | Disable-NetFirewallRule }
  }
  Remove-Item -Force $StatePath
}

if (Test-Path $AppDir) {
  Write-Host "==> Deleting $AppDir"
  Remove-Item -Recurse -Force $AppDir
}

if ($RemoveData) {
  Write-Host "==> Deleting $DataDir (configuration, users and identity key)"
  Remove-Item -Recurse -Force $DataDir -ErrorAction SilentlyContinue
} else {
  Write-Host "Kept $DataDir (configuration and identity key). Delete it, or run with -RemoveData, to remove them."
}
Write-Host 'WRHS agent removed.'
