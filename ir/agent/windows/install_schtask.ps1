Param(
  [Parameter(Mandatory=$false)][string]$InstallDir = "C:\ProgramData\IRAgent",
  [Parameter(Mandatory=$false)][string]$TaskName = "IRAgent",
  [Parameter(Mandatory=$false)][int]$EveryMinutes = 1,
  [Parameter(Mandatory=$false)][switch]$AtStartup = $true,
  [Parameter(Mandatory=$false)][switch]$AtLogon = $true
)

$ErrorActionPreference = "Stop"

$runPs1 = Join-Path $InstallDir "run_ir_agent.ps1"
if (!(Test-Path $runPs1)) {
  # assume scripts live next to this installer; copy them into InstallDir
  $src = Split-Path -Parent $MyInvocation.MyCommand.Path
  New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
  Copy-Item (Join-Path $src "run_ir_agent.ps1") $runPs1 -Force
}

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$runPs1`" -InstallDir `"$InstallDir`" -RunOnce"

$triggers = @()
if ($AtStartup) { $triggers += New-ScheduledTaskTrigger -AtStartup }
if ($AtLogon) { $triggers += New-ScheduledTaskTrigger -AtLogOn }

# periodic trigger (repeat forever)
$t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
$t.RepetitionInterval = New-TimeSpan -Minutes $EveryMinutes
$t.RepetitionDuration = [TimeSpan]::MaxValue
$triggers += $t

# Run as SYSTEM (recommended), highest privileges
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

# Conservative settings: don't run in parallel, start when available
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -StartWhenAvailable

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Force | Out-Null

Write-Host "Installed Scheduled Task: $TaskName"
Write-Host "Runs: $runPs1 (run-once mode) every $EveryMinutes minute(s) + startup/logon"

