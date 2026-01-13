Param(
  [Parameter(Mandatory=$false)][string]$InstallDir = "C:\ProgramData\IRAgent",
  [Parameter(Mandatory=$false)][int]$PollSeconds = 30,
  [Parameter(Mandatory=$false)][int]$StartupWaitSeconds = 30,
  [Parameter(Mandatory=$false)][switch]$AssumeIsolated = $false
)

$ErrorActionPreference = "Stop"

function Load-EnvFile($Path) {
  if (!(Test-Path $Path)) { throw "Missing env file: $Path" }
  Get-Content $Path | ForEach-Object {
    $line = $_.Trim()
    if ($line.Length -eq 0) { return }
    if ($line.StartsWith("#")) { return }
    $idx = $line.IndexOf("=")
    if ($idx -lt 1) { return }
    $k = $line.Substring(0, $idx)
    $v = $line.Substring($idx + 1)
    [System.Environment]::SetEnvironmentVariable($k, $v, "Process")
  }
}

Load-EnvFile (Join-Path $InstallDir "agent.env")

$args = @(
  "-m", "ir.agent.run",
  "--agent-id", $env:IR_AGENT_ID,
  "--hostname", $env:COMPUTERNAME,
  "--orch-url", $env:IR_ORCH_URL,
  "--shared-key", $env:IR_SHARED_KEY,
  "--internet-probe", $env:IR_INTERNET_PROBE,
  "--poll-seconds", "$PollSeconds",
  "--startup-wait-seconds", "$StartupWaitSeconds",
  "--enroll-mtls"
)

if ($AssumeIsolated) { $args += "--assume-isolated" }
if ($env:IR_FETCH_LEECHAGENT_TLS -eq "1") { $args += "--fetch-leechagent-tls" }
if ($env:IR_LEECHAGENT_PATH -and $env:IR_LEECHAGENT_PATH.Trim().Length -gt 0) {
  $args += @("--leechagent-path", $env:IR_LEECHAGENT_PATH)
}
if ($env:IR_LEECHAGENT_ARGS -and $env:IR_LEECHAGENT_ARGS.Trim().Length -gt 0) {
  $args += @("--leechagent-args", $env:IR_LEECHAGENT_ARGS)
}
if ($env:IR_LEECHAGENT_CWD -and $env:IR_LEECHAGENT_CWD.Trim().Length -gt 0) {
  $args += @("--leechagent-cwd", $env:IR_LEECHAGENT_CWD)
}

Write-Host "Running: python $($args -join ' ')"
python @args

