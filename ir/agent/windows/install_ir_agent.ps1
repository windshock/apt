Param(
  [Parameter(Mandatory=$false)][string]$InstallDir = "C:\ProgramData\IRAgent",
  [Parameter(Mandatory=$true)][string]$OrchUrl,   # e.g. https://dfir.skplanet.com:443  (or http://<dfir>:8080 for PoC)
  [Parameter(Mandatory=$true)][string]$EnrollUrl, # e.g. https://dfir.skplanet.com:8443
  [Parameter(Mandatory=$true)][string]$SharedKey,
  [Parameter(Mandatory=$false)][string]$AgentId = $env:COMPUTERNAME,
  [Parameter(Mandatory=$false)][string]$AgentIp = "",
  [Parameter(Mandatory=$false)][string]$TlsCaPath = "",
  [Parameter(Mandatory=$false)][string]$InternetProbe = "https://example.com",
  [Parameter(Mandatory=$false)][int]$PollSeconds = 30,
  [Parameter(Mandatory=$false)][int]$StartupWaitSeconds = 30,
  [Parameter(Mandatory=$false)][switch]$EnrollMtls = $true,
  [Parameter(Mandatory=$false)][switch]$FetchLeechagentTls = $true,
  [Parameter(Mandatory=$false)][string]$LeechAgentPath = "",
  [Parameter(Mandatory=$false)][string]$LeechAgentArgs = "",
  [Parameter(Mandatory=$false)][string]$DfIrServerIp = ""  # optional: restrict inbound 28474 to this IP
)

$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $InstallDir "mtls") | Out-Null

# Write runtime env for the agent
$envFile = Join-Path $InstallDir "agent.env"
@"
IR_AGENT_ID=$AgentId
IR_AGENT_IP=$AgentIp
IR_ORCH_URL=$OrchUrl
IR_ENROLL_URL=$EnrollUrl
IR_SHARED_KEY=$SharedKey
IR_TLS_CA=$TlsCaPath
IR_ENROLL_MTLS=1
IR_FETCH_LEECHAGENT_TLS=1
IR_MTLS_DIR=$InstallDir\mtls
IR_INTERNET_PROBE=$InternetProbe
IR_LEECHAGENT_PATH=$LeechAgentPath
IR_LEECHAGENT_ARGS=$LeechAgentArgs
"@ | Set-Content -Encoding ASCII -Path $envFile

# Firewall: allow inbound gRPC 28474 (from DFIR server if provided)
try {
  $ruleName = "IR-LeechAgent-28474"
  if ($DfIrServerIp -and $DfIrServerIp.Trim().Length -gt 0) {
    netsh advfirewall firewall add rule name="$ruleName" dir=in action=allow protocol=TCP localport=28474 remoteip=$DfIrServerIp | Out-Null
  } else {
    netsh advfirewall firewall add rule name="$ruleName" dir=in action=allow protocol=TCP localport=28474 | Out-Null
  }
} catch {}

Write-Host "InstallDir: $InstallDir"
Write-Host "Wrote env:  $envFile"
Write-Host ""
Write-Host "Next steps (PoC):"
Write-Host "1) Install Python 3.11+ and pip on this Windows PC."
Write-Host "2) Install deps: pip install -r <repo>/requirements.txt  (needs requests+cryptography at minimum)"
Write-Host "3) Run agent:"
Write-Host "   powershell -ExecutionPolicy Bypass -File `"$PSScriptRoot\run_ir_agent.ps1`" -InstallDir `"$InstallDir`" -PollSeconds $PollSeconds -StartupWaitSeconds $StartupWaitSeconds"

