Param(
  [Parameter(Mandatory=$false)][string]$InstallDir = "C:\ProgramData\IRAgent",
  # Orchestrator API URL (mTLS port). In production behind gateway: https://dfir.skplanet.com:443
  [Parameter(Mandatory=$false)][string]$OrchUrl = "https://dfir.skplanet.com:443",
  # Enrollment/bootstrap URL (no client cert). In production behind gateway: https://dfir.skplanet.com:8443
  [Parameter(Mandatory=$false)][string]$EnrollUrl = "https://dfir.skplanet.com:8443",
  # Where to download bootstrap assets (CA + scripts). Default: EnrollUrl.
  [Parameter(Mandatory=$false)][string]$BootstrapUrl = "",
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

$bootstrap = $BootstrapUrl
if (-not $bootstrap -or $bootstrap.Trim().Length -eq 0) { $bootstrap = $EnrollUrl }
$bootstrap = $bootstrap.TrimEnd("/")

# Download CA (for gateway TLS) if not provided.
# Note: if your dfir.skplanet.com TLS cert is publicly trusted, you can leave $TlsCaPath empty.
if (-not $TlsCaPath -or $TlsCaPath.Trim().Length -eq 0) {
  $caOut = Join-Path $InstallDir "mtls\gateway-ca.crt.pem"
  try {
    Invoke-WebRequest -UseBasicParsing -Uri "$bootstrap/bootstrap/ca.crt.pem" -OutFile $caOut | Out-Null
    $TlsCaPath = $caOut
  } catch {
    Write-Host "WARN: failed to download CA from $bootstrap/bootstrap/ca.crt.pem"
    Write-Host "      error: $($_.Exception.Message)"
    Write-Host "      You may need to provide -TlsCaPath (or install your enterprise/public TLS cert)."
  }
}

# Download helper scripts into InstallDir for easy Scheduled Task setup.
try {
  Invoke-WebRequest -UseBasicParsing -Uri "$bootstrap/bootstrap/windows/run_ir_agent.ps1" -OutFile (Join-Path $InstallDir "run_ir_agent.ps1") | Out-Null
  Invoke-WebRequest -UseBasicParsing -Uri "$bootstrap/bootstrap/windows/install_schtask.ps1" -OutFile (Join-Path $InstallDir "install_schtask.ps1") | Out-Null
  Invoke-WebRequest -UseBasicParsing -Uri "$bootstrap/bootstrap/windows/uninstall_schtask.ps1" -OutFile (Join-Path $InstallDir "uninstall_schtask.ps1") | Out-Null
} catch {
  Write-Host "WARN: failed to download helper scripts from $bootstrap/bootstrap/windows/*"
  Write-Host "      error: $($_.Exception.Message)"
}

# Write runtime env for the agent
$envFile = Join-Path $InstallDir "agent.env"
$enrollMtlsVal = "0"
if ($EnrollMtls) { $enrollMtlsVal = "1" }
$fetchLeechVal = "0"
if ($FetchLeechagentTls) { $fetchLeechVal = "1" }
@"
IR_AGENT_ID=$AgentId
IR_AGENT_IP=$AgentIp
IR_ORCH_URL=$OrchUrl
IR_ENROLL_URL=$EnrollUrl
IR_SHARED_KEY=$SharedKey
IR_TLS_CA=$TlsCaPath
IR_ENROLL_MTLS=$enrollMtlsVal
IR_FETCH_LEECHAGENT_TLS=$fetchLeechVal
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
Write-Host "Bootstrap:  $bootstrap"
Write-Host "CA path:    $TlsCaPath"
Write-Host ""
Write-Host "Next steps (PoC):"
Write-Host "1) Install Python 3.11+ and pip on this Windows PC."
Write-Host "2) Install deps: pip install -r <repo>/requirements.txt  (needs requests+cryptography at minimum)"
Write-Host "3) Run agent:"
Write-Host "   powershell -ExecutionPolicy Bypass -File `"$InstallDir\run_ir_agent.ps1`" -InstallDir `"$InstallDir`" -PollSeconds $PollSeconds -StartupWaitSeconds $StartupWaitSeconds"
Write-Host "4) (Optional) Install Scheduled Task:"
Write-Host "   powershell -ExecutionPolicy Bypass -File `"$InstallDir\install_schtask.ps1`" -InstallDir `"$InstallDir`" -TaskName `"IRAgent`" -EveryMinutes 1"

