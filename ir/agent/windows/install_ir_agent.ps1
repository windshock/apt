Param(
  [Parameter(Mandatory=$false)][string]$InstallDir = "C:\ProgramData\IRAgent",
  # Orchestrator API URL (mTLS port).
  # NOTE: In Kubernetes NodePort PoC, this is typically https://dfir.skplanet.com:30443
  [Parameter(Mandatory=$false)][string]$OrchUrl = "https://dfir.skplanet.com:443",
  # Enrollment/bootstrap URL (no client cert).
  # NOTE: In Kubernetes NodePort PoC, this is typically https://dfir.skplanet.com:30444
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

function Use-Tls12 {
  # Windows PowerShell 5.1 can default to older TLS. Force TLS1.2 for HTTPS downloads.
  try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  } catch {}
}

function Test-GetOk([string]$Url) {
  try {
    $r = Invoke-WebRequest -UseBasicParsing -Uri $Url -Method GET -TimeoutSec 5
    return ($r.StatusCode -ge 200 -and $r.StatusCode -lt 300)
  } catch {
    return $false
  }
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $InstallDir "mtls") | Out-Null

Use-Tls12

$bootstrap = $BootstrapUrl
if (-not $bootstrap -or $bootstrap.Trim().Length -eq 0) { $bootstrap = $EnrollUrl }
$bootstrap = $bootstrap.TrimEnd("/")

# Auto-detect Kubernetes NodePort environment:
# If the default ports (443/8443) don't respond for /bootstrap/*, fall back to 30443/30444.
try {
  $bUri = [Uri]$bootstrap
  $bootstrapOk = Test-GetOk "$bootstrap/bootstrap/windows/README.txt"
  if (-not $bootstrapOk) {
    if ($bUri.Port -eq 8443 -or $bUri.Port -eq 443) {
      $altBootstrap = "{0}://{1}:30444" -f $bUri.Scheme, $bUri.Host
      if (Test-GetOk "$altBootstrap/bootstrap/windows/README.txt") {
        $bootstrap = $altBootstrap
        $EnrollUrl = $altBootstrap
        try {
          $oUri = [Uri]$OrchUrl
          if ($oUri.Port -eq 443) {
            $OrchUrl = "{0}://{1}:30443" -f $oUri.Scheme, $oUri.Host
          }
        } catch {}
        Write-Host "Detected NodePort bootstrap; using:"
        Write-Host "  OrchUrl  = $OrchUrl"
        Write-Host "  EnrollUrl= $EnrollUrl"
        Write-Host "  Bootstrap= $bootstrap"
      }
    }
  }
} catch {}

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
Write-Host "2) Install deps (no repo clone needed):"
Write-Host "   python -m pip install --upgrade pip"
Write-Host "   python -m pip install requests cryptography"
Write-Host "3) Run agent:"
Write-Host "   powershell -ExecutionPolicy Bypass -File `"$InstallDir\run_ir_agent.ps1`" -InstallDir `"$InstallDir`" -PollSeconds $PollSeconds -StartupWaitSeconds $StartupWaitSeconds"
Write-Host "4) (Optional) Install Scheduled Task:"
Write-Host "   powershell -ExecutionPolicy Bypass -File `"$InstallDir\install_schtask.ps1`" -InstallDir `"$InstallDir`" -TaskName `"IRAgent`" -EveryMinutes 1"

