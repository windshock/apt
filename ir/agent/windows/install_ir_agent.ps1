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

$AgentIp = $AgentIp.Trim()
if (-not $AgentIp -or $AgentIp.Length -eq 0) {
  # Best-effort auto-detect a usable IPv4 (avoid loopback/APIPA).
  try {
    $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
      Where-Object { $_.IPAddress -and $_.IPAddress -ne "127.0.0.1" -and -not $_.IPAddress.StartsWith("169.254.") } |
      Sort-Object -Property InterfaceMetric, PrefixLength
    if ($ips -and $ips.Count -gt 0) {
      $AgentIp = $ips[0].IPAddress
    }
  } catch {}
}

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

# NOTE about IR_TLS_CA:
# - This should be used ONLY to verify the gateway/orchestrator *server TLS* certificate.
# - If you are using a publicly trusted cert (e.g., GlobalSign wildcard), leave it empty.
# - If you are using an internal/self-signed gateway cert, you must pre-install that CA on Windows
#   (or pass -TlsCaPath to a CA bundle that can validate the gateway cert).
#
# We intentionally do NOT auto-download any "internal IR CA" here, because it is not the same CA as the
# public wildcard cert and would break TLS verification (leading to "orchestrator unreachable").

# Download helper scripts into InstallDir for easy Scheduled Task setup.
try {
  Invoke-WebRequest -UseBasicParsing -Uri "$bootstrap/bootstrap/windows/run_ir_agent.ps1" -OutFile (Join-Path $InstallDir "run_ir_agent.ps1") | Out-Null
  Invoke-WebRequest -UseBasicParsing -Uri "$bootstrap/bootstrap/windows/install_schtask.ps1" -OutFile (Join-Path $InstallDir "install_schtask.ps1") | Out-Null
  Invoke-WebRequest -UseBasicParsing -Uri "$bootstrap/bootstrap/windows/uninstall_schtask.ps1" -OutFile (Join-Path $InstallDir "uninstall_schtask.ps1") | Out-Null
} catch {
  Write-Host "WARN: failed to download helper scripts from $bootstrap/bootstrap/windows/*"
  Write-Host "      error: $($_.Exception.Message)"
}

# Download minimal python package payload (ir_agent.zip) so python can import `ir.agent.run` without a repo clone.
try {
  $pyDir = Join-Path $InstallDir "py"
  New-Item -ItemType Directory -Force -Path $pyDir | Out-Null
  $zipOut = Join-Path $InstallDir "ir_agent.zip"
  Invoke-WebRequest -UseBasicParsing -Uri "$bootstrap/bootstrap/windows/ir_agent.zip" -OutFile $zipOut | Out-Null
  Expand-Archive -Path $zipOut -DestinationPath $pyDir -Force
} catch {
  Write-Host "WARN: failed to download/extract ir_agent.zip from $bootstrap/bootstrap/windows/ir_agent.zip"
  Write-Host "      error: $($_.Exception.Message)"
}

# Download LeechAgent bundle (optional) so the endpoint can expose gRPC 28474 when isolated.
# This is served from the DFIR server and is NOT stored in git.
try {
  $laDir = Join-Path $InstallDir "leechagent"
  New-Item -ItemType Directory -Force -Path $laDir | Out-Null
  $laZip = Join-Path $InstallDir "leechagent.zip"
  Invoke-WebRequest -UseBasicParsing -Uri "$bootstrap/bootstrap/windows/leechagent.zip" -OutFile $laZip | Out-Null
  Expand-Archive -Path $laZip -DestinationPath $laDir -Force
  $laExe = Join-Path $laDir "leechagent.exe"
  if ((-not $LeechAgentPath -or $LeechAgentPath.Trim().Length -eq 0) -and (Test-Path $laExe)) {
    $LeechAgentPath = $laExe
  }
  # Ensure agent starts LeechAgent from its own folder so DLLs are found.
  if (-not $env:IR_LEECHAGENT_CWD -or $env:IR_LEECHAGENT_CWD.Trim().Length -eq 0) {
    # store in variable later written to agent.env
    $LeechAgentCwd = $laDir
  }
} catch {
  Write-Host "WARN: leechagent.zip not downloaded (optional): $bootstrap/bootstrap/windows/leechagent.zip"
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
IR_AGENT_PY_DIR=$InstallDir\py
IR_ENROLL_MTLS=$enrollMtlsVal
IR_FETCH_LEECHAGENT_TLS=$fetchLeechVal
IR_MTLS_DIR=$InstallDir\mtls
IR_INTERNET_PROBE=$InternetProbe
IR_LEECHAGENT_PATH=$LeechAgentPath
IR_LEECHAGENT_ARGS=$LeechAgentArgs
IR_LEECHAGENT_CWD=$LeechAgentCwd
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
Write-Host "   python -m pip install requests cryptography pydantic"
Write-Host "3) Run agent:"
Write-Host "   powershell -ExecutionPolicy Bypass -File `"$InstallDir\run_ir_agent.ps1`" -InstallDir `"$InstallDir`" -PollSeconds $PollSeconds -StartupWaitSeconds $StartupWaitSeconds"
Write-Host "4) (Optional) Install Scheduled Task:"
Write-Host "   powershell -ExecutionPolicy Bypass -File `"$InstallDir\install_schtask.ps1`" -InstallDir `"$InstallDir`" -TaskName `"IRAgent`" -EveryMinutes 1"

