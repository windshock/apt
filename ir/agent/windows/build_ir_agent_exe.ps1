Param(
  [Parameter(Mandatory=$false)][string]$RepoRoot = (Resolve-Path "$PSScriptRoot\..\..\..").Path,
  [Parameter(Mandatory=$false)][string]$PythonExe = "python",
  [Parameter(Mandatory=$false)][string]$OutDir = ""
)

$ErrorActionPreference = "Stop"

Set-Location $RepoRoot

$venv = Join-Path $RepoRoot ".venv-ir-agent"
if (!(Test-Path $venv)) {
  & $PythonExe -m venv $venv
}

$py = Join-Path $venv "Scripts\python.exe"
$pip = Join-Path $venv "Scripts\pip.exe"

& $pip install --upgrade pip wheel | Out-Null

# Minimal deps for ir.agent.run (do NOT install full repo requirements)
& $pip install "requests==2.32.3" "cryptography==44.0.1" "pyinstaller==6.10.0" | Out-Null

if ($OutDir -and $OutDir.Trim().Length -gt 0) {
  $dist = $OutDir
} else {
  $dist = Join-Path $RepoRoot "dist"
}

Write-Host "Building EXE into: $dist"

& $py -m PyInstaller `
  --clean `
  --onefile `
  --name "ir-agent" `
  --distpath "$dist" `
  "$RepoRoot\ir\agent\ir_agent_main.py"

Write-Host ""
Write-Host "OK: built $dist\ir-agent.exe"

