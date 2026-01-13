Param(
  [Parameter(Mandatory=$false)][string]$TaskName = "IRAgent"
)

$ErrorActionPreference = "Stop"

try {
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
  Write-Host "Removed Scheduled Task: $TaskName"
} catch {
  Write-Host "Task not found or already removed: $TaskName"
}

