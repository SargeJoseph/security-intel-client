# Autonomous Forensic Artifact Collector - Task Scheduler Wrapper
# Runs the Python FAC script non-interactively

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$pythonScript = Join-Path $scriptPath "auto_fac_scan.py"
$logFile = Join-Path $scriptPath "Output\auto_fac_scan_log.txt"

# Ensure Output directory exists
$outputDir = Join-Path $scriptPath "Output"
if (-not (Test-Path $outputDir)) {
  New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

# Log start time
$startTime = Get-Date
"=" * 80 | Out-File -FilePath $logFile -Append
"AUTONOMOUS FAC SCAN - Started at $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))" | Out-File -FilePath $logFile -Append
"=" * 80 | Out-File -FilePath $logFile -Append

try {
  # Set UTF-8 encoding for Python output
  $env:PYTHONIOENCODING = "utf-8"

  # Run Python script and capture all output
  # No prompts in autonomous mode (interactive=False)
  $output = python "$pythonScript" 2>&1

  # Log output
  $output | Out-File -FilePath $logFile -Encoding UTF8 -Append

  # Log completion
  $endTime = Get-Date
  $duration = ($endTime - $startTime).TotalSeconds
  "`n" + "=" * 80 | Out-File -FilePath $logFile -Append
  "FAC scan completed - Exit code: $LASTEXITCODE" | Out-File -FilePath $logFile -Append
  "Duration: $([math]::Round($duration, 1)) seconds" | Out-File -FilePath $logFile -Append
  "Finished at $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))" | Out-File -FilePath $logFile -Append
  "=" * 80 | Out-File -FilePath $logFile -Append
  "`n" | Out-File -FilePath $logFile -Append

  exit $LASTEXITCODE

} catch {
  $errorMsg = $_.Exception.Message
  "`nFATAL ERROR: $errorMsg" | Out-File -FilePath $logFile -Append
  exit 1
}
