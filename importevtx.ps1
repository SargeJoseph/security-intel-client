# ===================================================================================
# importevtx.ps1 - Complete Event Import with Live Log Processing
#
# This script processes both live Security log and archived files:
# - Reads and processes live Security log events
# - Archives and clears the live log
# - Processes all archived .evtx files
# - Filters out port 5353 (mDNS) and system processes
# - Prevents duplicate processing via database tracking
# ===================================================================================

# --- CONFIGURATION PARAMETERS (MUST BE FIRST IN SCRIPT) ---
param(
  [string]$EventsDatabasePath,
  [string]$LogArchivesPath,
  [string]$DiagnosticLogPath,
  [int]$BatchSize = 10000,
  [switch]$Resume,
  [switch]$ValidateOnly,
  [switch]$SkipArchiving
)

# --- LOAD CONFIGURATION FROM .ENV FILE ---
function Load-DotEnv {
  param([string]$EnvFilePath)

  $config = @{}

  if (Test-Path $EnvFilePath) {
    Get-Content $EnvFilePath | ForEach-Object {
      $line = $_.Trim()
      # Skip empty lines and comments
      if ($line -and -not $line.StartsWith('#')) {
        $parts = $line -split '=', 2
        if ($parts.Count -eq 2) {
          $key = $parts[0].Trim()
          $value = $parts[1].Trim()
          # Expand environment variables in the value (e.g., %USERPROFILE%)
          $expandedValue = [System.Environment]::ExpandEnvironmentVariables($value)
          $config[$key] = $expandedValue
          Write-Verbose "Loaded config: $key = $expandedValue"
        }
      }
    }
    return $config
  } else {
    Write-Error ".env file not found at: $EnvFilePath"
    Write-Error "Please create a .env file based on .env.example"
    return $null
  }
}

# Get the directory where this script is located
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$EnvFile = Join-Path $ScriptDir ".env"

# Load .env file
$EnvConfig = Load-DotEnv -EnvFilePath $EnvFile
if ($null -eq $EnvConfig) {
  Write-Error "Failed to load configuration from .env file. Exiting."
  exit 1
}

Write-Host "Configuration loaded from .env file" -ForegroundColor Green

# Use values from .env if not provided as parameters
if (-not $EventsDatabasePath) {
  $EventsDatabasePath = $EnvConfig['DB']
}
if (-not $LogArchivesPath) {
  $LogArchivesPath = $EnvConfig['LOGARCHIVES']
}
if (-not $DiagnosticLogPath) {
  $DiagnosticLogPath = Join-Path $EnvConfig['OUTPUT'] "security_intel_evtx_imports.log"
}

# Validate required paths are set
if (-not $EventsDatabasePath) {
  Write-Error "DB path not set. Please configure DB in .env file"
  exit 1
}
if (-not $LogArchivesPath) {
  Write-Error "LOGARCHIVES path not set. Please configure LOGARCHIVES in .env file"
  exit 1
}
if (-not $EnvConfig['OUTPUT']) {
  Write-Error "OUTPUT path not set. Please configure OUTPUT in .env file"
  exit 1
}

Write-Host "Using Database: $EventsDatabasePath" -ForegroundColor Cyan
Write-Host "Using Log Archives: $LogArchivesPath" -ForegroundColor Cyan
Write-Host "Using Diagnostic Log: $DiagnosticLogPath" -ForegroundColor Cyan

# --- VALIDATE AND CREATE REQUIRED DIRECTORIES ---
Write-Host "`nValidating directory structure..." -ForegroundColor Yellow

# Ensure OUTPUT directory exists
if (-not (Test-Path $EnvConfig['OUTPUT'])) {
  Write-Host "Creating OUTPUT directory: $($EnvConfig['OUTPUT'])" -ForegroundColor Yellow
  New-Item -Path $EnvConfig['OUTPUT'] -ItemType Directory -Force | Out-Null
  Write-Host "✓ OUTPUT directory created" -ForegroundColor Green
} else {
  Write-Host "✓ OUTPUT directory exists" -ForegroundColor Green
}

# Ensure LOGARCHIVES directory exists
if (-not (Test-Path $LogArchivesPath)) {
  Write-Host "Creating LOGARCHIVES directory: $LogArchivesPath" -ForegroundColor Yellow
  New-Item -Path $LogArchivesPath -ItemType Directory -Force | Out-Null
  Write-Host "✓ LOGARCHIVES directory created" -ForegroundColor Green
} else {
  Write-Host "✓ LOGARCHIVES directory exists" -ForegroundColor Green
}

# Ensure DB parent directory exists (SQLite will create the DB file itself)
$DbParentDir = Split-Path $EventsDatabasePath -Parent
if (-not (Test-Path $DbParentDir)) {
  Write-Host "Creating DB parent directory: $DbParentDir" -ForegroundColor Yellow
  New-Item -Path $DbParentDir -ItemType Directory -Force | Out-Null
  Write-Host "✓ DB parent directory created" -ForegroundColor Green
} else {
  Write-Host "✓ DB parent directory exists" -ForegroundColor Green
}

Write-Host "Directory validation complete`n" -ForegroundColor Green

# --- SQLITE LOADING ---
$SqliteDllPath = $EnvConfig['SQLITE_DLL']
if (-not $SqliteDllPath) {
  Write-Error "SQLITE_DLL path not set. Please configure SQLITE_DLL in .env file"
  exit 1
}
if (-not (Test-Path $SqliteDllPath)) {
  Write-Error "SQLite DLL not found at: $SqliteDllPath"
  Write-Error "Please install PSSQLite module or update SQLITE_DLL path in .env file"
  exit 1
}
Write-Host "Loading SQLite from: $SqliteDllPath" -ForegroundColor Cyan
Add-Type -Path $SqliteDllPath

# --- LOGGING FUNCTIONS ---
function Write-Log {
  param([string]$Message, [string]$Level = "INFO")
  $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $logEntry = "($timestamp) - $Level`: $Message"
  $color = switch ($Level) {
    "ERROR" { "Red" } "WARNING" { "Yellow" } "SUCCESS" { "Green" } "INFO" { "White" } default { "Cyan" }
  }
  Write-Host $logEntry -ForegroundColor $color
  Add-Content -Path $DiagnosticLogPath -Value $logEntry
}

function Initialize-Logging {
  # Output directory already validated and created at script start
  Write-Log "Starting new import session with live log processing." "INFO"
  Write-Log "FILTER: Excluding port 5353 (mDNS) and system processes" "INFO"
}

# --- HELPER FUNCTION: PATH NORMALIZATION ---
function Convert-ApplicationPath {
  param([string]$Path)
  if (-not $Path) { return "UNKNOWN" }
  if ($Path -match '^\\device\\harddiskvolume\d+\\(.+)$') {
    return "c:\$($matches[1])"
  }
  if ($Path -match '^\\[^\\]') {
    return "c:$Path"
  }
  return $Path
}

# --- DATABASE FUNCTIONS ---
function Initialize-EventsDatabase {
  param($EventsDbPath)

  try {
    Write-Log "Initializing database: $EventsDbPath" "INFO"
    $connectionString = "Data Source=$EventsDbPath"
    $connection = New-Object -TypeName System.Data.SQLite.SQLiteConnection -ArgumentList $connectionString
    $connection.Open()

    $command = $connection.CreateCommand()
    $command.CommandText = @"
CREATE TABLE IF NOT EXISTS processed_files (
    filename TEXT PRIMARY KEY,
    processed_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    event_count INTEGER,
    status TEXT DEFAULT 'COMPLETED',
    error_message TEXT,
    processing_time_seconds REAL
);

CREATE TABLE IF NOT EXISTS firewall_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_file TEXT,
    event_id INTEGER,
    event_time DATETIME,
    source_ip TEXT,
    source_port INTEGER,
    dest_ip TEXT,
    dest_port INTEGER,
    protocol INTEGER,
    direction TEXT,
    process_name TEXT,
    process_path TEXT,
    action TEXT,
    raw_data TEXT,
    FOREIGN KEY (source_file) REFERENCES processed_files(filename)
);

CREATE TABLE IF NOT EXISTS import_progress (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    current_file TEXT,
    files_processed INTEGER,
    total_files INTEGER,
    events_processed INTEGER,
    last_update DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_firewall_events_ip ON firewall_events(source_ip, dest_ip);
CREATE INDEX IF NOT EXISTS idx_firewall_events_time ON firewall_events(event_time);
CREATE INDEX IF NOT EXISTS idx_firewall_events_file ON firewall_events(source_file);
CREATE INDEX IF NOT EXISTS idx_firewall_events_ports ON firewall_events(source_port, dest_port);
CREATE UNIQUE INDEX IF NOT EXISTS idx_firewall_events_dedup
ON firewall_events(source_file, event_time, source_ip, dest_ip, process_name, source_port, dest_port);

"@
    $command.ExecuteNonQuery()
    $connection.Close()
    Write-Log "Database initialized successfully" "INFO"
    return $true
  } catch {
    Write-Log "Failed to initialize database: $_" "ERROR"
    return $false
  }
}

function Test-DatabaseLock {
  param($EventsDbPath)
  try {
    $connectionString = "Data Source=$EventsDbPath"
    $connection = New-Object -TypeName System.Data.SQLite.SQLiteConnection -ArgumentList $connectionString
    $connection.Open(); $connection.Close()
    return $true
  } catch {
    return $false
  }
}

# --- DATA CONVERSION & PROCESSING ---
function ConvertTo-EventJson {
  param($EventRecord, $FileName)
  try {
    $xml = [xml]$EventRecord.ToXml()
    $rawProcessPath = ($xml.Event.EventData.Data | Where-Object Name -eq "Application").'#text'
    $normalizedPath = Convert-ApplicationPath -Path $rawProcessPath
    $processName = if ($normalizedPath -ne "UNKNOWN") { Split-Path -Leaf $normalizedPath } else { "UNKNOWN" }

    $filteredProcesses = @("System", "svchost.exe", "Svchost.exe", "SVCHOST.EXE", "nxplayer.bin", "nxserver.bin", "mdnsresponder.exe")
    if ($filteredProcesses -contains $processName.ToLower()) { return $null }

    # Port parsing
    $sourcePortText = ($xml.Event.EventData.Data | Where-Object Name -eq "SourcePort").'#text'
    $destPortText = ($xml.Event.EventData.Data | Where-Object Name -eq "DestPort").'#text'
    $sourcePort = if ([int]::TryParse($sourcePortText, [ref]$null)) { [int]$sourcePortText } else { $null }
    $destPort = if ([int]::TryParse($destPortText, [ref]$null)) { [int]$destPortText } else { $null }

    # --- FILTER OUT PORT 5353 (mDNS) ---
    if ($sourcePort -eq 5353 -or $destPort -eq 5353) {
      return $null  # Skip mDNS traffic
    }

    $action = switch ($EventRecord.Id) { 5156 { "ALLOWED" } 5157 { "BLOCKED" } default { "UNKNOWN" } }
    $directionCode = ($xml.Event.EventData.Data | Where-Object Name -eq "Direction").'#text'
    $direction = switch ($directionCode) { "%%14592" { "INBOUND" } "%%14593" { "OUTBOUND" } default { $directionCode } }
    $protocolText = ($xml.Event.EventData.Data | Where-Object Name -eq "Protocol").'#text'
    $protocol = if ([int]::TryParse($protocolText, [ref]$null)) { [int]$protocolText } else { $null }

    return @{
      source_file  = $FileName
      event_id     = $EventRecord.Id
      event_time   = $EventRecord.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
      source_ip    = ($xml.Event.EventData.Data | Where-Object Name -eq "SourceAddress").'#text'
      source_port  = $sourcePort
      dest_ip      = ($xml.Event.EventData.Data | Where-Object Name -eq "DestAddress").'#text'
      dest_port    = $destPort
      protocol     = $protocol
      direction    = $direction
      process_name = $processName
      process_path = $normalizedPath
      action       = $action
      raw_data     = $EventRecord.ToXml()
    }
  } catch {
    Write-Log "Failed to convert event to JSON: $_" "WARNING"
    return $null
  }
}

function Update-Progress {
  param($Connection, $CurrentFile, $FilesProcessed, $TotalFiles, $EventsProcessed)

  try {
    $cmd = $Connection.CreateCommand()
    $cmd.CommandText = @"
INSERT OR REPLACE INTO import_progress
(id, current_file, files_processed, total_files, events_processed, last_update)
VALUES (1, ?, ?, ?, ?, CURRENT_TIMESTAMP)
"@
    $cmd.Parameters.AddWithValue($null, $CurrentFile) | Out-Null
    $cmd.Parameters.AddWithValue($null, $FilesProcessed) | Out-Null
    $cmd.Parameters.AddWithValue($null, $TotalFiles) | Out-Null
    $cmd.Parameters.AddWithValue($null, $EventsProcessed) | Out-Null
    $cmd.ExecuteNonQuery() | Out-Null
  } catch {
    Write-Log "Failed to update progress: $_" "WARNING"
  }
}

function Get-ResumePoint {
  param($EventsDbPath)

  try {
    $connectionString = "Data Source=$EventsDbPath"
    $connection = New-Object -TypeName System.Data.SQLite.SQLiteConnection -ArgumentList $connectionString
    $connection.Open()

    $cmd = $connection.CreateCommand()
    $cmd.CommandText = "SELECT current_file FROM import_progress WHERE id = 1"
    $result = $cmd.ExecuteScalar()
    $connection.Close()

    return $result
  } catch {
    return $null
  }
}

function Write-EventBatch {
  param($Connection, $EventBatch, $FileName, $BatchId)

  try {
    if ($EventBatch.Count -eq 0) {
      return 0
    }

    # START TRANSACTION
    $transactionCmd = $Connection.CreateCommand()
    $transactionCmd.CommandText = "BEGIN TRANSACTION"
    $transactionCmd.ExecuteNonQuery() | Out-Null

    $processedCount = 0
    $skippedCount = 0

    try {
      foreach ($evtx in $EventBatch) {
        # Create NEW command for each insert
        $insertCmd = $Connection.CreateCommand()
        $insertCmd.CommandText = @"
INSERT OR IGNORE INTO firewall_events
(source_file, event_id, event_time, source_ip, source_port, dest_ip, dest_port, protocol, direction, process_name, process_path, action, raw_data)
VALUES (@source_file, @event_id, @event_time, @source_ip, @source_port, @dest_ip, @dest_port, @protocol, @direction, @process_name, @process_path, @action, @raw_data)
"@

        # Helper function to add parameter with NULL handling
        function Add-ParamWithNull($cmd, $name, $value) {
          if ($null -eq $value -or $value -eq "") {
            $cmd.Parameters.AddWithValue($name, [System.DBNull]::Value) | Out-Null
          } else {
            $cmd.Parameters.AddWithValue($name, $value) | Out-Null
          }
        }

        # Add all parameters with proper NULL handling
        Add-ParamWithNull $insertCmd "@source_file" $evtx.source_file
        Add-ParamWithNull $insertCmd "@event_id" $evtx.event_id
        Add-ParamWithNull $insertCmd "@event_time" $evtx.event_time
        Add-ParamWithNull $insertCmd "@source_ip" $evtx.source_ip
        Add-ParamWithNull $insertCmd "@source_port" $evtx.source_port
        Add-ParamWithNull $insertCmd "@dest_ip" $evtx.dest_ip
        Add-ParamWithNull $insertCmd "@dest_port" $evtx.dest_port
        Add-ParamWithNull $insertCmd "@protocol" $evtx.protocol
        Add-ParamWithNull $insertCmd "@direction" $evtx.direction
        Add-ParamWithNull $insertCmd "@process_name" $evtx.process_name
        Add-ParamWithNull $insertCmd "@process_path" $evtx.process_path
        Add-ParamWithNull $insertCmd "@action" $evtx.action
        Add-ParamWithNull $insertCmd "@raw_data" $evtx.raw_data

        $rowsAffected = $insertCmd.ExecuteNonQuery()
        $insertCmd.Dispose()

        # In the Write-EventBatch function, enhance the tracking:
        if ($rowsAffected -eq 1) {
          $processedCount++
          # ENHANCED TRACKING - include action for security_events aggregation
          $NewlyProcessedEvents.Add([PSCustomObject]@{
              ProcessName = $evtx.process_name
              SourceIP    = $evtx.source_ip
              DestIP      = $evtx.dest_ip
              SourcePort  = $evtx.source_port
              DestPort    = $evtx.dest_port
              EventTime   = $evtx.event_time
              Action      = $evtx.action  # ← ADD THIS for allowed/denied tracking
            })
        } else {
          $skippedCount++
        }
      }

      # COMMIT TRANSACTION
      $commitCmd = $Connection.CreateCommand()
      $commitCmd.CommandText = "COMMIT TRANSACTION"
      $commitCmd.ExecuteNonQuery() | Out-Null

      return $processedCount

    } catch {
      # ROLLBACK on error
      try {
        $rollbackCmd = $Connection.CreateCommand()
        $rollbackCmd.CommandText = "ROLLBACK TRANSACTION"
        $rollbackCmd.ExecuteNonQuery() | Out-Null
      } catch {
        Write-Log "Warning: Could not rollback transaction: $_" "WARNING"
      }
      throw
    }
  } catch {
    Write-Log "FAILED to write event batch ${BatchId}: $($_.Exception.Message)" "ERROR"
    return 0
  }
}# --- BATCH PROCESSING FUNCTION ---


function Import-EvtFile {
  param($File, $EventsDbPath, $FileIndex, $TotalFiles)

  $startTime = Get-Date
  $filename = $File.Name
  $connectionString = "Data Source=$EventsDbPath"

  try {
    $connection = New-Object -TypeName System.Data.SQLite.SQLiteConnection -ArgumentList $connectionString
    $connection.Open()

    # Check if file already processed
    $checkCmd = $connection.CreateCommand()
    $checkCmd.CommandText = "SELECT status FROM processed_files WHERE filename = ?"
    $checkCmd.Parameters.AddWithValue($null, $filename) | Out-Null
    $existingStatus = $checkCmd.ExecuteScalar()

    if ($existingStatus -eq "COMPLETED") {
      $connection.Close()
      return 0
    }

    Write-Log "Processing: $filename ($FileIndex of $TotalFiles)" "INFO"

    # Mark file as in progress
    $progressCmd = $connection.CreateCommand()
    $progressCmd.CommandText = @"
INSERT OR REPLACE INTO processed_files (filename, status, processing_time_seconds)
VALUES (?, 'IN_PROGRESS', 0)
"@
    $progressCmd.Parameters.AddWithValue($null, $filename) | Out-Null
    $progressCmd.ExecuteNonQuery() | Out-Null

    # Get events with XPath filter
    $xpathFilter = "*[System[(EventID=5156 or EventID=5157)]]"
    $events = Get-WinEvent -Path $File.FullName -FilterXPath $xpathFilter -ErrorAction SilentlyContinue

    if ($null -eq $events -or $events.Count -eq 0) {
      Write-Log "No matching events found in: $filename" "INFO"
      $recordCmd = $connection.CreateCommand()
      $recordCmd.CommandText = "UPDATE processed_files SET status = 'COMPLETED', event_count = 0 WHERE filename = ?"
      $recordCmd.Parameters.AddWithValue($null, $filename) | Out-Null
      $recordCmd.ExecuteNonQuery() | Out-Null
      $connection.Close()
      return 0
    }

    Write-Log "Found $($events.Count) events in $filename (before port filtering)" "INFO"

    $eventCount = 0
    $filteredCount = 0
    $batchEvents = [System.Collections.Generic.List[object]]::new()
    $totalProcessed = 0

    foreach ($evt in $events) {
      $jsonEvent = ConvertTo-EventJson -EventRecord $evt -FileName $filename
      if ($null -ne $jsonEvent) {
        $batchEvents.Add($jsonEvent)
      } else {
        $filteredCount++
      }

      # Process batch when full
      if ($batchEvents.Count -ge $BatchSize) {
        $processed = Write-EventBatch -Connection $connection -EventBatch $batchEvents -FileName $filename -BatchId "Batch-$totalProcessed"
        $totalProcessed += $processed
        $batchEvents.Clear()

        # Update progress
        Update-Progress -Connection $connection -CurrentFile $filename -FilesProcessed $FileIndex -TotalFiles $TotalFiles -EventsProcessed $totalProcessed
      }

      $eventCount++
    }

    # Process remaining events
    if ($batchEvents.Count -gt 0) {
      $processed = Write-EventBatch -Connection $connection -EventBatch $batchEvents -FileName $filename -BatchId "Final"
      $totalProcessed += $processed
    }

    # Record completion
    $endTime = Get-Date
    $processingTime = ($endTime - $startTime).TotalSeconds

    $recordCmd = $connection.CreateCommand()
    $recordCmd.CommandText = @"
UPDATE processed_files
SET status = 'COMPLETED', event_count = ?, processing_time_seconds = ?
WHERE filename = ?
"@
    $recordCmd.Parameters.AddWithValue($null, $totalProcessed) | Out-Null
    $recordCmd.Parameters.AddWithValue($null, $processingTime) | Out-Null
    $recordCmd.Parameters.AddWithValue($null, $filename) | Out-Null
    $recordCmd.ExecuteNonQuery() | Out-Null

    $connection.Close()
    Write-Log "Successfully processed $totalProcessed events from $filename ($filteredCount filtered out, ${processingTime}s)" "INFO"
    return $totalProcessed

  } catch {
    Write-Log "Failed to process $filename : $_" "ERROR"

    # Mark file as failed
    try {
      $errorCmd = $connection.CreateCommand()
      $errorCmd.CommandText = "UPDATE processed_files SET status = 'FAILED', error_message = ? WHERE filename = ?"
      $errorCmd.Parameters.AddWithValue($null, $_.Exception.Message) | Out-Null
      $errorCmd.Parameters.AddWithValue($null, $filename) | Out-Null
      $errorCmd.ExecuteNonQuery() | Out-Null
      $connection.Close()
    } catch {
      Write-Log "Failed to record error for $filename : $_" "ERROR"
    }

    return 0
  }
}

# --- VALIDATION FUNCTION ---
function Test-EventFiles {
  param($LogFiles)

  Write-Log "Starting validation of $($LogFiles.Count) files" "INFO"
  $validFiles = @()
  $invalidFiles = @()

  foreach ($file in $LogFiles) {
    try {
      Get-WinEvent -Path $file.FullName -FilterXPath "*[System[(EventID=5156 or EventID=5157)]]" -MaxEvents 1 -ErrorAction Stop | Out-Null
      $validFiles += $file
      Write-Log "Valid: $($file.Name)" "INFO"
    } catch {
      $invalidFiles += $file
      Write-Log "Invalid: $($file.Name) - $_" "WARNING"
    }
  }

  Write-Log "Validation complete: $($validFiles.Count) valid, $($invalidFiles.Count) invalid" "INFO"
  return $validFiles
}

# --- MAIN EXECUTION ---
function Start-Import {
  $script:NewlyProcessedEvents = [System.Collections.Generic.List[object]]::new()
  Write-Log "Starting FINAL event import script" "INFO"
  Initialize-Logging

  # --- DATABASE LOCK HANDLING WITH RETRIES ---
  Write-Log "Checking database accessibility..." "INFO"
  $maxRetries = 3
  $retryCount = 0
  while ($retryCount -lt $maxRetries) {
    if (Test-DatabaseLock -EventsDbPath $EventsDatabasePath) { break }
    $retryCount++
    if ($retryCount -lt $maxRetries) {
      $waitTime = 30 * $retryCount
      Write-Log "Database locked. Waiting $waitTime seconds... (Attempt $retryCount of $maxRetries)" "WARNING"
      Start-Sleep -Seconds $waitTime
    } else {
      Write-Log "Database still locked after $maxRetries attempts. Exiting." "ERROR"
      return
    }
  }
  Write-Log "Database lock check passed." "SUCCESS"

  # --- INITIALIZE DATABASE ---
  if (-not (Initialize-EventsDatabase -EventsDbPath $EventsDatabasePath)) {
    Write-Log "Failed to initialize database. Exiting." "ERROR"
    return
  }

  # --- STEP 1: PROCESS LIVE SECURITY LOG ---
  Write-Log "=== STEP 1: Processing live Security log ===" "INFO"

  $xpathFilter = "*[System[(EventID=5156 or EventID=5157)]]"
  $liveLogProcessed = $false

  # Generate the archive filename ONCE (use for both tracking AND saving)
  $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
  $archiveFileName = "Security-Archive-$timestamp.evtx"
  $archiveFilePath = Join-Path $LogArchivesPath $archiveFileName

  try {
    Write-Log "Reading events from live Security log..." "INFO"
    $liveEvents = Get-WinEvent -LogName 'Security' -FilterXPath $xpathFilter -ErrorAction Stop

    if ($null -ne $liveEvents -and $liveEvents.Count -gt 0) {
      Write-Log "Found $($liveEvents.Count) events in live Security log (before filtering)" "INFO"

      # Open database connection
      $connectionString = "Data Source=$EventsDatabasePath"
      $connection = New-Object -TypeName System.Data.SQLite.SQLiteConnection -ArgumentList $connectionString
      $connection.Open()

      # Mark as in progress (USING THE ARCHIVE FILENAME)
      $progressCmd = $connection.CreateCommand()
      $progressCmd.CommandText = "INSERT OR REPLACE INTO processed_files (filename, status) VALUES (?, 'IN_PROGRESS')"
      $progressCmd.Parameters.AddWithValue($null, $archiveFileName) | Out-Null
      $progressCmd.ExecuteNonQuery() | Out-Null

      # Process events in batches
      $batchEvents = [System.Collections.Generic.List[object]]::new()
      $totalProcessed = 0
      $filteredCount = 0

      # In the live log processing section, add this inside the batch processing loop:
      foreach ($evt in $liveEvents) {
        $jsonEvent = ConvertTo-EventJson -EventRecord $evt -FileName $archiveFileName
        if ($null -ne $jsonEvent) {
          $batchEvents.Add($jsonEvent)
        } else {
          $filteredCount++
        }

        # Process batch when full
        if ($batchEvents.Count -ge $BatchSize) {
          $processed = Write-EventBatch -Connection $connection -EventBatch $batchEvents -FileName $archiveFileName -BatchId "Live-$totalProcessed"
          $totalProcessed += $processed
          $batchEvents.Clear()
        }
      }

      # Process remaining events
      if ($batchEvents.Count -gt 0) {
        $processed = Write-EventBatch -Connection $connection -EventBatch $batchEvents -FileName $archiveFileName -BatchId "Live-Final"
        $totalProcessed += $processed
      }

      # Mark as completed
      $recordCmd = $connection.CreateCommand()
      $recordCmd.CommandText = "UPDATE processed_files SET status = 'COMPLETED', event_count = ? WHERE filename = ?"
      $recordCmd.Parameters.AddWithValue($null, $totalProcessed) | Out-Null
      $recordCmd.Parameters.AddWithValue($null, $archiveFileName) | Out-Null
      $recordCmd.ExecuteNonQuery() | Out-Null

      $connection.Close()

      Write-Log "Successfully processed $totalProcessed events from live log ($filteredCount filtered out)" "SUCCESS"
      $liveLogProcessed = $true

      # --- ARCHIVE AND CLEAR LIVE LOG ---
      if (-not $SkipArchiving) {
        Write-Log "Archiving and clearing live Security log..." "INFO"

        try {
          # Archive directory already validated at script start
          # Archive (USING THE SAME FILENAME WE TRACKED)
          Start-Process -FilePath "wevtutil.exe" -ArgumentList "epl Security `"$archiveFilePath`"" -Wait -NoNewWindow
          Write-Log "Live log archived to: $archiveFileName" "SUCCESS"

          # Clear
          Start-Process -FilePath "wevtutil.exe" -ArgumentList "cl Security" -Wait -NoNewWindow
          Write-Log "Live Security log cleared" "SUCCESS"
        } catch {
          Write-Log "Failed to archive/clear live log: $_" "ERROR"
        }
      }
    } else {
      Write-Log "No events found in live Security log" "INFO"
      $liveLogProcessed = $true
    }
  } catch {
    if ($_.Exception.Message -like "*No events were found*" -or
      $_.Exception.Message -like "*specified selection criteria*") {
      Write-Log "No matching events in live Security log (after XPath filter)" "INFO"
      $liveLogProcessed = $true
    } else {
      Write-Log "Error reading live Security log: $_" "ERROR"
    }
  }

  # --- STEP 2: PROCESS ARCHIVED FILES ---
  Write-Log "=== STEP 2: Processing archived log files ===" "INFO"

  # Log archives directory already validated and created at script start
  $logFiles = Get-ChildItem -Path $LogArchivesPath -Filter "Security-Archive-*.evtx" -ErrorAction SilentlyContinue | Sort-Object Name
  Write-Log "Found $($logFiles.Count) archived log files to process" "INFO"

  if ($logFiles.Count -eq 0) {
    if ($liveLogProcessed) {
      Write-Log "No archived files to process, but live log was processed successfully" "SUCCESS"
    } else {
      Write-Log "No log files found and live log failed. Exiting." "WARNING"
    }
    return
  }

  # Validate files if requested
  if ($ValidateOnly) {
    Test-EventFiles -LogFiles $logFiles
    Write-Log "Validation only mode completed" "INFO"
    return
  }

  # Handle resume functionality
  $startIndex = 0
  if ($Resume) {
    $resumeFile = Get-ResumePoint -EventsDbPath $EventsDatabasePath
    if ($null -ne $resumeFile) {
      Write-Log "Resuming from file: $resumeFile" "INFO"
      $startIndex = [array]::IndexOf($logFiles.Name, $resumeFile)
      if ($startIndex -eq -1) { $startIndex = 0 }
    }
  }

  # Process files
  $totalEvents = 0
  $processedFiles = 0
  $filesToProcess = $logFiles.Count - $startIndex

  Write-Log "Processing $filesToProcess archived files" "INFO"

  for ($i = $startIndex; $i -lt $logFiles.Count; $i++) {
    $file = $logFiles[$i]
    $eventsProcessed = Import-EvtFile -File $file -EventsDbPath $EventsDatabasePath -FileIndex ($i + 1) -TotalFiles $logFiles.Count
    $totalEvents += $eventsProcessed
    $processedFiles++

    if ($eventsProcessed -gt 0 -or $processedFiles % 100 -eq 0 -or $processedFiles -eq $filesToProcess) {
      Write-Log "Progress: $processedFiles/$filesToProcess files, $totalEvents events" "INFO"
    }
  }

  Write-Log "=== IMPORT SUMMARY ===" "SUCCESS"
  Write-Log "Live log processed: $liveLogProcessed" "INFO"
  Write-Log "Archived files processed: $processedFiles" "INFO"
  Write-Log "Total events imported: $totalEvents" "INFO"

  # --- STEP 3: INCREMENTAL UPDATE OF ip_processes TABLE ---
  if ($NewlyProcessedEvents.Count -gt 0) {
    Write-Log "=== STEP 3: Incrementally updating ip_processes table ===" "INFO"
    Write-Log "Processing $($NewlyProcessedEvents.Count) newly imported events for IP-process associations" "INFO"

    try {
      $ipProcessesConnection = New-Object -TypeName System.Data.SQLite.SQLiteConnection -ArgumentList "Data Source=$EventsDatabasePath"
      $ipProcessesConnection.Open()

      # Get unique process-IP combinations from newly processed events
      $uniqueCombinations = @{}
      foreach ($evtx in $NewlyProcessedEvents) {
        # Process source IP
        if ($evtx.SourceIP -and $evtx.SourceIP -ne '') {
          $key = "$($evtx.ProcessName)|$($evtx.SourceIP)"
          if (-not $uniqueCombinations.ContainsKey($key)) {
            $uniqueCombinations[$key] = @{
              ProcessName = $evtx.ProcessName
              IP          = $evtx.SourceIP
              FirstSeen   = $evtx.EventTime
              LastSeen    = $evtx.EventTime
            }
          } else {
            # Update timestamps if needed
            if ($evtx.EventTime -lt $uniqueCombinations[$key].FirstSeen) {
              $uniqueCombinations[$key].FirstSeen = $evtx.EventTime
            }
            if ($evtx.EventTime -gt $uniqueCombinations[$key].LastSeen) {
              $uniqueCombinations[$key].LastSeen = $evtx.EventTime
            }
          }
        }

        # Process destination IP
        if ($evtx.DestIP -and $evtx.DestIP -ne '') {
          $key = "$($evtx.ProcessName)|$($evtx.DestIP)"
          if (-not $uniqueCombinations.ContainsKey($key)) {
            $uniqueCombinations[$key] = @{
              ProcessName = $evtx.ProcessName
              IP          = $evtx.DestIP
              FirstSeen   = $evtx.EventTime
              LastSeen    = $evtx.EventTime
            }
          } else {
            # Update timestamps if needed
            if ($evtx.EventTime -lt $uniqueCombinations[$key].FirstSeen) {
              $uniqueCombinations[$key].FirstSeen = $evtx.EventTime
            }
            if ($evtx.EventTime -gt $uniqueCombinations[$key].LastSeen) {
              $uniqueCombinations[$key].LastSeen = $evtx.EventTime
            }
          }
        }
      }

      Write-Log "Found $($uniqueCombinations.Count) unique process-IP combinations to update" "INFO"

      # Update ip_processes table with only the new combinations
      $updatedCount = 0
      $insertedCount = 0

      $transactionCmd = $ipProcessesConnection.CreateCommand()
      $transactionCmd.CommandText = "BEGIN TRANSACTION"
      $transactionCmd.ExecuteNonQuery() | Out-Null

      foreach ($key in $uniqueCombinations.Keys) {
        $combo = $uniqueCombinations[$key]

        # Check if this combination already exists
        $checkCmd = $ipProcessesConnection.CreateCommand()
        $checkCmd.CommandText = "SELECT first_seen, last_seen FROM ip_processes WHERE ip_address = ? AND process_name = ?"
        $checkCmd.Parameters.AddWithValue($null, $combo.IP) | Out-Null
        $checkCmd.Parameters.AddWithValue($null, $combo.ProcessName) | Out-Null
        $checkReader = $checkCmd.ExecuteReader()

        if ($checkReader.Read()) {
          # Update existing record
          $existingFirstSeen = $checkReader.GetString(0)
          $existingLastSeen = $checkReader.GetString(1)
          $checkReader.Close()

          $newFirstSeen = if ($combo.FirstSeen -lt $existingFirstSeen) { $combo.FirstSeen } else { $existingFirstSeen }
          $newLastSeen = if ($combo.LastSeen -gt $existingLastSeen) { $combo.LastSeen } else { $existingLastSeen }

          $updateCmd = $ipProcessesConnection.CreateCommand()
          $updateCmd.CommandText = "UPDATE ip_processes SET first_seen = ?, last_seen = ? WHERE ip_address = ? AND process_name = ?"
          $updateCmd.Parameters.AddWithValue($null, $newFirstSeen) | Out-Null
          $updateCmd.Parameters.AddWithValue($null, $newLastSeen) | Out-Null
          $updateCmd.Parameters.AddWithValue($null, $combo.IP) | Out-Null
          $updateCmd.Parameters.AddWithValue($null, $combo.ProcessName) | Out-Null
          $updateCmd.ExecuteNonQuery() | Out-Null
          $updatedCount++
        } else {
          # Insert new record
          $checkReader.Close()
          $insertCmd = $ipProcessesConnection.CreateCommand()
          $insertCmd.CommandText = "INSERT INTO ip_processes (ip_address, process_name, first_seen, last_seen) VALUES (?, ?, ?, ?)"
          $insertCmd.Parameters.AddWithValue($null, $combo.IP) | Out-Null
          $insertCmd.Parameters.AddWithValue($null, $combo.ProcessName) | Out-Null
          $insertCmd.Parameters.AddWithValue($null, $combo.FirstSeen) | Out-Null
          $insertCmd.Parameters.AddWithValue($null, $combo.LastSeen) | Out-Null
          $insertCmd.ExecuteNonQuery() | Out-Null
          $insertedCount++
        }
      }

      $commitCmd = $ipProcessesConnection.CreateCommand()
      $commitCmd.CommandText = "COMMIT TRANSACTION"
      $commitCmd.ExecuteNonQuery() | Out-Null

      $ipProcessesConnection.Close()

      Write-Log "ip_processes table updated incrementally: $insertedCount new records, $updatedCount updated records" "SUCCESS"

    } catch {
      Write-Log "Error incrementally updating ip_processes table: $_" "ERROR"
      try {
        $rollbackCmd = $ipProcessesConnection.CreateCommand()
        $rollbackCmd.CommandText = "ROLLBACK TRANSACTION"
        $rollbackCmd.ExecuteNonQuery() | Out-Null
        $ipProcessesConnection.Close()
      } catch {}
    }
  } else {
    Write-Log "No new events to process for ip_processes update" "INFO"
  }

  # --- STEP 4: INCREMENTAL UPDATE OF security_events TABLE ---
  if ($NewlyProcessedEvents.Count -gt 0) {
    Write-Log "=== STEP 4: Incrementally updating security_events table ===" "INFO"
    Write-Log "Processing $($NewlyProcessedEvents.Count) newly imported events for security events aggregation" "INFO"

    try {
      $securityEventsConnection = New-Object -TypeName System.Data.SQLite.SQLiteConnection -ArgumentList "Data Source=$EventsDatabasePath"
      $securityEventsConnection.Open()

      # Ensure the security_events table exists
      $createTableCmd = $securityEventsConnection.CreateCommand()
      $createTableCmd.CommandText = @"
CREATE TABLE IF NOT EXISTS security_events (
    application_path TEXT PRIMARY KEY,
    total_connections INTEGER,
    allowed_connections INTEGER,
    denied_connections INTEGER,
    unique_source_ips TEXT,
    unique_source_ips_count INTEGER,
    unique_dest_ips TEXT,
    unique_dest_ips_count INTEGER,
    unique_source_ports TEXT,
    unique_source_ports_count INTEGER,
    unique_dest_ports TEXT,
    unique_dest_ports_count INTEGER,
    first_seen DATETIME,
    last_seen DATETIME
);
"@
      $createTableCmd.ExecuteNonQuery() | Out-Null

      # Aggregate the new events by process name
      $processAggregates = @{}

      foreach ($evtx in $NewlyProcessedEvents) {
        $processName = $evtx.ProcessName
        if (-not $processAggregates.ContainsKey($processName)) {
          $processAggregates[$processName] = @{
            TotalConnections   = 0
            AllowedConnections = 0
            DeniedConnections  = 0
            SourceIPs          = @{}
            DestIPs            = @{}
            SourcePorts        = @{}
            DestPorts          = @{}
            FirstSeen          = $evtx.EventTime
            LastSeen           = $evtx.EventTime
          }
        }

        $agg = $processAggregates[$processName]
        $agg.TotalConnections++

        # Track allowed/denied connections using the Action field
        if ($evtx.Action -eq 'ALLOWED') {
          $agg.AllowedConnections++
        } elseif ($evtx.Action -eq 'BLOCKED') {
          $agg.DeniedConnections++
        }

        # Note: We'd need to track action in NewlyProcessedEvents to do allowed/denied properly
        # For now, we'll focus on the aggregations we can do with current data

        # Track unique IPs and ports
        if ($evtx.SourceIP -and $evtx.SourceIP -ne '') {
          $agg.SourceIPs[$evtx.SourceIP] = $true
        }
        if ($evtx.DestIP -and $evtx.DestIP -ne '') {
          $agg.DestIPs[$evtx.DestIP] = $true
        }

        # Update timestamps
        if ($evtx.EventTime -lt $agg.FirstSeen) {
          $agg.FirstSeen = $evtx.EventTime
        }
        if ($evtx.EventTime -gt $agg.LastSeen) {
          $agg.LastSeen = $evtx.EventTime
        }
      }

      Write-Log "Found $($processAggregates.Count) processes to update in security_events" "INFO"

      # Update security_events table
      $updatedCount = 0
      $insertedCount = 0

      $transactionCmd = $securityEventsConnection.CreateCommand()
      $transactionCmd.CommandText = "BEGIN TRANSACTION"
      $transactionCmd.ExecuteNonQuery() | Out-Null

      foreach ($processName in $processAggregates.Keys) {
        $agg = $processAggregates[$processName]

        # Check if this process already exists in security_events
        $checkCmd = $securityEventsConnection.CreateCommand()
        $checkCmd.CommandText = "SELECT total_connections, first_seen, last_seen, unique_source_ips, unique_dest_ips FROM security_events WHERE application_path = ?"
        $checkCmd.Parameters.AddWithValue($null, $processName) | Out-Null
        $checkReader = $checkCmd.ExecuteReader()

        if ($checkReader.Read()) {
          # Update existing record - merge with existing data

          $existingFirstSeen = $checkReader['first_seen']
          $existingLastSeen = $checkReader['last_seen']
          $existingSourceIPs = if ($checkReader['unique_source_ips']) { $checkReader['unique_source_ips'].Split(',') } else { @() }
          $existingDestIPs = if ($checkReader['unique_dest_ips']) { $checkReader['unique_dest_ips'].Split(',') } else { @() }
          $checkReader.Close()

          # Merge IP sets (ensure we filter out empty strings)
          $allSourceIPs = @()
          if ($existingSourceIPs) {
            $allSourceIPs += $existingSourceIPs | Where-Object { $_ -and $_.Trim() -ne '' }
          }
          if ($agg.SourceIPs.Keys) {
            $allSourceIPs += $agg.SourceIPs.Keys | Where-Object { $_ -and $_.Trim() -ne '' }
          }
          $mergedSourceIPs = $allSourceIPs | Sort-Object -Unique

          $allDestIPs = @()
          if ($existingDestIPs) {
            $allDestIPs += $existingDestIPs | Where-Object { $_ -and $_.Trim() -ne '' }
          }
          if ($agg.DestIPs.Keys) {
            $allDestIPs += $agg.DestIPs.Keys | Where-Object { $_ -and $_.Trim() -ne '' }
          }
          $mergedDestIPs = $allDestIPs | Sort-Object -Unique

          # Calculate new timestamps
          $newFirstSeen = if ($agg.FirstSeen -lt $existingFirstSeen) { $agg.FirstSeen } else { $existingFirstSeen }
          $newLastSeen = if ($agg.LastSeen -gt $existingLastSeen) { $agg.LastSeen } else { $existingLastSeen }

          $updateCmd = $securityEventsConnection.CreateCommand()
          $updateCmd.CommandText = @"
UPDATE security_events SET
    total_connections = total_connections + ?,
    allowed_connections = allowed_connections + ?,
    denied_connections = denied_connections + ?,
    unique_source_ips = ?,
    unique_source_ips_count = ?,
    unique_dest_ips = ?,
    unique_dest_ips_count = ?,
    first_seen = ?,
    last_seen = ?
WHERE application_path = ?
"@
          # And add the parameters:
          $updateCmd.Parameters.AddWithValue($null, $agg.TotalConnections) | Out-Null
          $updateCmd.Parameters.AddWithValue($null, $agg.AllowedConnections) | Out-Null  # ← Add this
          $updateCmd.Parameters.AddWithValue($null, $agg.DeniedConnections) | Out-Null   # ← Add this
          $updateCmd.Parameters.AddWithValue($null, ($mergedSourceIPs -join ',')) | Out-Null
          $updateCmd.Parameters.AddWithValue($null, $mergedSourceIPs.Count) | Out-Null
          $updateCmd.Parameters.AddWithValue($null, ($mergedDestIPs -join ',')) | Out-Null
          $updateCmd.Parameters.AddWithValue($null, $mergedDestIPs.Count) | Out-Null
          $updateCmd.Parameters.AddWithValue($null, $newFirstSeen) | Out-Null
          $updateCmd.Parameters.AddWithValue($null, $newLastSeen) | Out-Null
          $updateCmd.Parameters.AddWithValue($null, $processName) | Out-Null
          $updateCmd.ExecuteNonQuery() | Out-Null
          $updatedCount++
        } else {
          # Insert new record
          $checkReader.Close()
          $insertCmd = $securityEventsConnection.CreateCommand()
          $insertCmd.CommandText = @"
INSERT INTO security_events (
    application_path, total_connections, allowed_connections, denied_connections,
    unique_source_ips, unique_source_ips_count, unique_dest_ips, unique_dest_ips_count,
    first_seen, last_seen
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"@
          # Update the parameters to include the actual counts:
          $insertCmd.Parameters.AddWithValue($null, $processName) | Out-Null
          $insertCmd.Parameters.AddWithValue($null, $agg.TotalConnections) | Out-Null
          $insertCmd.Parameters.AddWithValue($null, $agg.AllowedConnections) | Out-Null  # ← Use actual count
          $insertCmd.Parameters.AddWithValue($null, $agg.DeniedConnections) | Out-Null   # ← Use actual count
          $insertCmd.Parameters.AddWithValue($null, ($agg.SourceIPs.Keys -join ',')) | Out-Null
          $insertCmd.Parameters.AddWithValue($null, $agg.SourceIPs.Count) | Out-Null
          $insertCmd.Parameters.AddWithValue($null, ($agg.DestIPs.Keys -join ',')) | Out-Null
          $insertCmd.Parameters.AddWithValue($null, $agg.DestIPs.Count) | Out-Null
          $insertCmd.Parameters.AddWithValue($null, $agg.FirstSeen) | Out-Null
          $insertCmd.Parameters.AddWithValue($null, $agg.LastSeen) | Out-Null

          $insertCmd.ExecuteNonQuery() | Out-Null
          $insertedCount++
        }
      }

      $commitCmd = $securityEventsConnection.CreateCommand()
      $commitCmd.CommandText = "COMMIT TRANSACTION"
      $commitCmd.ExecuteNonQuery() | Out-Null

      $securityEventsConnection.Close()

      Write-Log "security_events table updated incrementally: $insertedCount new processes, $updatedCount updated processes" "SUCCESS"

    } catch {
      Write-Log "Error incrementally updating security_events table: $_" "ERROR"
      try {
        $rollbackCmd = $securityEventsConnection.CreateCommand()
        $rollbackCmd.CommandText = "ROLLBACK TRANSACTION"
        $rollbackCmd.ExecuteNonQuery() | Out-Null
        $securityEventsConnection.Close()
      } catch {}
    }
  } else {
    Write-Log "No new events to process for security_events update" "INFO"
  }

}

# --- SCRIPT ENTRY POINT ---
Start-Import
