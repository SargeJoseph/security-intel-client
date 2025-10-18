# SecurityDB.psm1 - PowerShell module for database access

$Script:PythonExe = "python"
$Script:ApiScript = Join-Path $PSScriptRoot "security_db_api.py"

function Test-Python {
    try {
        $null = Get-Command python -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Test-DBAPI {
    return (Test-Path $Script:ApiScript) -and (Test-Python)
}

function ConvertTo-DBEvent {
    param(
        [string]$ApplicationPath,
        [int]$TotalConnections,
        [int]$AllowedConnections,
        [int]$DeniedConnections,
        [string]$UniqueIPs,
        [string]$UniquePorts,
        [int]$UniqueIPsCount,
        [int]$UniquePortsCount
    )

    # Fix application path if needed
    if ($ApplicationPath -match '^\\[^\\]') {
        $ApplicationPath = "c:$ApplicationPath"
    }

    return @{
        application_path    = $ApplicationPath
        total_connections   = $TotalConnections
        allowed_connections = $AllowedConnections
        denied_connections  = $DeniedConnections
        unique_ips          = $UniqueIPs
        unique_ports        = $UniquePorts
        unique_ips_count    = $UniqueIPsCount
        unique_ports_count  = $UniquePortsCount
    }
}

function Write-SecurityEventsSimple {
    param([hashtable]$SummaryHash, [string]$LogPath)

    if (-not (Test-DBAPI)) {
        Add-Content -Path $LogPath -Value "($(Get-Date)) - ERROR: Database API not available"
        return $false
    }

    # Check if we have data FIRST
    if ($null -eq $SummaryHash -or $SummaryHash.Count -eq 0) {
        Add-Content -Path $LogPath -Value "($(Get-Date)) - WARNING: No summary data to write to database"
        return $false
    }

    # Create simple JSON structure
    $eventsList = [System.Collections.Generic.List[object]]::new()

    Add-Content -Path $LogPath -Value "($(Get-Date)) - DEBUG: Processing $($SummaryHash.Count) summary entries"

    foreach ($entry in $SummaryHash.GetEnumerator()) {
        $eventData = @{
            application_path    = $entry.Key
            total_connections   = $entry.Value.Total
            allowed_connections = $entry.Value.Allowed
            denied_connections  = $entry.Value.Denied
            unique_ips          = (($entry.Value.IPs | Sort-Object) -join "; ")
            unique_ports        = (($entry.Value.Ports | Sort-Object) -join "; ")
            unique_ips_count    = $entry.Value.IPs.Count
            unique_ports_count  = $entry.Value.Ports.Count
        }
        $eventsList.Add($eventData)
    }

    Add-Content -Path $LogPath -Value "($(Get-Date)) - DEBUG: Created $($eventsList.Count) events for database"

    # Convert to JSON
    $jsonContent = $eventsList | ConvertTo-Json -Depth 10
    $tempJson = Join-Path $env:TEMP "security_events_simple_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"

    try {
        Add-Content -Path $LogPath -Value "($(Get-Date)) - DEBUG: Writing to temp JSON: $tempJson"
        $jsonContent | Out-File -FilePath $tempJson -Encoding UTF8

        # Verify file was written
        if (-not (Test-Path $tempJson)) {
            Add-Content -Path $LogPath -Value "($(Get-Date)) - ERROR: Temp JSON file was not created"
            return $false
        }

        $fileSize = (Get-Item $tempJson).Length
        Add-Content -Path $LogPath -Value "($(Get-Date)) - DEBUG: Temp file size: $fileSize bytes"

        Add-Content -Path $LogPath -Value "($(Get-Date)) - DEBUG: Calling Python API..."
        $result = & $Script:PythonExe $Script:ApiScript $tempJson 2>&1

        Add-Content -Path $LogPath -Value "($(Get-Date)) - DEBUG: Python exit code: $LASTEXITCODE"
        Add-Content -Path $LogPath -Value "($(Get-Date)) - DEBUG: Python output: $result"

        # Clean up temp file
        Remove-Item $tempJson -Force -ErrorAction SilentlyContinue

        if ($LASTEXITCODE -eq 0) {
            Add-Content -Path $LogPath -Value "($(Get-Date)) - SUCCESS: $($eventsList.Count) events written to database"
            return $true
        } else {
            Add-Content -Path $LogPath -Value "($(Get-Date)) - ERROR: Python API failed - $result"
            return $false
        }
    } catch {
        Add-Content -Path $LogPath -Value "($(Get-Date)) - ERROR: Simple write failed - $_"
        # Clean up temp file on error
        if (Test-Path $tempJson) {
            Remove-Item $tempJson -Force -ErrorAction SilentlyContinue
        }
        return $false
    }
}

function Invoke-ProcessIPLinking {
    param([string]$LogPath)

    if (-not (Test-DBAPI)) {
        Add-Content -Path $LogPath -Value "($(Get-Date)) - ERROR: Database API not available for process linking"
        return $false
    }

    Add-Content -Path $LogPath -Value "($(Get-Date)) - Linking processes to IPs..."

    try {
        $result = & $Script:PythonExe -c @"
import sys
sys.path.append('$($PSScriptRoot.Replace('\', '/'))')
from security_db_api import SecurityDBAPI
api = SecurityDBAPI()
success = api.link_processes_to_ips()
print('SUCCESS' if success else 'FAILED')
"@ 2>&1

        Add-Content -Path $LogPath -Value "($(Get-Date)) - Process linking result: $result"

        if ($result -match 'SUCCESS') {
            Add-Content -Path $LogPath -Value "($(Get-Date)) - Process-IP linking completed successfully"
            return $true
        } else {
            Add-Content -Path $LogPath -Value "($(Get-Date)) - Process-IP linking failed"
            return $false
        }
    } catch {
        Add-Content -Path $LogPath -Value "($(Get-Date)) - ERROR during process linking: $_"
        return $false
    }
}

function Test-ArchiveProcessed {
    param([string]$ArchiveName, [string]$LogPath)

    if (-not (Test-DBAPI)) {
        # If we can't check, assume it's not processed to be safe
        return $false
    }

    $fileName = Split-Path -Leaf $ArchiveName
    $fileNameEscaped = $fileName -replace "'", "''"

    try {
        $result = & $Script:PythonExe -c @"
import sys
sys.path.append('$($PSScriptRoot.Replace('\', '/'))')
from security_db_api import SecurityDBAPI
api = SecurityDBAPI()
is_processed = api.is_archive_processed('$fileNameEscaped')
print('TRUE' if is_processed else 'FALSE')
"@ 2>&1

        return ($result -eq 'TRUE')
    } catch {
        Add-Content -Path $LogPath -Value "($(Get-Date)) - WARNING: Archive check failed for $fileName : $_"
        return $false # Fail safely
    }
}

function Add-ProcessedArchive {
    param(
        [string]$ArchiveName,
        [int]$EventCount,
        [string]$LogPath
    )

    if (-not (Test-DBAPI)) {
        Add-Content -Path $LogPath -Value "($(Get-Date)) - WARNING: Cannot track archive (API not available)"
        return $false
    }

    # Extract just the filename if a full path was provided
    $fileName = Split-Path -Leaf $ArchiveName

    # Escape single quotes for Python string
    $fileNameEscaped = $fileName -replace "'", "''"

    try {
        $result = & $Script:PythonExe -c @"
import sys
sys.path.append('$($PSScriptRoot.Replace('\', '/'))')
from security_db_api import SecurityDBAPI
api = SecurityDBAPI()
api.track_processed_archive('$fileNameEscaped', $EventCount)
print('SUCCESS')
"@ 2>&1

        if ($result -match 'SUCCESS') {
            Add-Content -Path $LogPath -Value "($(Get-Date)) - Tracked archive: $fileName ($EventCount events)"
            return $true
        } else {
            Add-Content -Path $LogPath -Value "($(Get-Date)) - WARNING: Could not track archive: $result"
            return $false
        }
    } catch {
        Add-Content -Path $LogPath -Value "($(Get-Date)) - WARNING: Archive tracking failed: $_"
        return $false
    }
}

# Export all functions
Export-ModuleMember -Function *
