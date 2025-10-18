"""
VirusTotal API Module
Handles all interactions with VirusTotal CLI, file scanning, and uploads.
"""

import hashlib
import json
import os
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.prompt import Confirm
from rich.panel import Panel
from rich.table import Table
from rich import box
import re

from constants import (
    VT_SCAN_DELAY, VT_UPLOAD_DAILY_LIMIT, VT_MAX_FILE_SIZE,
    VT_SCAN_TIMEOUT, VT_UPLOAD_TIMEOUT, VT_VERSION_TIMEOUT,
    EXCLUDED_VENDORS, PROGRESS_DESCRIPTION, DB_MAX_RETRIES, DB_RETRY_DELAY,
    VT_CACHE_MAX_DAYS
)
from config import VT_CLI_PATH
from vt_db import VTDatabase
_SHA256_RE = re.compile(r'^[0-9a-fA-F]{64}\Z')
console = Console()


class VTScanner:
    """VirusTotal scanner using VT CLI with UPLOAD CAPABILITY"""

    def __init__(self, vt_db: VTDatabase):
        self.vt_db = vt_db
        self.vt_cli_path = None  # Instance variable instead of global
        self.check_vt_cli()

    def check_vt_cli(self):
        """Verify VT CLI is installed with enhanced security validation"""
        import shutil
        import stat

        # Check if VT_CLI_PATH is set in .env first
        if VT_CLI_PATH:
            vt_path = Path(VT_CLI_PATH)
            if vt_path.exists() and vt_path.is_file():
                console.print(f"[cyan]Using VT CLI from .env: {vt_path}[/cyan]")
                self.vt_cli_path = str(vt_path)
                # Quick validation test
                try:
                    result = subprocess.run(
                        [str(vt_path), 'version'],
                        capture_output=True,
                        text=True,
                        timeout=VT_VERSION_TIMEOUT,
                        shell=False
                    )
                    if result.returncode == 0:
                        console.print(f"[green]✓ VT CLI validated: {result.stdout.strip()}[/green]")
                        return
                    else:
                        console.print(f"[yellow]Warning: VT CLI at {vt_path} failed validation, searching system paths...[/yellow]")
                        self.vt_cli_path = None
                except Exception as e:
                    console.print(f"[yellow]Warning: Could not validate VT CLI at {vt_path}: {e}[/yellow]")
                    console.print("[yellow]Searching system paths...[/yellow]")
                    self.vt_cli_path = None
            else:
                console.print(f"[yellow]VT_CLI_PATH in .env not found: {vt_path}, searching system paths...[/yellow]")

        # STRICT WHITELIST - only these exact names allowed
        ALLOWED_CLI_NAMES = frozenset(["vt", "vt.exe"])

        # Platform-specific safe system directories
        if os.name == 'nt':
            SAFE_SYSTEM_PATHS = frozenset([
                os.environ.get('PROGRAMFILES', 'C:\\Program Files'),
                os.environ.get('PROGRAMFILES(X86)', 'C:\\Program Files (x86)'),
                os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Programs'),
                os.path.join(os.environ.get('USERPROFILE', ''), 'AppData', 'Local', 'Programs')
            ])
        else:
            SAFE_SYSTEM_PATHS = frozenset([
                '/usr/local/bin',
                '/usr/bin',
                '/opt/local/bin',
                os.path.expanduser('~/.local/bin')
            ])

        def is_path_safe(test_path, safe_directories):
            """Check if path is within safe directories with proper normalization"""
            test_path = os.path.normcase(os.path.normpath(os.path.realpath(test_path)))

            for safe_dir in safe_directories:
                if not safe_dir:  # Skip empty paths
                    continue

                safe_dir_norm = os.path.normcase(os.path.normpath(os.path.realpath(safe_dir)))

                # Check if test_path starts with safe_dir
                if test_path.startswith(safe_dir_norm):
                    remaining = test_path[len(safe_dir_norm):]
                    # Valid if nothing remains or it starts with path separator
                    if not remaining or remaining.startswith(os.sep):
                        return True

            return False

        validated_paths = []

        # Step 1: Try shutil.which first
        for cli_name in ALLOWED_CLI_NAMES:
            if not cli_name.replace('.', '').replace('_', '').isalnum():
                continue

            try:
                found_path = shutil.which(cli_name)

                if found_path and os.path.isfile(found_path):
                    # Resolve to absolute path (prevents symlink attacks)
                    resolved_path = os.path.realpath(found_path)

                    # Validate path is in safe directory
                    if is_path_safe(resolved_path, SAFE_SYSTEM_PATHS):
                        # Check file permissions (should not be world-writable)
                        file_stat = os.stat(resolved_path)
                        if os.name != 'nt':  # Unix-like systems
                            if file_stat.st_mode & stat.S_IWOTH:
                                console.print(f"[yellow]Warning: {resolved_path} is world-writable, skipping[/yellow]")
                                continue

                        validated_paths.append(resolved_path)
                    else:
                        console.print(f"[dim]Found {cli_name} at {resolved_path} but not in safe directories[/dim]")

            except Exception as e:
                console.print(f"[dim]Error checking {cli_name}: {e}[/dim]")
                continue

        # Step 2: Test validated executables
        for cli_path in validated_paths:
            try:
                # Double-check the path still exists and is executable
                if not os.path.isfile(cli_path):
                    continue

                if os.name != 'nt':
                    if not os.access(cli_path, os.X_OK):
                        continue

                # Build minimal secure environment
                secure_env = {
                    'SYSTEMROOT': os.environ.get('SYSTEMROOT', 'C:\\Windows'),
                    'TEMP': os.environ.get('TEMP', ''),
                    'TMP': os.environ.get('TMP', ''),
                }

                # Add PATH - use full system PATH for DLL resolution
                # but ensure our validated directory is first
                cli_dir = os.path.dirname(cli_path)
                system_path = os.environ.get('PATH', '')
                secure_env['PATH'] = f"{cli_dir}{os.pathsep}{system_path}"

                # Add Windows-specific required variables
                if os.name == 'nt':
                    for var in ['USERPROFILE', 'HOMEDRIVE', 'HOMEPATH', 'APPDATA', 'LOCALAPPDATA']:
                        val = os.environ.get(var)
                        if val:
                            secure_env[var] = val

                # Test execution with strict security settings
                result = subprocess.run(
                    [cli_path, 'version'],
                    capture_output=True,
                    text=True,
                    timeout=VT_VERSION_TIMEOUT,
                    env=secure_env,
                    shell=False,  # Prevent shell injection
                    close_fds=True  # Don't inherit file descriptors
                )

                if result.returncode == 0:
                    # Verify output looks like VT CLI version
                    output = result.stdout.strip()

                    if 'vt' in output.lower() or 'virustotal' in output.lower():
                        console.print(f"[green]✓ VT CLI validated at: {cli_path}[/green]")
                        version_match = output.split()[0] if output else 'unknown'
                        console.print(f"[green]Version: {version_match}[/green]")

                        # Store validated path in instance variable
                        self.vt_cli_path = cli_path
                        return
                    else:
                        console.print(f"[yellow]Unexpected version output from {cli_path}[/yellow]")

            except subprocess.TimeoutExpired:
                console.print(f"[yellow]Timeout testing {cli_path}[/yellow]")
            except Exception as e:
                console.print(f"[dim]Error testing {cli_path}: {e}[/dim]")
                continue

        # Step 3: Not found - provide secure guidance
        console.print("[red]VT CLI not found in safe system locations.[/red]")
        console.print("[yellow]Please install from: https://github.com/VirusTotal/vt-cli[/yellow]")
        console.print("[yellow]Ensure 'vt' is installed in a standard system directory:[/yellow]")

        for safe_path in sorted(SAFE_SYSTEM_PATHS):
            if safe_path and os.path.isdir(safe_path):
                console.print(f"  • {safe_path}")

        if Confirm.ask("Continue without VT scanning?"):
            console.print("[yellow]VT scanning will be disabled[/yellow]")
        else:
            import sys
            sys.exit(1)

    def calculate_hash(self, file_path: str) -> Optional[str]:
        """Calculate SHA256 hash of a file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest().lower()
        except Exception as e:
            console.print(f"[red]Error calculating hash for {file_path}: {e}[/red]")
            return None

    def upload_file(self, file_path: str, sha256: Optional[str] = None) -> Optional[Dict]:
        """Upload a file to VirusTotal"""
        console.print(f"🔍 [DEBUG] upload_file START: {Path(file_path).name}")

        # Check if VT CLI is available
        if not self.vt_cli_path:
            console.print("[red]VT CLI not available for upload[/red]")
            return None

        # Check daily upload limit
        uploads_today = self.vt_db.get_upload_count_today()
        if uploads_today >= VT_UPLOAD_DAILY_LIMIT:
            console.print(f"[red]Daily upload limit reached ({VT_UPLOAD_DAILY_LIMIT})[/red]")
            return None

        # Calculate hash if not provided
        if not sha256:
            sha256 = self.calculate_hash(file_path)
            if not sha256:
                return None

        # Check file size (VT limit: 650MB for API, 32MB for web)
        file_size = Path(file_path).stat().st_size
        if file_size > VT_MAX_FILE_SIZE:
            console.print(f"[red]File too large for upload: {file_size / (1024*1024):.1f}MB[/red]")
            self.vt_db.track_upload(sha256, False, "File too large")
            return None

        console.print(f"[cyan]Uploading {Path(file_path).name} ({file_size / 1024:.1f}KB)...[/cyan]")

        try:
            # Upload using VT CLI (correct command: vt scan file <path>)
            console.print(f"[dim]Running: vt scan file \"{file_path}\"[/dim]")
            result = subprocess.run(
                [self.vt_cli_path, "scan", "file", file_path, "--format", "json"],
                capture_output=True,
                text=True,
                timeout=VT_UPLOAD_TIMEOUT,
                encoding='utf-8',
                errors='ignore'
            )

            # Debug output
            console.print(f"[dim]VT upload return code: {result.returncode}[/dim]")
            console.print(f"[dim]VT stdout length: {len(result.stdout)} chars[/dim]")
            console.print(f"[dim]VT stderr length: {len(result.stderr) if result.stderr else 0} chars[/dim]")
            if result.stdout:
                console.print(f"[dim]First 500 chars of stdout: {result.stdout[:500]}[/dim]")
            if result.stderr:
                console.print(f"[dim]Stderr: {result.stderr[:500]}[/dim]")

            if result.returncode != 0:
                error_msg = result.stderr if result.stderr else "Unknown error"
                console.print(f"[red]Upload failed: {error_msg}[/red]")

                # Create placeholder hash entry before tracking failed upload
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                try:
                    cursor = self.vt_db.conn.cursor()
                    cursor.execute('''
                        INSERT OR IGNORE INTO file_hashes
                        (sha256, file_name, status, first_seen, last_seen, file_size, upload_attempted)
                        VALUES (?, ?, ?, ?, ?, ?, 1)
                    ''', (sha256, Path(file_path).name.lower(), 'upload_failed', now, now, file_size))
                    self.vt_db.conn.commit()
                except Exception as e:
                    console.print(f"[yellow]Warning: Could not create hash entry: {e}[/yellow]")

                self.vt_db.track_upload(sha256, False, error_msg)
                self.vt_db.track_api_usage('file_upload', False)
                return None

            # Parse upload response
            try:
                data = json.loads(result.stdout)
                console.print(f"[dim]JSON parsed successfully[/dim]")
                console.print(f"[dim]Response type: {type(data)}[/dim]")
                if isinstance(data, dict):
                    console.print(f"[dim]Response keys: {list(data.keys())}[/dim]")
            except json.JSONDecodeError as e:
                console.print(f"[yellow]Upload succeeded but couldn't parse response: {e}[/yellow]")
                console.print(f"[dim]Raw response: {result.stdout[:1000]}[/dim]")
                data = None

            # Create placeholder hash entry BEFORE tracking upload
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            try:
                cursor = self.vt_db.conn.cursor()
                cursor.execute('''
                    INSERT OR IGNORE INTO file_hashes
                    (sha256, file_name, status, first_seen, last_seen, file_size, upload_attempted)
                    VALUES (?, ?, ?, ?, ?, ?, 1)
                ''', (sha256, Path(file_path).name.lower(), 'uploaded', now, now, file_size))
                self.vt_db.conn.commit()
            except Exception as e:
                console.print(f"[yellow]Warning: Could not create hash entry: {e}[/yellow]")

            # Track successful upload
            self.vt_db.track_upload(sha256, True)
            self.vt_db.track_api_usage('file_upload', True)

            console.print(f"[green]File uploaded successfully![/green]")
            console.print(f"[yellow]VirusTotal is analyzing the file. This may take a few minutes...[/yellow]")

            # Wait longer and try scanning multiple times
            for attempt in range(3):
                console.print(f"[dim]Waiting for analysis... attempt {attempt + 1}/3[/dim]")
                time.sleep(15)  # Wait 30 seconds between attempts

                scan_result = self.scan_hash(sha256)
                if scan_result and scan_result.get('status') == 'scanned':
                    console.print(f"[green]File analyzed successfully![/green]")
                    return scan_result
                elif scan_result and scan_result.get('status') == 'not_found':
                    console.print(f"[yellow]File not yet available in database, retrying...[/yellow]")
                    continue

            console.print(f"[yellow]File uploaded but not yet analyzed. It will be available in VT shortly.[/yellow]")
            return {'status': 'uploaded', 'sha256': sha256}

        except subprocess.TimeoutExpired:
            console.print("[red]Upload timed out[/red]")
            self.vt_db.track_upload(sha256, False, "Timeout")
            return None
        except Exception as e:
            console.print(f"[red]Upload error: {e}[/red]")
            self.vt_db.track_upload(sha256, False, str(e))
            return None

    def scan_file(self, file_path: str, allow_upload: bool = False) -> Optional[Dict]:
        """Calculate hash and scan a file, with optional upload capability"""
        console.print(f"[DEBUG] scan_file called: {Path(file_path).name}, allow_upload={allow_upload}")
        try:
            # Calculate SHA256
            sha256 = self.calculate_hash(file_path)
            console.print(f"🔍 [DEBUG] Calculated hash: {sha256}")
            if not sha256:
                return None

            # Check if already scanned recently (cached)
            try:
                hash_info = self.vt_db.get_hash_info(sha256)
                if hash_info and hash_info.get('last_scanned'):
                    last_scan = datetime.fromisoformat(hash_info['last_scanned'])
                    if datetime.now() - last_scan < timedelta(days=VT_CACHE_MAX_DAYS):
                        console.print(f"[green]Using cached scan (age: {(datetime.now() - last_scan).days} days)[/green]")
                        return {
                            'sha256': sha256,
                            'cached': True,
                            'status': hash_info.get('status', 'unknown'),
                            'malicious': hash_info.get('max_malicious', 0),
                            'suspicious': hash_info.get('max_suspicious', 0),
                            'harmless': hash_info.get('max_harmless', 0),
                            'undetected': hash_info.get('max_undetected', 0)
                        }
            except Exception as e:
                console.print(f"[yellow]Database read error (continuing): {e}[/yellow]")

            # Scan with VT
            result = self.scan_hash(sha256)
            console.print(f"🔍 [DEBUG] scan_hash returned: {result}")

            # FIXED: Handle the case where scan_hash returns None (error)
            if result is None:
                console.print("[red]Scan failed - VT returned error[/red]")
                # Even on scan failure, we might want to offer upload
                if allow_upload or Confirm.ask("Scan failed. Upload to VirusTotal for analysis?"):
                    console.print(f"🔍 [DEBUG] UPLOAD TRIGGERED after scan failure!")
                    upload_result = self.upload_file(file_path, sha256)
                    if upload_result:
                        result = upload_result
                else:
                    return None

            # FIXED: Handle 'not_found' status
            elif result.get('status') == 'not_found':
                console.print(f"[yellow]File not in VT database[/yellow]")
                console.print(f"🔍 [DEBUG] allow_upload = {allow_upload}")
                if allow_upload or Confirm.ask("Upload to VirusTotal for analysis?"):
                    console.print(f"🔍 [DEBUG] UPLOAD TRIGGERED! Condition evaluated to TRUE")
                    upload_result = self.upload_file(file_path, sha256)
                    console.print(f"🔍 [DEBUG] upload_file returned: {upload_result}")
                    if upload_result:
                        result = upload_result
                        console.print(f"🔍 [DEBUG] Upload successful, new result: {result}")
                    else:
                        console.print(f"🔍 [DEBUG] Upload failed or returned None")
                else:
                    console.print(f"🔍 [DEBUG] UPLOAD NOT TRIGGERED! Condition evaluated to FALSE")
                    # Explicitly return a 'not_found_skipped' status
                    return {'status': 'not_found_skipped', 'sha256': sha256}

            # Save results to database if we have a successful scan
            if result and result.get('status') == 'scanned':
                # ... rest of your database saving code remains the same ...
                # Extract file name from VT response or fall back to local file name
                vt_file_name = result.get('file_name')
                local_file_name = Path(file_path).name
                file_name = (vt_file_name or local_file_name).lower()

                # Update database with retry logic for locking
                max_retries = DB_MAX_RETRIES
                for attempt in range(max_retries):
                    try:
                        cursor = self.vt_db.conn.cursor()
                        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                        status = 'malicious' if result['malicious'] > 5 else 'clean'

                        cursor.execute('''
                            INSERT INTO file_hashes
                            (sha256, file_name, status, first_seen, last_seen, last_scanned,
                            total_scans, max_malicious, max_suspicious,
                            max_harmless, max_undetected, file_size)
                            VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
                            ON CONFLICT(sha256) DO UPDATE SET
                                file_name = COALESCE(file_name, ?),
                                last_seen = ?,
                                last_scanned = ?,
                                total_scans = total_scans + 1,
                                max_malicious = MAX(max_malicious, ?),
                                max_suspicious = MAX(max_suspicious, ?),
                                max_harmless = MAX(max_harmless, ?),
                                max_undetected = MAX(max_undetected, ?),
                                file_size = ?
                        ''', (
                            sha256, file_name, status, now, now, now,
                            result['malicious'], result['suspicious'],
                            result['harmless'], result['undetected'],
                            Path(file_path).stat().st_size,
                            file_name, now, now,
                            result['malicious'], result['suspicious'],
                            result['harmless'], result['undetected'],
                            Path(file_path).stat().st_size
                        ))

                        # Add file path with extracted filename
                        cursor.execute('''
                            INSERT OR IGNORE INTO file_paths
                            (sha256, file_path, file_name, first_seen)
                            VALUES (?, ?, ?, ?)
                        ''', (sha256, file_path, file_name, now))

                        # Add scan history
                        cursor.execute('''
                            INSERT INTO vt_scan_history
                            (sha256, scan_timestamp, malicious, suspicious,
                            harmless, undetected, detecting_vendors, scan_type)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            sha256, now,
                            result['malicious'], result['suspicious'],
                            result['harmless'], result['undetected'],
                            json.dumps(result['detecting_vendors']),
                            'upload' if allow_upload else 'lookup'
                        ))

                        # Update vendor statistics based on consensus
                        self.vt_db.update_vendor_stats_from_scan(
                            detecting_vendors=result['detecting_vendors'],
                            total_malicious=result['malicious'],
                            scan_timestamp=now
                        )

                        self.vt_db.conn.commit()
                        break  # Success

                    except Exception as e:
                        if "database is locked" in str(e) and attempt < max_retries - 1:
                            console.print(f"[yellow]Database locked, retrying... (attempt {attempt + 1}/{max_retries})[/yellow]")
                            time.sleep(DB_RETRY_DELAY)
                            continue
                        else:
                            console.print(f"[red]Database error: {e}[/red]")
                            break

                return {
                    'sha256': sha256,
                    'file_name': file_name,
                    'cached': False,
                    **result
                }

            return result

        except Exception as e:
            console.print(f"[red]Error scanning file {file_path}: {e}[/red]")
            return None

    def scan_multiple_files(self, file_paths: List[str], allow_upload: bool = False) -> Dict:
        """Scan multiple files with progress tracking and upload support"""
        console.print(f"🔍 [DEBUG] scan_multiple_files called with {len(file_paths)} files, allow_upload={allow_upload}")

        results = {
            'total': len(file_paths),
            'scanned': 0,
            'malicious': 0,
            'clean': 0,
            'not_found': 0,
            'not_found_skipped': 0,
            'uploaded': 0,
            'errors': 0,
            'cached': 0
        }

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("•"),
            TextColumn("[progress.details]{task.fields[details]}"),
            console=console
        ) as progress:

            task = progress.add_task(
                PROGRESS_DESCRIPTION,
                total=len(file_paths),
                details="Starting..."
            )

            for i, file_path in enumerate(file_paths):
                filename = Path(file_path).name
                progress.update(
                    task,
                    description=PROGRESS_DESCRIPTION,
                    details=f"{filename} ({i+1}/{len(file_paths)})"
                )

                console.print(f"🔍 [DEBUG] Scanning file {i+1}/{len(file_paths)}: {filename}")
                console.print(f"🔍 [DEBUG] allow_upload parameter passed to scan_file: {allow_upload}")

                result = self.scan_file(file_path, allow_upload=allow_upload)

                console.print(f"🔍 [DEBUG] scan_file returned: {result}")

                if result:
                    if result.get('cached'):
                        results['cached'] += 1
                        progress.console.print(f"[dim]{filename}: Cached ({result.get('malicious', 0)} detections)[/dim]")
                    elif result.get('status') == 'scanned':
                        results['scanned'] += 1
                        if result.get('malicious', 0) > 5:
                            results['malicious'] += 1
                            progress.console.print(f"[red]{filename}: MALICIOUS ({result.get('malicious', 0)} detections)[/red]")
                        else:
                            results['clean'] += 1
                            progress.console.print(f"[green]{filename}: Clean[/green]")
                    elif result.get('status') == 'not_found':
                        results['not_found'] += 1
                        progress.console.print(f"[yellow]{filename}: Not in VT[/yellow]")
                    elif result.get('status') == 'not_found_skipped':
                        results['not_found_skipped'] += 1
                        progress.console.print(f"[dim]{filename}: Not in VT (skipped upload)[/dim]")
                    elif result.get('status') == 'uploaded':
                        results['uploaded'] += 1
                        progress.console.print(f"[cyan]{filename}: Uploaded[/cyan]")
                else:
                    results['errors'] += 1
                    progress.console.print(f"[yellow]{filename}: Scan failed[/yellow]")

                progress.advance(task)
                time.sleep(VT_SCAN_DELAY)

        # Track this scan run in the database
        self.vt_db.track_vt_run(
            scan_type='multiple_from_list',
            files_processed=results['total'],
            successfully_scanned=results['scanned'],
            new_scans=results['scanned'],  # scanned means fresh API calls
            malicious_count=results['malicious'],
            clean_count=results['clean'],
            cached_count=results['cached'],
            errors_count=results['errors']
        )

        # Update excluded vendors list after scan completes
        try:
            self.vt_db.update_excluded_vendors_list()
        except Exception as e:
            console.print(f"[yellow]Warning: Could not update excluded vendors list: {e}[/yellow]")

        return results

    def scan_hash(self, sha256: str) -> Optional[Dict]:
        if not _SHA256_RE.fullmatch(sha256):
            console.print(f'[red]Invalid SHA-256 hash: {sha256!r}[/red]')
            return None

        # Check if VT CLI is available
        if not self.vt_cli_path:
            console.print("[red]VT CLI not available for scanning[/red]")
            return None

        try:
            self.vt_db.track_api_usage('hash_lookup', True)

            result = subprocess.run(
                [self.vt_cli_path, "file", sha256, "--format", "json"],
                capture_output=True,
                text=True,
                timeout=VT_SCAN_TIMEOUT,
                encoding='utf-8',
                errors='ignore'
            )

            console.print(f"[dim]VT return code: {result.returncode}[/dim]")
            console.print(f"[dim]VT stdout length: {len(result.stdout)} chars[/dim]")

            if result.returncode != 0:
                error_msg = result.stderr.lower() if result.stderr else ""
                if 'not found' in error_msg:
                    console.print(f"🔍 [DEBUG] scan_hash returning 'not_found' status")
                    return {'status': 'not_found', 'sha256': sha256}
                elif 'invalid file hash' in error_msg:
                    console.print(f"[yellow]Invalid hash format: {sha256}[/yellow]")
                    return None
                elif 'quota exceeded' in error_msg:
                    console.print("[red]VirusTotal API quota exceeded[/red]")
                    return None
                elif 'forbidden' in error_msg or 'unauthorized' in error_msg:
                    console.print("[red]VirusTotal API authentication failed[/red]")
                    return None
                else:
                    console.print(f"[yellow]VT CLI error: {result.stderr.strip()}[/yellow]")
                    return None

            # Handle None or empty stdout
            if not result.stdout or not result.stdout.strip():
                console.print(f"[red]Empty response from VT for {sha256}[/red]")
                return {'status': 'not_found', 'sha256': sha256}

            # Parse JSON response
            try:
                data = json.loads(result.stdout)
            except json.JSONDecodeError as e:
                console.print(f"[red]JSON parse error for {sha256}: {e}[/red]")
                # Show the first part to debug
                if result.stdout:
                    console.print(f"[dim]First 200 chars: {result.stdout[:200]}[/dim]")
                return {'status': 'not_found', 'sha256': sha256}

  # Handle list responses (unexpected but we can work with it)
            if isinstance(data, list):
                console.print(f"[yellow]VT returned list with {len(data)} items[/yellow]")
                if not data:
                    console.print("[yellow]Empty list returned[/yellow]")
                    return {'status': 'not_found', 'sha256': sha256}

                # Use the first item that has the data we need
                for item in data:
                    if isinstance(item, dict):
                        data = item
                        console.print("[dim]Using first valid dict item from list[/dim]")
                        break
                else:
                    console.print("[red]No valid dict items in list[/red]")
                    return None

            if not isinstance(data, dict):
                console.print(f"[red]Unexpected data type after processing: {type(data)}[/red]")
                return None

            # Extract analysis stats and file name - try multiple formats
            stats = None
            results = None  # Initialize results here
            detecting_vendors = []
            file_name = None

            # Format 1: New API format with data.attributes
            if 'data' in data and isinstance(data['data'], dict) and 'attributes' in data['data']:
                attributes = data['data']['attributes']
                stats = attributes.get('last_analysis_stats', {})
                results = attributes.get('last_analysis_results', {})
                # Extract file names - VT provides multiple options
                file_name = (attributes.get('meaningful_name') or
                           (attributes.get('names', [None])[0] if attributes.get('names') else None))
                if file_name:
                    file_name = file_name.lower()
            # Format 2: Direct attributes (some responses)
            elif 'attributes' in data and isinstance(data['attributes'], dict):
                attributes = data['attributes']
                stats = attributes.get('last_analysis_stats', {})
                results = attributes.get('last_analysis_results', {})
                file_name = (attributes.get('meaningful_name') or
                           (attributes.get('names', [None])[0] if attributes.get('names') else None))
                if file_name:
                    file_name = file_name.lower()
            # Format 3: Direct stats (older format)
            elif 'last_analysis_stats' in data:
                stats = data['last_analysis_stats']
                results = data.get('last_analysis_results', {})
                file_name = data.get('meaningful_name') or (data.get('names', [None])[0] if data.get('names') else None)
                if file_name:
                    file_name = file_name.lower()
            else:
                console.print("[yellow]Could not find analysis stats in response[/yellow]")
                console.print(f"[dim]Available keys: {list(data.keys())}[/dim]")
                return None

            if not stats:
                console.print("[yellow]No stats found after extraction[/yellow]")
                return None

            # Extract detecting vendors (excluding known false positives)
            # FIXED: Check if results exists and is a dict before iterating
            if results and isinstance(results, dict):
                console.print(f"[dim]Processing {len(results)} vendor results[/dim]")
                for vendor, info in results.items():
                    if isinstance(info, dict) and info.get('category') == 'malicious':
                       # if vendor not in EXCLUDED_VENDORS:
                            detecting_vendors.append(vendor)
                console.print(f"[dim]Found {len(detecting_vendors)} detecting vendors [/dim]")
            else:
                console.print(f"[yellow]No vendor results found or invalid format. Results type: {type(results)}[/yellow]")
            return {
                'status': 'scanned',
                'file_name': file_name,
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'detecting_vendors': detecting_vendors
            }

        except subprocess.TimeoutExpired:
            console.print(f"[yellow]Timeout scanning {sha256}[/yellow]")
            return None
        except Exception as e:
            console.print(f"[red]Error scanning {sha256}: {e}[/red]")
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
            return None

    def test_vt_cli(self):
        """Test if VT CLI works from Python"""
        console.print("[cyan]Testing VT CLI from Python...[/cyan]")

        # Check if VT CLI is available
        if not self.vt_cli_path:
            console.print("[red]VT CLI path not set, cannot run test.[/red]")
            return False

        # Test with a real, known hash (EICAR test file - this should exist in VT)
        test_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"  # EICAR test file

        # Test 1: Direct vt command (using validated path)
        console.print("\n[cyan]Test 1: Direct vt command[/cyan]")
        try:
            result = subprocess.run(
                [self.vt_cli_path, "file", test_hash, "--format", "json"],
                capture_output=True,
                text=True,
                timeout=VT_SCAN_TIMEOUT
            )

            console.print(f"[dim]Return code: {result.returncode}[/dim]")
            console.print(f"[dim]Stdout length: {len(result.stdout)}[/dim]")
            if result.stderr:
                console.print(f"[dim]Stderr: {result.stderr.strip()}[/dim]")

            if result.returncode == 0:
                console.print("[green]✓ Direct vt command works![/green]")
                try:
                    data = json.loads(result.stdout)
                    console.print("[green]✓ JSON response is valid[/green]")

                    # Show some stats from the response
                    if 'data' in data and 'attributes' in data['data']:
                        stats = data['data']['attributes'].get('last_analysis_stats', {})
                        console.print(f"[dim]Malicious: {stats.get('malicious', 0)}[/dim]")
                        console.print(f"[dim]Clean: {stats.get('harmless', 0)}[/dim]")
                    return True
                except json.JSONDecodeError as e:
                    console.print(f"[red]✗ JSON response is invalid: {e}[/red]")
                    # Show what we got
                    if result.stdout:
                        console.print(f"[dim]Response: {result.stdout[:200]}...[/dim]")
            else:
                if 'not found' in (result.stderr or '').lower():
                    console.print("[yellow]✓ VT CLI works - file not found in database[/yellow]")
                    return True
                else:
                    console.print(f"[red]✗ Direct vt command failed[/red]")

        except Exception as e:
            console.print(f"[red]✗ Direct vt command error: {e}[/red]")

        # Test 2: Test vt version command
        console.print("\n[cyan]Test 2: Testing vt version[/cyan]")
        try:
            result = subprocess.run(
                [self.vt_cli_path, "version"],
                capture_output=True,
                text=True,
                timeout=VT_VERSION_TIMEOUT
            )

            console.print(f"[dim]Return code: {result.returncode}[/dim]")
            console.print(f"[dim]Output: {result.stdout.strip()}[/dim]")

            if result.returncode == 0:
                console.print("[green]✓ vt version command works![/green]")
                return True
            else:
                console.print("[red]✗ vt version command failed[/red]")

        except Exception as e:
            console.print(f"[red]✗ vt version command error: {e}[/red]")

        return False

    def test_scan_known_file(self):
        """Test scanning a known file"""
        console.print("[cyan]Testing scan with known file...[/cyan]")

        # Try scanning a system file that should exist
        test_files = [
            "C:\\Windows\\System32\\notepad.exe",
            "C:\\Windows\\System32\\calc.exe",
            "C:\\Windows\\System32\\cmd.exe"
        ]

        for test_file in test_files:
            if Path(test_file).exists():
                console.print(f"\n[cyan]Testing with: {test_file}[/cyan]")
                result = self.scan_file(test_file)
                if result:
                    if result.get('cached'):
                        console.print(f"[yellow]Cached result: {result.get('malicious', 0)} detections[/yellow]")
                    else:
                        console.print(f"[green]Fresh scan: {result.get('malicious', 0)} detections[/green]")
                    return True
                else:
                    console.print(f"[red]Scan failed for {test_file}[/red]")

        console.print("[red]No test files could be scanned[/red]")
        return False

    def update_vt_filenames(self):
        """Extract filenames from file paths and update the database"""
        console.print(Panel("Update VT Filenames", style="cyan"))

        if not self.vt_db.conn:
            console.print("[yellow]Database not connected.[/yellow]")
            return

        cursor = self.vt_db.conn.cursor()

        # First check if file_name column exists in file_paths
        cursor.execute("PRAGMA table_info(file_paths)")
        columns = [row[1] for row in cursor.fetchall()]

        if 'file_name' not in columns:
            console.print("[yellow]Adding file_name column to file_paths table...[/yellow]")
            cursor.execute('ALTER TABLE file_paths ADD COLUMN file_name TEXT')
            self.vt_db.conn.commit()

        # Get all file paths that don't have file_name populated
        cursor.execute('SELECT id, file_path FROM file_paths WHERE file_name IS NULL OR file_name = ""')
        rows = cursor.fetchall()

        if not rows:
            console.print("[green]All file paths already have filenames extracted![/green]")
            return

        console.print(f"[cyan]Processing {len(rows)} file paths...[/cyan]")

        updated = 0
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:

            task = progress.add_task("Extracting filenames...", total=len(rows))

            for row in rows:
                row_id = row[0]
                file_path = row[1]

                if file_path:
                    # Extract filename from path
                    filename = Path(file_path).name.lower()

                    cursor.execute('''
                        UPDATE file_paths
                        SET file_name = ?
                        WHERE id = ?
                    ''', (filename, row_id))

                    updated += 1

                progress.advance(task)

        self.vt_db.conn.commit()
        console.print(f"[green]Updated {updated} records with extracted filenames[/green]")

        # Show some statistics
        cursor.execute('SELECT COUNT(*) FROM file_paths WHERE file_name IS NOT NULL AND file_name != ""')
        with_filenames = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM file_paths')
        total_paths = cursor.fetchone()[0]

        console.print(f"\n[cyan]Filename Extraction Statistics:[/cyan]")
        console.print(f"  Total file paths: {total_paths}")
        console.print(f"  Paths with extracted filenames: {with_filenames}")
        console.print(f"  Remaining without filenames: {total_paths - with_filenames}")

    def malicious_process_report(self):
        """Generate a comprehensive report of malicious processes and their associated files"""
        console.print(Panel("Malicious Process Report", style="red"))

        if not self.vt_db.conn:
            console.print("[yellow]Database not connected.[/yellow]")
            return

        cursor = self.vt_db.conn.cursor()

        # Get comprehensive malicious process data with file paths and latest vendor info
        cursor.execute('''
            SELECT
                ip.process_name AS process_name,
                COUNT(DISTINCT ip.ip_address) AS ip_count,
                fh.sha256,
                fh.status,
                fh.max_malicious,
                fh.total_scans,
                fp.file_path,
                (SELECT detecting_vendors
                 FROM vt_scan_history
                 WHERE vt_scan_history.sha256 = fh.sha256
                 ORDER BY scan_timestamp DESC
                 LIMIT 1) AS latest_vendors
            FROM ip_processes ip
            INNER JOIN file_paths fp ON LOWER(ip.process_name) = LOWER(fp.file_name)
            INNER JOIN file_hashes fh ON fp.sha256 = fh.sha256
            WHERE fh.max_malicious > 0
            GROUP BY ip.process_name, fh.sha256, fp.file_path
            ORDER BY fh.max_malicious DESC, ip_count DESC
        ''')

        results = cursor.fetchall()

        if not results:
            console.print("[green]No malicious processes found with VT data[/green]")
            return

        console.print(f"[red bold]Found {len(results)} malicious process-hash combinations[/red bold]\n")

        # Create comprehensive table
        table = Table(title="Malicious Processes and Associated Files", box=box.ROUNDED, expand=True)
        table.add_column("Process Name", style="red bold", max_width=30)
        table.add_column("IPs", style="yellow", justify="right")
        table.add_column("SHA256", style="white", max_width=20)
        table.add_column("Status", style="white")
        table.add_column("Detections", style="red", justify="right")
        table.add_column("Total Scans", style="white", justify="right")
        table.add_column("File Path", style="dim", max_width=40)
        table.add_column("Top Vendors", style="dim", max_width=30)

        for row in results:
            # Parse vendor JSON and show top 2
            vendors = json.loads(row[7]) if row[7] else []
            top_vendors = ", ".join(vendors[:2]) if vendors else "N/A"

            # Truncate file path if too long
            file_path = row[6]
            if len(file_path) > 40:
                file_path = "..." + file_path[-37:]

            table.add_row(
                row[0],  # process_name
                str(row[1]),  # ip_count
                row[2][:16] + "...",  # sha256 truncated
                row[3],  # status
                str(row[4]),  # max_detections
                str(row[5]),  # total_scans
                file_path,  # file_path
                top_vendors  # top_vendors
            )

        console.print(table)

        # Show summary statistics
        cursor.execute('''
            SELECT COUNT(DISTINCT ip.process_name)
            FROM ip_processes ip
            INNER JOIN file_paths fp ON LOWER(ip.process_name) = LOWER(fp.file_name)
            INNER JOIN file_hashes fh ON fp.sha256 = fh.sha256
            WHERE fh.max_malicious > 0
        ''')
        unique_processes = cursor.fetchone()[0]

        cursor.execute('''
            SELECT COUNT(DISTINCT fh.sha256)
            FROM file_hashes fh
            WHERE fh.max_malicious > 0
        ''')
        unique_malicious_files = cursor.fetchone()[0]

        console.print(f"\n[cyan]Summary Statistics:[/cyan]")
        console.print(f"  Total malicious process-hash combinations: {len(results)}")
        console.print(f"  Unique malicious processes: {unique_processes}")
        console.print(f"  Unique malicious files: {unique_malicious_files}")

        if unique_processes > 0:
            cursor.execute('''
                SELECT DISTINCT ip.process_name
                FROM ip_processes ip
                INNER JOIN file_paths fp ON LOWER(ip.process_name) = LOWER(fp.file_name)
                INNER JOIN file_hashes fh ON fp.sha256 = fh.sha256
                WHERE fh.max_malicious > 0
                ORDER BY ip.process_name
                LIMIT 15
            ''')

            console.print(f"\n[cyan]Processes involved in malicious activity:[/cyan]")
            for row in cursor.fetchall():
                console.print(f"  - {row[0]}")
