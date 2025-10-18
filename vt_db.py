"""
VirusTotal Database Module
Handles all database operations, schema management, and data tracking.
"""

import json
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

from rich.console import Console

from constants import (
    DB_PATH,
    VT_UPLOAD_DAILY_LIMIT,
    VT_VENDOR_CONSENSUS_THRESHOLD,
    VT_VENDOR_MIN_DETECTIONS,
    VT_VENDOR_MAX_FP_RATE
)

console = Console()


class VTDatabase:
    """Extends the existing security database with VT functionality"""

    def __init__(self, db_conn):
        """
        Args:
            db_conn: sqlite3.Connection from the main Database class
        """
        self.conn = db_conn
        self.init_vt_tables()

    def init_vt_tables(self):
        """Create VT-specific tables"""
        cursor = self.conn.cursor()

        # File hashes table with file_name column
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_hashes (
                sha256 TEXT PRIMARY KEY,
                file_name TEXT,
                status TEXT,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                last_scanned TIMESTAMP,
                total_scans INTEGER DEFAULT 0,
                max_malicious INTEGER DEFAULT 0,
                max_suspicious INTEGER DEFAULT 0,
                max_harmless INTEGER DEFAULT 0,
                max_undetected INTEGER DEFAULT 0,
                file_size INTEGER,
                upload_attempted INTEGER DEFAULT 0
            )
        ''')

        # Add file_size column if it doesn't exist (for existing databases)
        try:
            cursor.execute('ALTER TABLE file_hashes ADD COLUMN file_size INTEGER')
            self.conn.commit()
            console.print("[green]Added file_size column to file_hashes table[/green]")
        except:
            pass  # Column already exists

        # Add upload_attempted column if it doesn't exist (for existing databases)
        try:
            cursor.execute('ALTER TABLE file_hashes ADD COLUMN upload_attempted INTEGER DEFAULT 0')
            self.conn.commit()
            console.print("[green]Added upload_attempted column to file_hashes table[/green]")
        except:
            pass  # Column already exists

        # File paths associated with hashes
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_paths (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sha256 TEXT,
                file_path TEXT,
                file_name TEXT,
                first_seen TIMESTAMP,
                UNIQUE(sha256, file_path),
                FOREIGN KEY (sha256) REFERENCES file_hashes(sha256)
            )
        ''')

        # Add file_name column to file_paths if it doesn't exist
        try:
            cursor.execute('ALTER TABLE file_paths ADD COLUMN file_name TEXT')
            self.conn.commit()
        except:
            pass  # Column already exists

        # VT scan history
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vt_scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sha256 TEXT,
                scan_timestamp TIMESTAMP,
                malicious INTEGER,
                suspicious INTEGER,
                harmless INTEGER,
                undetected INTEGER,
                detecting_vendors TEXT,
                scan_type TEXT,
                FOREIGN KEY (sha256) REFERENCES file_hashes(sha256)
            )
        ''')

        # Vendor performance tracking
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vt_vendors (
                vendor_name TEXT PRIMARY KEY,
                total_detections INTEGER DEFAULT 0,
                false_positive_estimate INTEGER DEFAULT 0,
                first_detected TIMESTAMP,
                last_detected TIMESTAMP,
                reliability_score REAL DEFAULT 0.0
            )
        ''')

        # Link processes to file hashes
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS process_hashes (
                process_name TEXT,
                sha256 TEXT,
                first_seen TIMESTAMP,
                PRIMARY KEY (process_name, sha256),
                FOREIGN KEY (sha256) REFERENCES file_hashes(sha256)
            )
        ''')

        # Upload tracking - NEW TABLE FOR UPLOAD FUNCTIONALITY
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vt_uploads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sha256 TEXT,
                upload_timestamp TIMESTAMP,
                upload_success INTEGER,
                error_message TEXT
            )
        ''')

        # API usage tracking - NEW TABLE FOR RATE LIMITING
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vt_api_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action_type TEXT,
                timestamp TIMESTAMP,
                success INTEGER
            )
        ''')

        # VT scan runs tracking - Track each execution with vendor changes
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vt_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP,
                scan_type TEXT,
                files_processed INTEGER DEFAULT 0,
                successfully_scanned INTEGER DEFAULT 0,
                new_scans INTEGER DEFAULT 0,
                malicious_count INTEGER DEFAULT 0,
                clean_count INTEGER DEFAULT 0,
                cached_count INTEGER DEFAULT 0,
                errors_count INTEGER DEFAULT 0,
                excluded_vendors_added TEXT,
                excluded_vendors_removed TEXT
            )
        ''')

        self.conn.commit()

    def get_upload_count_today(self) -> int:
        """Get number of uploads performed today"""
        cursor = self.conn.cursor()
        today = datetime.now().date().isoformat()

        cursor.execute('''
            SELECT COUNT(*) FROM vt_uploads
            WHERE date(upload_timestamp) = ? AND upload_success = 1
        ''', (today,))

        return cursor.fetchone()[0]

    def track_upload(self, sha256: str, success: bool, error_msg: Optional[str] = None):
        """Track an upload attempt"""
        cursor = self.conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute('''
            INSERT INTO vt_uploads (sha256, upload_timestamp, upload_success, error_message)
            VALUES (?, ?, ?, ?)
        ''', (sha256, now, 1 if success else 0, error_msg))

        # Update file_hashes upload_attempted flag only if hash exists
        try:
            cursor.execute('''
                UPDATE file_hashes
                SET upload_attempted = 1
                WHERE sha256 = ?
            ''', (sha256,))
        except Exception as e:
            # Hash might not exist yet, that's okay
            console.print(f"[dim]Could not update upload_attempted flag: {e}[/dim]")

        self.conn.commit()

    def track_api_usage(self, action_type: str, success: bool):
        """Track API usage for rate limiting"""
        cursor = self.conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute('''
            INSERT INTO vt_api_usage (action_type, timestamp, success)
            VALUES (?, ?, ?)
        ''', (action_type, now, 1 if success else 0))

        self.conn.commit()

    def track_vt_run(self, scan_type: str, files_processed: int = 0, successfully_scanned: int = 0,
                     new_scans: int = 0, malicious_count: int = 0, clean_count: int = 0,
                     cached_count: int = 0, errors_count: int = 0,
                     excluded_vendors_added: Optional[List[str]] = None,
                     excluded_vendors_removed: Optional[List[str]] = None):
        """Track a VT scan run execution

        Args:
            scan_type: Type of scan (e.g., 'single_file', 'multiple_from_list', 'file_hash', 'FAC')
            files_processed: Total number of files processed
            successfully_scanned: Number of files successfully scanned (fresh API calls)
            new_scans: Number of new scans performed (non-cached)
            malicious_count: Number of malicious files detected
            clean_count: Number of clean files detected
            cached_count: Number of results retrieved from cache
            errors_count: Number of errors encountered
            excluded_vendors_added: List of vendor names added to exclusion list
            excluded_vendors_removed: List of vendor names removed from exclusion list
        """
        cursor = self.conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")        # Convert lists to comma-separated strings for storage
        added_str = ', '.join(excluded_vendors_added) if excluded_vendors_added else None
        removed_str = ', '.join(excluded_vendors_removed) if excluded_vendors_removed else None

        cursor.execute('''
            INSERT INTO vt_runs
            (timestamp, scan_type, files_processed, successfully_scanned, new_scans,
             malicious_count, clean_count, cached_count, errors_count,
             excluded_vendors_added, excluded_vendors_removed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (now, scan_type, files_processed, successfully_scanned, new_scans,
              malicious_count, clean_count, cached_count, errors_count,
              added_str, removed_str))

        self.conn.commit()

        # Return the ID of the inserted run for reference
        return cursor.lastrowid
    def safe_update_hash(self, sha256: str, data: Dict, max_retries: int = 3) -> bool:
        """
        Safely update hash data with retry logic - FULLY PROTECTED

        Args:
            sha256: The SHA256 hash to update
            data: Dictionary of field-value pairs to update
            max_retries: Maximum number of retry attempts

        Returns:
            True if successful, False otherwise
        """
        # Define allowed fields as a frozen set (immutable for security)
        ALLOWED_FIELDS = frozenset({
            'file_name', 'status', 'first_seen', 'last_seen', 'last_scanned',
            'total_scans', 'max_malicious', 'max_suspicious', 'max_harmless',
            'max_undetected', 'file_size', 'upload_attempted'
        })

        for attempt in range(max_retries):
            try:
                cursor = self.conn.cursor()
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                # Check if hash exists
                cursor.execute('SELECT sha256 FROM file_hashes WHERE sha256 = ?', (sha256,))
                exists = cursor.fetchone() is not None

                if exists:
                    # Validate and filter fields
                    validated_data = {}
                    for key, value in data.items():
                        if key in ALLOWED_FIELDS:
                            validated_data[key] = value
                        else:
                            console.print(f"[yellow]Warning: Ignoring disallowed field '{key}'[/yellow]")

                    if not validated_data:
                        console.print("[yellow]No valid fields to update[/yellow]")
                        return False

                    # Build parameterized query with validated field names
                    set_clauses = [f"{col} = ?" for col in validated_data.keys()]
                    values = list(validated_data.values())

                    query = f"UPDATE file_hashes SET {', '.join(set_clauses)}, last_seen = ? WHERE sha256 = ?"
                    cursor.execute(query, values + [now, sha256])

                else:
                    # INSERT new record with field validation
                    valid_data = {k: v for k, v in data.items() if k in ALLOWED_FIELDS}
                    valid_data['sha256'] = sha256
                    valid_data['first_seen'] = now
                    valid_data['last_seen'] = now

                    columns = ', '.join(valid_data.keys())
                    placeholders = ', '.join(['?'] * len(valid_data))

                    cursor.execute(
                        f"INSERT INTO file_hashes ({columns}) VALUES ({placeholders})",
                        list(valid_data.values())
                    )

                self.conn.commit()
                return True

            except Exception as e:
                if "database is locked" in str(e) and attempt < max_retries - 1:
                    console.print(f"[yellow]DB locked, retry {attempt + 1}/{max_retries}[/yellow]")
                    time.sleep(0.5 * (attempt + 1))
                    continue
                else:
                    console.print(f"[red]DB error: {e}[/red]")
                    return False

        return False
    def import_hash_database(self, json_path: Path) -> int:
        """Import hash_database.json from PowerShell script"""
        if not json_path.exists():
            console.print(f"[red]File not found: {json_path}[/red]")
            return 0

        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            cursor = self.conn.cursor()
            imported = 0

            hashes = data.get('hashes', {})
            console.print(f"[cyan]Found {len(hashes)} hashes to import[/cyan]")

            for sha256, hash_data in hashes.items():
                try:
                    # Insert or update file_hashes
                    # Prepare timestamps with fallbacks
                    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    first_seen = hash_data.get('first_seen') or now
                    last_seen = hash_data.get('last_seen') or now
                    last_scanned = last_seen  # Use last_seen as last_scanned

                    cursor.execute('''
                        INSERT INTO file_hashes
                        (sha256, status, first_seen, last_seen, last_scanned,
                         total_scans, max_malicious)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(sha256) DO UPDATE SET
                            last_seen = COALESCE(excluded.last_seen, file_hashes.last_seen, CURRENT_TIMESTAMP),
                            last_scanned = COALESCE(excluded.last_scanned, file_hashes.last_scanned, CURRENT_TIMESTAMP),
                            total_scans = total_scans + excluded.total_scans,
                            max_malicious = MAX(max_malicious, excluded.max_malicious)
                    ''', (
                        sha256.lower(),
                        hash_data.get('status', 'unknown'),
                        first_seen,
                        last_seen,
                        last_scanned,
                        hash_data.get('total_scans', 1),
                        hash_data.get('max_malicious', 0)
                    ))

                    # Import file paths
                    file_paths = hash_data.get('file_paths', [])
                    for path in file_paths:
                        cursor.execute('''
                            INSERT OR IGNORE INTO file_paths
                            (sha256, file_path, first_seen)
                            VALUES (?, ?, ?)
                        ''', (sha256.lower(), path, hash_data.get('first_seen')))

                    # Import scan history
                    scan_history = hash_data.get('scan_history', [])
                    for scan in scan_history:
                        vendors = scan.get('vendors', [])
                        cursor.execute('''
                            INSERT INTO vt_scan_history
                            (sha256, scan_timestamp, malicious, suspicious,
                             harmless, undetected, detecting_vendors)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            sha256.lower(),
                            scan.get('timestamp'),
                            scan.get('malicious', 0),
                            scan.get('suspicious', 0),
                            scan.get('harmless', 0),
                            scan.get('undetected', 0),
                            json.dumps(vendors)
                        ))

                        # Update vendor statistics based on this scan
                        self.update_vendor_stats_from_scan(
                            detecting_vendors=vendors,
                            total_malicious=scan.get('malicious', 0),
                            scan_timestamp=scan.get('timestamp')
                        )

                    imported += 1

                except Exception as e:
                    console.print(f"[yellow]Error importing {sha256}: {e}[/yellow]")
                    continue

            self.conn.commit()
            return imported

        except Exception as e:
            console.print(f"[red]Import failed: {e}[/red]")
            return 0

    def import_detection_tracking(self, json_path: Path) -> int:
        """Import detection_tracking.json from PowerShell script"""
        if not json_path.exists():
            console.print(f"[red]File not found: {json_path}[/red]")
            return 0

        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            cursor = self.conn.cursor()
            imported = 0

            vendors = data.get('vendors', {})
            console.print(f"[cyan]Found {len(vendors)} vendors to import[/cyan]")

            for vendor_name, vendor_data in vendors.items():
                try:
                    cursor.execute('''
                        INSERT INTO vt_vendors
                        (vendor_name, total_detections, false_positive_estimate,
                         first_detected, last_detected)
                        VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(vendor_name) DO UPDATE SET
                            total_detections = total_detections + excluded.total_detections,
                            false_positive_estimate = false_positive_estimate + excluded.false_positive_estimate,
                            last_detected = excluded.last_detected
                    ''', (
                        vendor_name,
                        vendor_data.get('total_detections', 0),
                        vendor_data.get('false_positive_estimate', 0),
                        vendor_data.get('first_detected'),
                        vendor_data.get('last_detected')
                    ))

                    imported += 1

                except Exception as e:
                    console.print(f"[yellow]Error importing vendor {vendor_name}: {e}[/yellow]")
                    continue

            self.conn.commit()
            return imported

        except Exception as e:
            console.print(f"[red]Import failed: {e}[/red]")
            return 0

    def update_vendor_stats_from_scan(self, detecting_vendors: List[str], total_malicious: int, scan_timestamp: str = None):
        """
        Update vendor statistics based on scan results using consensus logic.

        Logic:
        - If a vendor detects as malicious but fewer than VT_VENDOR_CONSENSUS_THRESHOLD vendors agree:
          increment false_positive_estimate
        - If a vendor detects as malicious and >= VT_VENDOR_CONSENSUS_THRESHOLD vendors agree:
          increment total_detections only (correct detection)
        - This helps identify unreliable vendors that frequently flag clean files

        Args:
            detecting_vendors: List of vendor names that detected the file as malicious
            total_malicious: Total number of vendors that detected as malicious (for consensus threshold)
            scan_timestamp: ISO timestamp of the scan (defaults to now)
        """
        if not detecting_vendors:
            return

        cursor = self.conn.cursor()
        now = scan_timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Use configurable consensus threshold
        is_likely_false_positive = total_malicious < VT_VENDOR_CONSENSUS_THRESHOLD

        for vendor_name in detecting_vendors:
            try:
                if is_likely_false_positive:
                    # Vendor detected but too few others agree - likely false positive
                    cursor.execute('''
                        INSERT INTO vt_vendors
                        (vendor_name, total_detections, false_positive_estimate, reliability_score, first_detected, last_detected)
                        VALUES (?, 1, 1, 0.0, ?, ?)
                        ON CONFLICT(vendor_name) DO UPDATE SET
                            total_detections = total_detections + 1,
                            false_positive_estimate = false_positive_estimate + 1,
                            reliability_score = (total_detections + 1 - false_positive_estimate - 1) * 1.0 / (total_detections + 1),
                            last_detected = excluded.last_detected
                    ''', (vendor_name, now, now))
                else:
                    # Vendor detected with sufficient consensus - valid detection
                    cursor.execute('''
                        INSERT INTO vt_vendors
                        (vendor_name, total_detections, false_positive_estimate, reliability_score, first_detected, last_detected)
                        VALUES (?, 1, 0, 1.0, ?, ?)
                        ON CONFLICT(vendor_name) DO UPDATE SET
                            total_detections = total_detections + 1,
                            reliability_score = (total_detections + 1 - false_positive_estimate) * 1.0 / (total_detections + 1),
                            last_detected = excluded.last_detected
                    ''', (vendor_name, now, now))

            except Exception as e:
                console.print(f"[yellow]Error updating vendor stats for {vendor_name}: {e}[/yellow]")
                continue

        self.conn.commit()

    def get_hash_info(self, sha256: str) -> Optional[Dict]:
        """Get information about a file hash"""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT * FROM file_hashes WHERE sha256 = ?
        ''', (sha256.lower(),))

        row = cursor.fetchone()
        if not row:
            return None

        return dict(row)

    def get_file_paths(self, sha256: str) -> List[str]:
        """Get all file paths associated with a hash"""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT file_path FROM file_paths WHERE sha256 = ?
        ''', (sha256.lower(),))

        return [row[0] for row in cursor.fetchall()]

    def get_scan_history(self, sha256: str) -> List[Dict]:
        """Get scan history for a hash"""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT * FROM vt_scan_history
            WHERE sha256 = ?
            ORDER BY scan_timestamp DESC
        ''', (sha256.lower(),))

        return [dict(row) for row in cursor.fetchall()]

    def link_process_to_hash(self, process_name: str, sha256: str):
        """Link a process name to a file hash"""
        cursor = self.conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute('''
            INSERT OR IGNORE INTO process_hashes
            (process_name, sha256, first_seen)
            VALUES (?, ?, ?)
        ''', (process_name, sha256.lower(), now))

        self.conn.commit()

    def get_hashes_for_process(self, process_name: str) -> List[str]:
        """Get all hashes associated with a process"""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT sha256 FROM process_hashes WHERE process_name = ?
        ''', (process_name,))

        return [row[0] for row in cursor.fetchall()]

    def get_processes_for_hash(self, sha256: str) -> List[str]:
        """Get all processes associated with a hash"""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT process_name FROM process_hashes WHERE sha256 = ?
        ''', (sha256.lower(),))

        return [row[0] for row in cursor.fetchall()]

    def get_malicious_hashes(self) -> List[Dict]:
        """Get all malicious file hashes"""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT * FROM file_hashes
            WHERE status = 'malicious' OR max_malicious > 0
            ORDER BY max_malicious DESC
        ''')

        return [dict(row) for row in cursor.fetchall()]

    def get_vendor_stats(self) -> List[Dict]:
        """Get vendor performance statistics"""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT * FROM vt_vendors
            ORDER BY total_detections DESC
        ''')

        vendors = [dict(row) for row in cursor.fetchall()]

        # reliability_score is now stored in the database
        # No need to calculate it here anymore
        return vendors

    def get_unreliable_vendors(self, min_detections: int = None, max_false_positive_rate: float = None) -> List[str]:
        """
        Get list of unreliable vendor names based on false positive rate.

        Args:
            min_detections: Minimum number of detections before considering vendor
                          (default: VT_VENDOR_MIN_DETECTIONS from constants)
            max_false_positive_rate: Maximum acceptable FP rate
                                    (default: VT_VENDOR_MAX_FP_RATE from constants)

        Returns:
            List of vendor names that exceed the false positive threshold
        """
        # Use constants as defaults
        if min_detections is None:
            min_detections = VT_VENDOR_MIN_DETECTIONS
        if max_false_positive_rate is None:
            max_false_positive_rate = VT_VENDOR_MAX_FP_RATE

        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT vendor_name, total_detections, false_positive_estimate
            FROM vt_vendors
            WHERE total_detections >= ?
        ''', (min_detections,))

        unreliable = []
        for row in cursor.fetchall():
            vendor_name = row[0]
            total = row[1]
            fp_estimate = row[2]

            if total > 0:
                fp_rate = fp_estimate / total
                if fp_rate > max_false_positive_rate:
                    unreliable.append(vendor_name)

        return unreliable

    def update_excluded_vendors_list(self, reliability_threshold: float = 0.70, min_detections: int = None) -> bool:
        """
        Update the EXCLUDED_VENDORS list in constants.py based on vendor reliability scores.

        Vendors with reliability < 70% (and sufficient detections) are added to the exclusion list.
        Vendors with reliability >= 70% are removed from the exclusion list.

        Args:
            reliability_threshold: Minimum reliability score to NOT be excluded (default: 0.70 = 70%)
            min_detections: Minimum detections before considering vendor (default: VT_VENDOR_MIN_DETECTIONS)

        Returns:
            True if constants.py was updated, False otherwise
        """
        if min_detections is None:
            min_detections = VT_VENDOR_MIN_DETECTIONS

        # Get vendors that should be excluded (< 70% reliability with enough detections)
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT vendor_name, reliability_score, total_detections
            FROM vt_vendors
            WHERE total_detections >= ?
            ORDER BY vendor_name
        ''', (min_detections,))

        should_exclude = []
        should_include = []

        for row in cursor.fetchall():
            vendor_name = row[0]
            reliability = row[1]

            if reliability < reliability_threshold:
                should_exclude.append(vendor_name)
            else:
                should_include.append(vendor_name)

        # Read current constants.py and extract existing excluded vendors
        constants_path = Path(__file__).parent / "constants.py"
        try:
            with open(constants_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except Exception as e:
            console.print(f"[red]Error reading constants.py: {e}[/red]")
            return False

        # Parse existing EXCLUDED_VENDORS to detect changes
        existing_excluded = set()
        in_excluded_vendors = False
        for line in lines:
            if line.strip().startswith('EXCLUDED_VENDORS = ['):
                in_excluded_vendors = True
                continue
            elif in_excluded_vendors:
                if ']' in line:
                    break
                # Extract vendor name from line like '    "VendorName",'
                stripped = line.strip().strip(',').strip('"').strip("'")
                if stripped:
                    existing_excluded.add(stripped)

        # Calculate changes
        new_excluded_set = set(should_exclude)
        added_vendors = sorted(new_excluded_set - existing_excluded)
        removed_vendors = sorted(existing_excluded - new_excluded_set)

        # Track vendor exclusion changes in vt_runs table
        if added_vendors or removed_vendors:
            self.track_vt_run(
                scan_type='vendor_exclusion_update',
                excluded_vendors_added=added_vendors if added_vendors else None,
                excluded_vendors_removed=removed_vendors if removed_vendors else None
            )

        # Find and update EXCLUDED_VENDORS list
        new_lines = []
        in_excluded_vendors = False
        updated = False

        skip_next_comments = False
        for i, line in enumerate(lines):
            # Skip any comment lines right before EXCLUDED_VENDORS
            if line.strip().startswith('#') and i + 1 < len(lines) and lines[i + 1].strip().startswith('EXCLUDED_VENDORS = ['):
                skip_next_comments = True
                continue

            if line.strip().startswith('EXCLUDED_VENDORS = ['):
                # Start of EXCLUDED_VENDORS list
                in_excluded_vendors = True
                updated = True
                skip_next_comments = False

                # Write new list without comment (tracking is in vt_runs table)
                new_lines.append('EXCLUDED_VENDORS = [\n')

                if should_exclude:
                    # Format as multiple lines with proper indentation
                    for j, vendor in enumerate(sorted(should_exclude)):
                        if j < len(should_exclude) - 1:
                            new_lines.append(f'    "{vendor}",\n')
                        else:
                            new_lines.append(f'    "{vendor}"\n')

                new_lines.append(']\n')

                # Skip lines until we find the closing bracket
                continue
            elif in_excluded_vendors:
                if ']' in line:
                    in_excluded_vendors = False
                continue
            elif skip_next_comments and line.strip().startswith('#'):
                # Skip old comment lines
                continue
            else:
                skip_next_comments = False
                new_lines.append(line)

        # Write updated constants.py
        if updated:
            try:
                with open(constants_path, 'w', encoding='utf-8') as f:
                    f.writelines(new_lines)

                excluded_count = len(should_exclude)
                console.print(f"[green]OK: Updated EXCLUDED_VENDORS list: {excluded_count} vendors excluded[/green]")
                if excluded_count > 0:
                    console.print(f"[dim]Excluded: {', '.join(sorted(should_exclude))}[/dim]")

                # Re-evaluate file hash statuses for files affected by excluded vendor changes
                self._reevaluate_affected_file_statuses(should_exclude)

                return True
            except Exception as e:
                console.print(f"[red]Error writing constants.py: {e}[/red]")
                return False

        return False

    def _reevaluate_affected_file_statuses(self, excluded_vendors: List[str]):
        """
        Re-evaluate file hash statuses for files that have detections from excluded vendors.
        Only processes files where at least one excluded vendor appears in detecting_vendors.

        Args:
            excluded_vendors: List of vendor names to exclude from malicious counts
        """
        if not excluded_vendors:
            return

        cursor = self.conn.cursor()

        # Find all files that have at least one excluded vendor in their detecting_vendors
        # We need to check the JSON array in vt_scan_history
        cursor.execute('''
            SELECT DISTINCT sha256, detecting_vendors, malicious
            FROM vt_scan_history
            WHERE detecting_vendors IS NOT NULL
              AND detecting_vendors != '[]'
        ''')

        affected_files = []
        excluded_set = set(excluded_vendors)

        for row in cursor.fetchall():
            sha256 = row[0]
            detecting_vendors_json = row[1]
            original_malicious_count = row[2]

            try:
                detecting_vendors = json.loads(detecting_vendors_json)
                # Check if any excluded vendor is in this file's detections
                if any(vendor in excluded_set for vendor in detecting_vendors):
                    # Count valid detections (excluding unreliable vendors)
                    valid_detections = sum(1 for v in detecting_vendors if v not in excluded_set)
                    affected_files.append((sha256, valid_detections, original_malicious_count))
            except json.JSONDecodeError:
                continue

        if not affected_files:
            console.print(f"[dim]No file statuses needed re-evaluation[/dim]")
            return

        # Update file_hashes status based on valid detection counts
        updated_count = 0
        for sha256, valid_detections, original_count in affected_files:
            # Determine new status based on valid detections (excluding unreliable vendors)
            if valid_detections > 5:
                new_status = 'malicious'
            elif valid_detections > 0:
                new_status = 'suspicious'
            else:
                new_status = 'clean'

            cursor.execute('''
                UPDATE file_hashes
                SET status = ?,
                    max_malicious = ?
                WHERE sha256 = ?
            ''', (new_status, valid_detections, sha256))
            updated_count += 1

        self.conn.commit()
        console.print(f"[green]OK: Re-evaluated {updated_count} file(s) affected by vendor exclusion changes[/green]")

    def get_recent_vt_runs(self, limit: int = 10) -> List[Dict]:
        """Get recent VT scan runs

        Args:
            limit: Maximum number of runs to return (default: 10)

        Returns:
            List of dictionaries containing run information
        """
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT * FROM vt_runs
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))

        return [dict(row) for row in cursor.fetchall()]

    def get_stats(self) -> Dict:
        """Get database statistics"""
        cursor = self.conn.cursor()

        cursor.execute('SELECT COUNT(*) FROM file_hashes')
        total_hashes = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM file_hashes WHERE status = "malicious"')
        malicious = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM vt_scan_history')
        total_scans = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM vt_vendors')
        total_vendors = cursor.fetchone()[0]

        # Upload statistics
        cursor.execute('SELECT COUNT(*) FROM vt_uploads')
        total_uploads = cursor.fetchone()[0]

        uploads_today = self.get_upload_count_today()

        # VT runs statistics
        cursor.execute('SELECT COUNT(*) FROM vt_runs')
        total_runs = cursor.fetchone()[0]

        return {
            'total_hashes': total_hashes,
            'malicious_hashes': malicious,
            'total_scans': total_scans,
            'total_vendors': total_vendors,
            'total_uploads': total_uploads,
            'uploads_today': uploads_today,
            'uploads_remaining': VT_UPLOAD_DAILY_LIMIT - uploads_today,
            'total_runs': total_runs
        }
