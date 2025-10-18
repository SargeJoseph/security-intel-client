#!/usr/bin/env python3
"""
Security Database API for PowerShell integration
"""

import sqlite3
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

# Import _get_env from config to use .env file ONLY
try:
    from config import _get_env
except ImportError:
    # Fallback if config not available
    def _get_env(key: str, default: str = None) -> str:
        return default or ''

DB_PATH = Path(_get_env('OUTPUT') or '.') / "security_intel.db"

class SecurityDBAPI:
    """Simple API for PowerShell to write security events directly to database"""

    def __init__(self, db_path: Path = DB_PATH, verbose: bool = False):
        self.db_path = db_path
        self.verbose = verbose
        self._ensure_tables()

    def _log(self, message: str):
        """Conditional logging"""
        if self.verbose:
            print(message)

    def _ensure_tables(self):
        """Ensure required tables exist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Main security events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                application_path TEXT PRIMARY KEY,
                total_connections INTEGER DEFAULT 0,
                allowed_connections INTEGER DEFAULT 0,
                denied_connections INTEGER DEFAULT 0,
                unique_ips TEXT,
                unique_ports TEXT,
                unique_ips_count INTEGER DEFAULT 0,
                unique_ports_count INTEGER DEFAULT 0,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP
            )
        ''')

        # Track processed archives to prevent re-processing
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS processed_archives (
                archive_name TEXT PRIMARY KEY,
                processed_date TIMESTAMP,
                event_count INTEGER
            )
        ''')

        # Link processes to IPs (created here for standalone API usage)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_processes (
                ip_address TEXT,
                process_name TEXT,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                PRIMARY KEY (ip_address, process_name)
            )
        ''')

        conn.commit()
        conn.close()

    def update_security_events_from_json(self, json_file_path: Path) -> bool:
        """Update security events from a JSON file"""
        try:
            self._log(f"Reading JSON file: {json_file_path}")

            # Check if file exists and has content
            if not json_file_path.exists():
                print(f"Error: JSON file does not exist: {json_file_path}")
                return False

            file_size = json_file_path.stat().st_size
            self._log(f"File size: {file_size} bytes")

            if file_size == 0:
                print("Error: JSON file is empty")
                return False

            with open(json_file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                self._log(f"File content length: {len(content)} characters")

                if not content.strip():
                    print("Error: JSON file contains only whitespace")
                    return False

                events_data = json.loads(content)

            self._log(f"Successfully loaded JSON. Type: {type(events_data)}")

            # Validate events data structure
            if isinstance(events_data, list):
                self._log(f"Processing {len(events_data)} events from list")
            elif isinstance(events_data, dict):
                self._log(f"Processing single event from dict. Keys: {list(events_data.keys())}")
                events_data = [events_data]  # Convert to list for consistent processing
            else:
                print(f"Error: Unexpected data type: {type(events_data)}")
                return False

            return self.batch_update_security_events(events_data)

        except json.JSONDecodeError as e:
            print(f"JSON decode error: {e}")
            return False
        except Exception as e:
            print(f"Error reading JSON file: {e}")
            return False

    def batch_update_security_events(self, events_data: List[Dict]) -> bool:
        """Update multiple security events in batch"""
        try:
            self._log(f"Starting batch update with {len(events_data)} events")

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            for i, event_data in enumerate(events_data):
                self._log(f"Processing event {i}: {event_data.get('application_path', 'unknown')}")

                # Validate event_data structure
                if not isinstance(event_data, dict):
                    print(f"Error: Event {i} is not a dictionary")
                    continue

                if 'application_path' not in event_data:
                    print(f"Error: Event {i} missing 'application_path'")
                    continue

                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                app_path = event_data['application_path']

                # Check if exists
                cursor.execute('SELECT * FROM security_events WHERE application_path = ?', (app_path,))
                existing = cursor.fetchone()

                if existing:
                    # Update existing record - MERGE data
                    existing_dict = dict(zip([col[0] for col in cursor.description], existing))

                    # Add to existing counts
                    total = existing_dict['total_connections'] + event_data.get('total_connections', 0)
                    allowed = existing_dict['allowed_connections'] + event_data.get('allowed_connections', 0)
                    denied = existing_dict['denied_connections'] + event_data.get('denied_connections', 0)

                    # Merge IPs and Ports (union of sets)
                    existing_ips = set(existing_dict['unique_ips'].split('; ')) if existing_dict['unique_ips'] else set()
                    new_ips = set(event_data.get('unique_ips', '').split('; ')) if event_data.get('unique_ips') else set()
                    merged_ips = existing_ips.union(new_ips)
                    # Remove empty strings
                    merged_ips.discard('')

                    existing_ports = set(existing_dict['unique_ports'].split('; ')) if existing_dict['unique_ports'] else set()
                    new_ports = set(event_data.get('unique_ports', '').split('; ')) if event_data.get('unique_ports') else set()
                    merged_ports = existing_ports.union(new_ports)
                    merged_ports.discard('')

                    cursor.execute('''
                        UPDATE security_events
                        SET total_connections = ?, allowed_connections = ?, denied_connections = ?,
                            unique_ips = ?, unique_ports = ?, unique_ips_count = ?, unique_ports_count = ?,
                            last_seen = ?
                        WHERE application_path = ?
                    ''', (
                        total, allowed, denied,
                        '; '.join(sorted(merged_ips)), '; '.join(sorted(merged_ports)),
                        len(merged_ips), len(merged_ports),
                        now, app_path
                    ))
                else:
                    # Insert new record
                    cursor.execute('''
                        INSERT INTO security_events
                        (application_path, total_connections, allowed_connections, denied_connections,
                         unique_ips, unique_ports, unique_ips_count, unique_ports_count, first_seen, last_seen)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        app_path,
                        event_data.get('total_connections', 0),
                        event_data.get('allowed_connections', 0),
                        event_data.get('denied_connections', 0),
                        event_data.get('unique_ips', ''),
                        event_data.get('unique_ports', ''),
                        event_data.get('unique_ips_count', 0),
                        event_data.get('unique_ports_count', 0),
                        now, now
                    ))

                self._log(f"Successfully processed: {app_path}")

            conn.commit()
            conn.close()
            print(f"SUCCESS: Batch update completed - {len(events_data)} events processed")
            return True

        except Exception as e:
            print(f"Batch database error: {e}")
            import traceback
            print(f"Traceback: {traceback.format_exc()}")
            return False

    def link_processes_to_ips(self) -> bool:
        """Link processes to IPs from firewall_events table"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Get distinct process-IP combinations from firewall_events
            # Use MIN(event_time) as first_seen and MAX(event_time) as last_seen
            cursor.execute('''
                SELECT
                    COALESCE(source_ip, dest_ip) as ip_address,
                    process_name,
                    MIN(event_time) as first_seen,
                    MAX(event_time) as last_seen
                FROM firewall_events
                WHERE process_name IS NOT NULL
                    AND process_name != 'UNKNOWN'
                    AND (source_ip IS NOT NULL OR dest_ip IS NOT NULL)
                GROUP BY ip_address, process_name
            ''')

            firewall_links = cursor.fetchall()
            print(f"Found {len(firewall_links)} process-IP associations in firewall_events")

            linked_count = 0
            updated_count = 0
            skipped_count = 0

            for ip, process_name, first_seen, last_seen in firewall_links:
                if not ip or not process_name:
                    skipped_count += 1
                    continue

                # Check if this combination already exists
                cursor.execute('''
                    SELECT first_seen, last_seen
                    FROM ip_processes
                    WHERE ip_address = ? AND process_name = ?
                ''', (ip, process_name))

                existing = cursor.fetchone()

                if existing:
                    # Update with earlier first_seen and later last_seen
                    existing_first = existing[0]
                    existing_last = existing[1]

                    new_first = min(first_seen, existing_first) if existing_first else first_seen
                    new_last = max(last_seen, existing_last) if existing_last else last_seen

                    cursor.execute('''
                        UPDATE ip_processes
                        SET first_seen = ?, last_seen = ?
                        WHERE ip_address = ? AND process_name = ?
                    ''', (new_first, new_last, ip, process_name))
                    updated_count += 1
                else:
                    # Insert new record
                    try:
                        cursor.execute('''
                            INSERT INTO ip_processes (ip_address, process_name, first_seen, last_seen)
                            VALUES (?, ?, ?, ?)
                        ''', (ip, process_name, first_seen, last_seen))
                        linked_count += 1
                    except sqlite3.IntegrityError:
                        # Race condition or duplicate - skip
                        skipped_count += 1
                        continue

            conn.commit()
            conn.close()

            total_processed = linked_count + updated_count
            print(f"SUCCESS: Processed {total_processed} process-IP associations")
            print(f"  - New links: {linked_count}")
            print(f"  - Updated links: {updated_count}")
            print(f"  - Skipped: {skipped_count}")
            return True

        except Exception as e:
            print(f"Process linking error: {e}")
            import traceback
            print(f"Traceback: {traceback.format_exc()}")
            return False

    def track_processed_archive(self, archive_name: str, event_count: int) -> bool:
        """Track that an archive has been processed"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            cursor.execute('''
                INSERT OR REPLACE INTO processed_archives
                (archive_name, processed_date, event_count)
                VALUES (?, ?, ?)
            ''', (archive_name, now, event_count))

            conn.commit()
            conn.close()
            return True

        except Exception as e:
            print(f"Archive tracking error: {e}")
            return False

    def is_archive_processed(self, archive_name: str) -> bool:
        """Check if an archive has already been processed"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT COUNT(*) FROM processed_archives
                WHERE archive_name = ?
            ''', (archive_name,))

            count = cursor.fetchone()[0]
            conn.close()

            return count > 0

        except Exception as e:
            print(f"Archive check error: {e}")
            return False

    def _extract_process_name(self, app_path: str) -> str:
        """Extract process name from application path"""
        if not app_path:
            return ""

        # Handle Windows paths
        if '\\' in app_path:
            return app_path.split('\\')[-1]
        # Handle Unix paths
        elif '/' in app_path:
            return app_path.split('/')[-1]
        else:
            return app_path


def main():
    """Command line interface for the API"""
    if len(sys.argv) != 2:
        print("Usage: python security_db_api.py <json_file_path>")
        sys.exit(1)

    json_file = Path(sys.argv[1])
    api = SecurityDBAPI()

    if api.update_security_events_from_json(json_file):
        print("SUCCESS: Data imported successfully")
        sys.exit(0)
    else:
        print("FAILED: Error importing data")
        sys.exit(1)


if __name__ == "__main__":
    main()
