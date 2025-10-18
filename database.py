"""
Database handler for Security Intelligence CLI Tool
Manages SQLite database connections, caching, and queries
"""

import sqlite3
import time
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Optional

from rich.console import Console

console = Console()


class Database:
    """SQLite database handler for caching intelligence data with better connection management"""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None
        self._connection_count = 0
        self.init_db()

    def init_db(self):
        """Initialize database with required tables and better settings"""
        max_retries = 3

        for attempt in range(max_retries):
            try:
                # Wait for database to be available before initializing
                if not self.wait_for_database_availability():
                    raise sqlite3.OperationalError("Database is locked and cannot be initialized")

                # Close existing connection if it exists
                if self.conn:
                    try:
                        self.conn.close()
                    except:
                        pass

                console.print(f"[dim]Attempting database connection (attempt {attempt + 1}/{max_retries})...[/dim]")

                self.conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
                self.conn.row_factory = sqlite3.Row

                # Use DELETE mode permanently to avoid WAL conflicts with external tools
                self.conn.execute('PRAGMA journal_mode=DELETE')
                self.conn.execute('PRAGMA busy_timeout=30000')
                self.conn.execute('PRAGMA foreign_keys=ON')
                self.conn.execute('PRAGMA synchronous=NORMAL')
                self.conn.execute('PRAGMA cache_size=-64000')

                cursor = self.conn.cursor()

                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS wfp_translations (
                        code_type TEXT NOT NULL,
                        code_value TEXT NOT NULL,
                        description TEXT NOT NULL,
                        PRIMARY KEY (code_type, code_value)
                    )
                ''')

                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS ip_intelligence (
                        ip_address TEXT PRIMARY KEY,
                        urlhaus_status TEXT,
                        urlhaus_details TEXT,
                        urlhaus_checked TIMESTAMP,
                        abuseipdb_confidence_score INTEGER,
                        abuseipdb_categories TEXT,
                        abuseipdb_total_reports INTEGER,
                        abuseipdb_checked TIMESTAMP,
                        ipqs_fraud_score INTEGER,
                        ipqs_checked TIMESTAMP,
                        greynoise_noise BOOLEAN,
                        greynoise_riot BOOLEAN,
                        greynoise_classification TEXT,
                        greynoise_last_seen TEXT,
                        greynoise_checked TIMESTAMP,
                        country TEXT,
                        city TEXT,
                        isp TEXT,
                        geoip_checked TIMESTAMP,
                        reverse_dns TEXT,
                        dns_checked TIMESTAMP,
                        first_seen TIMESTAMP,
                        last_seen TIMESTAMP
                    )
                ''')

                # Add GreyNoise columns if they don't exist (for existing databases)
                self._add_column_if_not_exists(cursor, 'ip_intelligence', 'greynoise_noise', 'BOOLEAN')
                self._add_column_if_not_exists(cursor, 'ip_intelligence', 'greynoise_riot', 'BOOLEAN')
                self._add_column_if_not_exists(cursor, 'ip_intelligence', 'greynoise_classification', 'TEXT')
                self._add_column_if_not_exists(cursor, 'ip_intelligence', 'greynoise_last_seen', 'TEXT')
                self._add_column_if_not_exists(cursor, 'ip_intelligence', 'greynoise_checked', 'TIMESTAMP')

                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS processed_files (
                        filename TEXT PRIMARY KEY,
                        processed_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                        event_count INTEGER,
                        status TEXT DEFAULT 'COMPLETED',
                        error_message TEXT,
                        processing_time_seconds REAL
                    )
                ''')

                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS api_usage (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        api_name TEXT,
                        request_time TIMESTAMP,
                        success INTEGER
                    )
                ''')

                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS ip_processes (
                        ip_address TEXT,
                        process_name TEXT,
                        first_seen TIMESTAMP,
                        last_seen TIMESTAMP,
                        PRIMARY KEY (ip_address, process_name),
                        FOREIGN KEY (ip_address) REFERENCES ip_intelligence(ip_address)
                    )
                ''')

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

                if self.conn is not None:
                    self.conn.commit()
                console.print("[green]Database initialized successfully[/green]")
                return  # Success - exit the retry loop

            except sqlite3.OperationalError as e:
                if "database is locked" in str(e) and attempt < max_retries - 1:
                    console.print(f"[yellow]Database locked during init, retrying... (attempt {attempt + 1}/{max_retries})[/yellow]")
                    time.sleep(2)  # Longer delay
                    continue
                else:
                    console.print("[red]Failed to initialize database after multiple attempts[/red]")
                    console.print("[yellow]Please ensure all external database browsers are closed[/yellow]")
                    raise e

    def _add_column_if_not_exists(self, cursor, table_name, column_name, column_type):
        """Helper to add a column to a table if it doesn't already exist"""
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = [col[1] for col in cursor.fetchall()]
        if column_name not in columns:
            console.print(f"[dim]Adding column {column_name} to {table_name}...[/dim]")
            cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")
            # Commit only if a valid connection exists to avoid calling commit on None
            if self.conn is not None:
                self.conn.commit()

    def _emergency_init(self):
        """Emergency initialization when database is locked"""
        console.print("[yellow]Attempting emergency database initialization...[/yellow]")

        try:
            # Just try to connect with longer timeout, don't mess with files
            self.conn = sqlite3.connect(self.db_path, timeout=60.0, check_same_thread=False)
            self.conn.execute('PRAGMA journal_mode=DELETE')  # Avoid WAL complications
            self.conn.execute('PRAGMA busy_timeout=60000')
            self.conn.execute('PRAGMA synchronous=NORMAL')
            console.print("[green]Emergency initialization successful[/green]")
        except Exception as e:
            console.print(f"[red]Emergency init failed: {e}[/red]")
            console.print("[yellow]Please close all external database browsers and try again[/yellow]")
            raise e

    def execute_with_retry(self, query, params=(), max_retries=3):
        """Execute SQL with retry logic for database locks"""
        if not self.conn:
            raise sqlite3.OperationalError("Database connection is not available")

        for attempt in range(max_retries):
            try:
                cursor = self.conn.cursor()
                cursor.execute(query, params)
                self.conn.commit()
                return cursor
            except sqlite3.OperationalError as e:
                if "database is locked" in str(e) and attempt < max_retries - 1:
                    console.print(f"[yellow]Database locked, retrying... (attempt {attempt + 1}/{max_retries})[/yellow]")
                    time.sleep(0.5 * (attempt + 1))
                    continue
                else:
                    raise e

    def update_ip_intelligence(self, ip: str, data: Dict):
        """Update or insert IP intelligence with retry"""
        if not self.conn:
            return

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        existing = self.get_ip_intelligence(ip)

        if existing:
            updates = []
            params = []
            for key, value in data.items():
                updates.append(f"{key} = ?")
                params.append(value)

            params.append(now)
            params.append(ip)

            self.execute_with_retry(
                f"UPDATE ip_intelligence SET {', '.join(updates)}, last_seen = ? WHERE ip_address = ?",
                params
            )
        else:
            data['ip_address'] = ip
            data['first_seen'] = now
            data['last_seen'] = now

            columns = ', '.join(data.keys())
            placeholders = ', '.join(['?'] * len(data))

            self.execute_with_retry(
                f"INSERT INTO ip_intelligence ({columns}) VALUES ({placeholders})",
                list(data.values())
            )

    def get_ip_intelligence(self, ip: str) -> Optional[Dict]:
        """Get cached intelligence for an IP"""
        if not self.conn:
            return None
        try:
            cursor = self.conn.cursor()
            cursor.execute('SELECT * FROM ip_intelligence WHERE ip_address = ?', (ip,))
            row = cursor.fetchone()
            return dict(row) if row else None
        except AttributeError:
            return None

    def get_stale_ips(self, check_type: str, days: int) -> List[str]:
        """Get IPs that need checking based on cache age"""
        if not self.conn:
            return []
        cursor = self.conn.cursor()
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()

        cursor.execute(f'''
            SELECT ip_address FROM ip_intelligence
            WHERE {check_type}_checked IS NULL
            OR {check_type}_checked < ?
        ''', (cutoff,))

        return [row[0] for row in cursor.fetchall()]

    def log_api_usage(self, api_name: str, success: bool):
        """Log API usage for rate limit tracking"""
        if not self.conn:
            return
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO api_usage (api_name, request_time, success)
            VALUES (?, ?, ?)
        ''', (api_name, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 1 if success else 0))
        self.conn.commit()

    def get_api_usage_today(self, api_name: str) -> int:
        """Get API usage count for today"""
        if not self.conn:
            return 0
        cursor = self.conn.cursor()
        today = datetime.now().date().isoformat()
        cursor.execute('''
            SELECT COUNT(*) FROM api_usage
            WHERE api_name = ? AND date(request_time) = ?
        ''', (api_name, today))
        return cursor.fetchone()[0]

    def get_stats(self) -> Dict:
        """Get database statistics"""
        if not self.conn:
            return { 'malicious_ips': 0, 'total_events': 0}
        cursor = self.conn.cursor()

        cursor.execute('SELECT COUNT(*) FROM ip_intelligence WHERE urlhaus_status = "malicious"')
        malicious = cursor.fetchone()[0]

        return {
            'malicious_ips': malicious,
            'total_events': 0
        }

    def wait_for_database_availability(self):
        """Wait indefinitely until database becomes available for actual use"""
        import sqlite3
        console.print("[dim]Checking database availability...[/dim]")

        last_error = None

        while True:
            try:
                # Test with the EXACT same parameters and operations as init_db
                test_conn = sqlite3.connect(
                    self.db_path,
                    timeout=30.0,
                    check_same_thread=False
                )
                test_conn.row_factory = sqlite3.Row

                # Set the EXACT same PRAGMAs as init_db
                test_conn.execute('PRAGMA journal_mode=DELETE')
                test_conn.execute('PRAGMA busy_timeout=30000')
                test_conn.execute('PRAGMA foreign_keys=ON')
                test_conn.execute('PRAGMA synchronous=NORMAL')
                test_conn.execute('PRAGMA cache_size=-64000')

                # Test actual table operations that we'll do in init_db
                cursor = test_conn.cursor()
                cursor.execute('SELECT name FROM sqlite_master WHERE type="table" LIMIT 1')

                # Test a write operation (this is what often fails with locks)
                cursor.execute('CREATE TABLE IF NOT EXISTS availability_test (id INTEGER)')
                cursor.execute('DROP TABLE IF EXISTS availability_test')

                test_conn.commit()
                test_conn.close()

                console.print("[green]✓ Database is available for read/write operations[/green]")
                return True

            except sqlite3.OperationalError as e:
                current_error = str(e)

                # Only show the message again if the error changed
                if current_error != last_error:
                    if "locked" in current_error.lower():
                        console.print("\n[red]❌ DATABASE IS LOCKED BY EXTERNAL APPLICATIONS[/red]")
                        console.print("[yellow]Please CLOSE THESE APPLICATIONS COMPLETELY:[/yellow]")
                        console.print("  • DB Browser for SQLite")
                        console.print("  • Valentina Studio")
                        console.print("  • DBeaver")
                        console.print("  • Any other SQLite database browser")
                        console.print(f"\n[dim]Database file: {self.db_path}[/dim]")
                        console.print("\n[yellow]Close all database browsers, then press Enter to check again...[/yellow]")
                    elif "unable to open" in current_error.lower():
                        console.print("\n[red]❌ Cannot open database file[/red]")
                        console.print("[yellow]The database file might be in use or permissions issue[/yellow]")
                        console.print(f"[dim]File: {self.db_path}[/dim]")
                        console.print("[yellow]Press Enter to retry...[/yellow]")
                    else:
                        console.print(f"\n[red]Database error: {e}[/red]")
                        return False

                    last_error = current_error

                # Wait for user to press Enter
                input()

                # Give the OS time to release file locks
                console.print("[dim]Checking if database is available now...[/dim]")
                time.sleep(1)

    def init_wfp_translations(self):
        """Initialize Windows Filtering Platform translation table"""
        if not self.conn:
            return

        cursor = self.conn.cursor()

        # Clear existing translations
        cursor.execute('DELETE FROM wfp_translations')

        # Direction codes
        direction_codes = [
            ('direction', '%%14592', 'Inbound'),
            ('direction', '%%14593', 'Outbound'),
            ('direction', '%%14594', 'Listen'),
            ('direction', '%%14595', 'Accept')
        ]

        # Layer codes
        layer_codes = [
            ('layer', '%%14608', 'Transport'),
            ('layer', '%%14609', 'Network'),
            ('layer', '%%14610', 'Datagram'),
            ('layer', '%%14611', 'Stream'),
            ('layer', '%%14612', 'Resource'),
            ('layer', '%%14613', 'Callout')
        ]

        # Protocol codes
        protocol_codes = [
            ('protocol', '0', 'HOPOPT'),
            ('protocol', '1', 'ICMP'),
            ('protocol', '2', 'IGMP'),
            ('protocol', '4', 'IP-in-IP'),
            ('protocol', '6', 'TCP'),
            ('protocol', '8', 'EGP'),
            ('protocol', '9', 'IGP'),
            ('protocol', '17', 'UDP'),
            ('protocol', '27', 'RDP'),
            ('protocol', '41', 'IPv6'),
            ('protocol', '43', 'IPv6-Route'),
            ('protocol', '44', 'IPv6-Frag'),
            ('protocol', '45', 'IDRP'),
            ('protocol', '46', 'RSVP'),
            ('protocol', '47', 'GRE'),
            ('protocol', '50', 'ESP'),
            ('protocol', '51', 'AH'),
            ('protocol', '58', 'ICMPv6'),
            ('protocol', '88', 'EIGRP'),
            ('protocol', '89', 'OSPF'),
            ('protocol', '94', 'IPIP'),
            ('protocol', '97', 'ETHERIP'),
            ('protocol', '98', 'ENCAP'),
            ('protocol', '103', 'PIM'),
            ('protocol', '108', 'IPComp'),
            ('protocol', '112', 'VRRP'),
            ('protocol', '115', 'L2TP'),
            ('protocol', '132', 'SCTP'),
            ('protocol', '137', 'MPLS-in-IP'),
            ('protocol', '255', 'Raw IP')
        ]

        # Filter Reason codes
        filter_reason_codes = [
            ('filter_reason', '0', 'No matching filter'),
            ('filter_reason', '1', 'Generic'),
            ('filter_reason', '2', 'Flow deleted'),
            ('filter_reason', '3', 'Reauthorized'),
            ('filter_reason', '4', 'Policy change'),
            ('filter_reason', '5', 'New flow'),
            ('filter_reason', '6', 'Normal termination'),
            ('filter_reason', '7', 'Abnormal termination'),
            ('filter_reason', '8', 'Expired flow'),
            ('filter_reason', '9', 'User mode request'),
            ('filter_reason', '268435456', 'Permitted by rule'),
            ('filter_reason', '268435457', 'Blocked by rule'),
            ('filter_reason', '268435458', 'Permitted by WFP'),
            ('filter_reason', '268435459', 'Blocked by WFP'),
            ('filter_reason', '268435460', 'Permitted by application'),
            ('filter_reason', '268435461', 'Blocked by application')
        ]

        # Insert all translations
        all_codes = direction_codes + layer_codes + protocol_codes + filter_reason_codes
        cursor.executemany('''
            INSERT OR REPLACE INTO wfp_translations (code_type, code_value, description)
            VALUES (?, ?, ?)
        ''', all_codes)

        self.conn.commit()
        console.print(f"[green]Initialized {len(all_codes)} WFP translations[/green]")

    def get_wfp_translation(self, code_type: str, code_value: str) -> str:
        """Get human-readable description for a WFP code"""
        if not self.conn:
            return code_value

        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT description FROM wfp_translations
            WHERE code_type = ? AND code_value = ?
        ''', (code_type, code_value))

        result = cursor.fetchone()
        return result[0] if result else code_value

    def close(self):
        """Close database connection properly with checkpoint"""
        if self.conn:
            try:
                self.conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                self.conn.commit()
                self.conn.close()
                self.conn = None
                console.print("[dim]Database connection closed cleanly[/dim]")
            except Exception as e:
                console.print(f"[dim]Database close error (non-critical): {e}[/dim]")
                try:
                    if self.conn is not None:
                        self.conn.close()
                except:
                    pass
                self.conn = None
