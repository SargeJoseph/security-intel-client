#!/usr/bin/env python3
"""
Database Maintenance Module
Handles database maintenance, cleanup operations, and external database browser
"""

import sqlite3
import subprocess
import platform
from pathlib import Path
from datetime import datetime, timedelta
from typing import TYPE_CHECKING
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.table import Table
from rich import box

if TYPE_CHECKING:
    from database import Database

console = Console()

# Cache configuration
URLHAUS_CACHE_DAYS = 90
GEOIP_CACHE_DAYS = 90


class DatabaseMaintenance:
    """Handles database maintenance, cleanup operations, and external database browser"""

    def __init__(self, db: 'Database', db_path: Path):
        """
        Initialize database maintenance handler

        Args:
            db: Database instance
            db_path: Path to the database file
        """
        self.db = db
        self.db_path = db_path

    def database_maintenance(self):
        """Perform database maintenance and cleanup"""
        console.print(Panel("Database Maintenance", style="cyan"))


        # Display current database status
        self._display_database_status()

        # Display database contents statistics
        self._display_database_stats()

        # NEW: Offer database explorer
        self.launch_database_explorer()

        # Offer maintenance operations
        self._perform_maintenance_operations()



    def launch_database_explorer(self):
        """Launch external database browser for visual data exploration"""
        console.print(Panel("Database Explorer", style="cyan"))

        # Make sure the database file exists
        if not self.db_path.exists():
            console.print(f"[red]Error: Database file not found at {self.db_path}[/red]")
            return False

        console.print("[dim]Preparing database for external access...[/dim]")

        # Close our database connection temporarily to allow external access
        try:
            if self.db and self.db.conn:
                # Create a checkpoint to ensure clean state
                self.db.conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                self.db.conn.commit()
                console.print("[green]✓ Database checkpoint created[/green]")
        except Exception as e:
            console.print(f"[yellow]Note: Could not create checkpoint: {e}[/yellow]")

        system = platform.system()
        launched_count = 0  # Track how many browsers we launched
        processes = []  # Store launched processes

        console.print("\n[cyan]Trying to launch database browsers...[/cyan]")

        if system == "Windows":
            browsers = [
                # Try common installation paths first
                # r"C:\Program Files\Paradigma Software\Valentina Studio 16\vstudio.exe",
                r"C:\Program Files\DB Browser for SQLite\DB Browser for SQLite.exe",
            ]

        elif system == "Darwin":  # macOS
            browsers = [
                "/Applications/DB Browser for SQLite.app/Contents/MacOS/DB Browser for SQLite",
                "/Applications/SQLiteStudio.app/Contents/MacOS/SQLiteStudio",
                "/Applications/DBeaver.app/Contents/MacOS/dbeaver",
                "/Applications/Valentina Studio.app/Contents/MacOS/Valentina Studio"
            ]

        elif system == "Linux":
            browsers = [
                "sqlitebrowser",
                "sqlitestudio",
                "dbeaver",
                "sqlite3"  # Command-line fallback
            ]

        else:
            console.print(f"[yellow]Unsupported operating system: {system}[/yellow]")
            browsers = []

        for browser in browsers:
            try:
                console.print(f"[dim]Trying: {browser}[/dim]")

                if system == "Windows" and (" " in browser or browser.endswith('.exe')):
                    # Handle Windows paths with spaces
                    if Path(browser).exists():
                        # Direct path exists
                        process = subprocess.Popen([browser, str(self.db_path)])
                    else:
                        # Try as command in PATH
                        process = subprocess.Popen([browser, str(self.db_path)])
                else:
                    # Unix-like systems
                    process = subprocess.Popen([browser, str(self.db_path)])

                # Give it a moment to launch
                import time
                time.sleep(1)  # Reduced sleep time since we're launching multiple

                if process.poll() is None:  # Still running
                    console.print(f"[green]✓ Successfully launched: {browser}[/green]")
                    launched_count += 1
                    processes.append(process)
                else:
                    console.print(f"[dim]  {browser} exited immediately[/dim]")

            except (FileNotFoundError, PermissionError, OSError) as e:
                console.print(f"[dim]  {browser} not available[/dim]")
                continue

        if launched_count == 0:
            console.print("\n[yellow]No SQLite browser could be auto-launched[/yellow]")
            console.print("[cyan]Manual options:[/cyan]")
            console.print(f"  1. Open database file directly:")
            console.print(f"     [white]{self.db_path}[/white]")
            console.print("  2. Install DB Browser for SQLite from:")
            console.print("     [blue]https://sqlitebrowser.org/[/blue]")

            # Offer to open the containing folder
            if Confirm.ask("\nOpen containing folder?"):
                try:
                    if system == "Windows":
                        subprocess.run(["explorer", str(self.db_path.parent)])
                    elif system == "Darwin":
                        subprocess.run(["open", str(self.db_path.parent)])
                    elif system == "Linux":
                        subprocess.run(["xdg-open", str(self.db_path.parent)])
                    console.print("[green]✓ Folder opened[/green]")
                except Exception as e:
                    console.print(f"[red]Error opening folder: {e}[/red]")

        else:
            # Successfully launched browsers
            console.print(f"\n[green]✓ Launched {launched_count} database browser(s) successfully![/green]")
            console.print("[yellow]⚠ Note: Avoid making changes from both applications simultaneously[/yellow]")
            console.print("[dim]The external browsers will show live data from your security intelligence database[/dim]")

        # Re-establish our database connection
        try:
            if self.db and not self.db.conn:
                self.db.init_db()
                console.print("[green]✓ Database connection restored[/green]")
        except Exception as e:
            console.print(f"[yellow]Note: Could not restore database connection: {e}[/yellow]")

        return launched_count > 0

    def _display_database_status(self):
        """Display current database file status"""
        console.print("\n[cyan]Current Database Status:[/cyan]")
        console.print(f"  Database path: {self.db_path}")

        if self.db_path.exists():
            db_size_kb = self.db_path.stat().st_size / 1024
            console.print(f"  Database size: {db_size_kb:.2f} KB")
        else:
            console.print("  [yellow]Database file not found[/yellow]")
            return

        # Check for WAL and SHM files
        wal_file = Path(str(self.db_path) + '-wal')
        shm_file = Path(str(self.db_path) + '-shm')

        if wal_file.exists():
            wal_size_kb = wal_file.stat().st_size / 1024
            console.print(f"  WAL file: {wal_size_kb:.2f} KB")

        if shm_file.exists():
            shm_size_kb = shm_file.stat().st_size / 1024
            console.print(f"  SHM file: {shm_size_kb:.2f} KB")

    def _display_database_stats(self):
        """Display database contents statistics"""
        stats = self.db.get_stats()

        console.print(f"\n[cyan]Database Contents:[/cyan]")
        # console.print(f"  Total IPs: {stats['total_ips']}")
        # console.print(f"  Malicious IPs: {stats['malicious_ips']}")
        #console.print(f"  Total Events: {stats['total_events']}")

        # Additional statistics
        if self.db.conn:
            cursor = self.db.conn.cursor()

            # Count processed archives
            cursor.execute('SELECT COUNT(*) FROM processed_files')
            archive_count = cursor.fetchone()[0]
            console.print(f"  Processed Archives: {archive_count}")


            # Count API usage entries
            cursor.execute('SELECT COUNT(*) FROM api_usage')
            api_usage_count = cursor.fetchone()[0]
            console.print(f"  API Usage Logs: {api_usage_count}")

            # Count IP processes
            cursor.execute('SELECT COUNT(*) FROM ip_processes')
            process_count = cursor.fetchone()[0]
            console.print(f"  IP-Process Associations: {process_count}")

    def _perform_maintenance_operations(self):
        """Perform various maintenance operations based on user choice"""

        # Operation 1: Database compaction (VACUUM)
        if Confirm.ask("\nCompact database (VACUUM)?"):
            self._compact_database()

        # Operation 2: Clear old cache entries
        if Confirm.ask("\nClear very old cache entries?"):
            self._clear_old_cache()

        # Operation 3: Clear API usage logs
        if Confirm.ask("\nClear old API usage logs?"):
            self._clear_api_logs()

        # Operation 4: Checkpoint WAL file
        if Confirm.ask("\nCheckpoint WAL file (merge to main database)?"):
            self._checkpoint_wal()

    def _compact_database(self):
        """Compact the database using VACUUM"""
        console.print("[yellow]Compacting database...[/yellow]")

        if not self.db.conn:
            console.print("[red]Database connection is not available. Cannot compact.[/red]")
            return

        try:
            old_size = self.db_path.stat().st_size / 1024

            self.db.conn.execute('VACUUM')
            self.db.conn.commit()

            new_size = self.db_path.stat().st_size / 1024
            saved = old_size - new_size

            console.print("[green]Database compacted![/green]")
            console.print(f"  Old size: {old_size:.2f} KB")
            console.print(f"  New size: {new_size:.2f} KB")
            console.print(f"  Space saved: {saved:.2f} KB")
        except Exception as e:
            console.print(f"[red]Error compacting database: {e}[/red]")

    def _clear_old_cache(self):
        """Clear cache entries older than retention period"""
        max_cache_days = max(URLHAUS_CACHE_DAYS, GEOIP_CACHE_DAYS) + 30
        cutoff_date = (datetime.now() - timedelta(days=max_cache_days)).isoformat()

        console.print(f"[yellow]Clearing entries older than {max_cache_days} days...[/yellow]")

        if not self.db.conn:
            console.print("[red]Database connection is not available. Cannot clear old entries.[/red]")
            return

        try:
            cursor = self.db.conn.cursor()

            # Count before deletion
            cursor.execute('SELECT COUNT(*) FROM ip_intelligence WHERE last_seen < ?', (cutoff_date,))
            old_count = cursor.fetchone()[0]

            if old_count == 0:
                console.print("[green]No old entries to clear[/green]")
                return

            # Delete old entries
            cursor.execute('DELETE FROM ip_intelligence WHERE last_seen < ?', (cutoff_date,))
            self.db.conn.commit()

            console.print(f"[green]Cleared {old_count} old entries[/green]")
        except Exception as e:
            console.print(f"[red]Error clearing old cache: {e}[/red]")

    def _clear_api_logs(self):
        """Clear old API usage logs"""
        cutoff_days = 90  # Keep 90 days of API logs
        cutoff_date = (datetime.now() - timedelta(days=cutoff_days)).isoformat()

        console.print(f"[yellow]Clearing API logs older than {cutoff_days} days...[/yellow]")

        if not self.db.conn:
            console.print("[red]Database connection is not available.[/red]")
            return

        try:
            cursor = self.db.conn.cursor()

            # Count before deletion
            cursor.execute('SELECT COUNT(*) FROM api_usage WHERE request_time < ?', (cutoff_date,))
            old_count = cursor.fetchone()[0]

            if old_count == 0:
                console.print("[green]No old API logs to clear[/green]")
                return

            # Delete old logs
            cursor.execute('DELETE FROM api_usage WHERE request_time < ?', (cutoff_date,))
            self.db.conn.commit()

            console.print(f"[green]Cleared {old_count} old API log entries[/green]")
        except Exception as e:
            console.print(f"[red]Error clearing API logs: {e}[/red]")

    def _checkpoint_wal(self):
        """Checkpoint WAL file to merge changes into main database"""
        console.print("[yellow]Checkpointing WAL file...[/yellow]")

        if not self.db.conn:
            console.print("[red]Database connection is not available.[/red]")
            return

        try:
            self.db.conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            self.db.conn.commit()
            console.print("[green]WAL checkpoint complete[/green]")

            # Check WAL file size after checkpoint
            wal_file = Path(str(self.db_path) + '-wal')
            if wal_file.exists():
                wal_size = wal_file.stat().st_size / 1024
                if wal_size > 0:
                    console.print(f"  WAL file size after checkpoint: {wal_size:.2f} KB")
                else:
                    console.print("  WAL file cleared")
            else:
                console.print("  WAL file removed")
        except Exception as e:
            console.print(f"[red]Error checkpointing WAL: {e}[/red]")
