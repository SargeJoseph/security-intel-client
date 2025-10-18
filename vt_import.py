"""
VirusTotal Import Module
Handles data import from PowerShell scripts and legacy data sources.
"""

from pathlib import Path
from typing import Dict

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

from constants import DEFAULT_HASH_DB_PATH, DEFAULT_DETECTION_DB_PATH
from vt_db import VTDatabase

console = Console()


def import_powershell_data(vt_db: VTDatabase):
    """Import data from PowerShell JSON files"""
    console.print(Panel("Import PowerShell VT Data", style="cyan"))

    # Ask for file locations
    hash_db_path = Prompt.ask(
        "Path to hash_database.json",
        default=str(DEFAULT_HASH_DB_PATH)
    )

    detection_db_path = Prompt.ask(
        "Path to detection_tracking.json",
        default=str(DEFAULT_DETECTION_DB_PATH)
    )

    hash_db_path = Path(hash_db_path)
    detection_db_path = Path(detection_db_path)

    total_imported = 0

    # Import hash database
    if hash_db_path.exists():
        console.print(f"\n[cyan]Importing {hash_db_path}...[/cyan]")
        count = vt_db.import_hash_database(hash_db_path)
        console.print(f"[green]Imported {count} hashes[/green]")
        total_imported += count
    else:
        console.print(f"[yellow]Hash database not found: {hash_db_path}[/yellow]")

    # Import detection tracking
    if detection_db_path.exists():
        console.print(f"\n[cyan]Importing {detection_db_path}...[/cyan]")
        count = vt_db.import_detection_tracking(detection_db_path)
        console.print(f"[green]Imported {count} vendors[/green]")
        total_imported += count
    else:
        console.print(f"[yellow]Detection tracking not found: {detection_db_path}[/yellow]")

    if total_imported > 0:
        console.print(f"\n[green]Successfully imported {total_imported} records![/green]")

        # Show stats
        stats = vt_db.get_stats()
        console.print(f"\n[cyan]Updated Statistics:[/cyan]")
        console.print(f"  Total hashes: {stats['total_hashes']}")
        console.print(f"  Malicious hashes: {stats['malicious_hashes']}")
        console.print(f"  Total scans: {stats['total_scans']}")
        console.print(f"  Vendors tracked: {stats['total_vendors']}")
    else:
        console.print("\n[yellow]No data was imported[/yellow]")


def one_time_vt_import(db_conn):
    """One-time import function for security_intel_cli.py"""
    console.print(Panel("One-Time VT Data Import", style="cyan"))

    vt_db = VTDatabase(db_conn)

    if Confirm.ask("Import data from PowerShell VT scanner?"):
        import_powershell_data(vt_db)

    if Confirm.ask("Run VT Scanner menu?"):
        from vt_ui import run_vt_scanner_menu
        run_vt_scanner_menu(vt_db)


def import_single_hash_file(vt_db: VTDatabase, hash_file_path: Path) -> int:
    """Import a single hash file in various formats"""
    if not hash_file_path.exists():
        console.print(f"[red]File not found: {hash_file_path}[/red]")
        return 0

    try:
        with open(hash_file_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()

        imported_count = 0

        # Try to detect format and import accordingly
        if content.startswith('{'):
            # JSON format
            try:
                data = json.loads(content)
                if 'hashes' in data:
                    # PowerShell format
                    imported_count = vt_db.import_hash_database(hash_file_path)
                else:
                    console.print("[yellow]Unsupported JSON format[/yellow]")
            except json.JSONDecodeError:
                console.print("[yellow]Invalid JSON format[/yellow]")

        else:
            # Plain text format - one hash per line
            hashes = [line.strip() for line in content.split('\n') if line.strip()]
            console.print(f"[cyan]Found {len(hashes)} hashes in plain text format[/cyan]")

            for hash_line in hashes:
                # Remove any comments or extra data
                hash_value = hash_line.split()[0] if hash_line.split() else hash_line
                if len(hash_value) == 64:  # SHA256 length
                    # Create basic hash entry
                    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    try:
                        cursor = vt_db.conn.cursor()
                        cursor.execute('''
                            INSERT OR IGNORE INTO file_hashes
                            (sha256, status, first_seen, last_seen)
                            VALUES (?, ?, ?, ?)
                        ''', (hash_value.lower(), 'imported', now, now))
                        imported_count += 1
                    except Exception as e:
                        console.print(f"[yellow]Error importing hash {hash_value}: {e}[/yellow]")
                        continue

            vt_db.conn.commit()

        return imported_count

    except Exception as e:
        console.print(f"[red]Import failed: {e}[/red]")
        return 0


def import_hash_list(vt_db: VTDatabase, hash_list: list, source: str = "manual") -> int:
    """Import a list of hashes into the database"""
    if not hash_list:
        console.print("[yellow]Empty hash list provided[/yellow]")
        return 0

    console.print(f"[cyan]Importing {len(hash_list)} hashes from {source}...[/cyan]")

    imported_count = 0
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        cursor = vt_db.conn.cursor()

        for hash_value in hash_list:
            if len(hash_value.strip()) == 64:  # SHA256 length
                try:
                    cursor.execute('''
                        INSERT OR IGNORE INTO file_hashes
                        (sha256, status, first_seen, last_seen, source)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (hash_value.strip().lower(), 'imported', now, now, source))
                    imported_count += 1
                except Exception as e:
                    console.print(f"[yellow]Error importing hash {hash_value}: {e}[/yellow]")
                    continue

        vt_db.conn.commit()
        console.print(f"[green]Successfully imported {imported_count} hashes[/green]")
        return imported_count

    except Exception as e:
        console.print(f"[red]Import failed: {e}[/red]")
        return 0


def export_hashes_to_file(vt_db: VTDatabase, export_path: Path, format: str = "json") -> bool:
    """Export hashes from database to file"""
    try:
        hashes = vt_db.get_malicious_hashes()

        if format.lower() == "json":
            export_data = {
                "export_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_hashes": len(hashes),
                "hashes": [
                    {
                        "sha256": h["sha256"],
                        "file_name": h.get("file_name", ""),
                        "status": h.get("status", ""),
                        "max_malicious": h.get("max_malicious", 0),
                        "first_seen": h.get("first_seen", ""),
                        "last_seen": h.get("last_seen", "")
                    }
                    for h in hashes
                ]
            }

            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2)

        elif format.lower() == "txt":
            with open(export_path, 'w', encoding='utf-8') as f:
                for h in hashes:
                    f.write(f"{h['sha256']}\n")

        else:
            console.print(f"[red]Unsupported export format: {format}[/red]")
            return False

        console.print(f"[green]Exported {len(hashes)} hashes to {export_path}[/green]")
        return True

    except Exception as e:
        console.print(f"[red]Export failed: {e}[/red]")
        return False


def show_import_statistics(vt_db: VTDatabase):
    """Show import-related statistics"""
    console.print(Panel("Import Statistics", style="cyan"))

    stats = vt_db.get_stats()

    console.print(f"\n[cyan]Import Statistics:[/cyan]")
    console.print(f"  Total imported hashes: {stats['total_hashes']}")
    console.print(f"  Imported malicious hashes: {stats['malicious_hashes']}")

    # Additional import-specific stats
    cursor = vt_db.conn.cursor()

    # Count imports by source if source column exists
    try:
        cursor.execute("PRAGMA table_info(file_hashes)")
        columns = [row[1] for row in cursor.fetchall()]

        if 'source' in columns:
            cursor.execute('''
                SELECT source, COUNT(*) as count
                FROM file_hashes
                WHERE source IS NOT NULL
                GROUP BY source
                ORDER BY count DESC
            ''')
            sources = cursor.fetchall()

            if sources:
                console.print(f"\n[cyan]Imports by Source:[/cyan]")
                for source, count in sources:
                    console.print(f"  {source}: {count}")

    except Exception:
        pass  # Source column might not exist

    # Recent imports
    cursor.execute('''
        SELECT first_seen, COUNT(*) as count
        FROM file_hashes
        WHERE first_seen > datetime('now', '-30 days')
        GROUP BY date(first_seen)
        ORDER BY first_seen DESC
        LIMIT 7
    ''')
    recent_imports = cursor.fetchall()

    if recent_imports:
        console.print(f"\n[cyan]Recent Import Activity (last 7 days):[/cyan]")
        for date_str, count in recent_imports:
            console.print(f"  {date_str[:10]}: {count} imports")


# Import necessary modules for additional functionality
import json
from datetime import datetime
