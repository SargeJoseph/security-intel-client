#!/usr/bin/env python3
"""
Autonomous Forensic Artifact Collector (FAC) Script
Runs independently via Task Scheduler to collect and scan forensic artifacts
Bypasses CLI menu system for automated execution
"""

import sys
from pathlib import Path
from datetime import datetime

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from forensic_collector import ForensicCollector
from vt_api import VTScanner
from vt_db import VTDatabase
from database import Database
from constants import DB_PATH

# Use safe ASCII output for logging/redirection compatibility
console = Console(legacy_windows=False, force_terminal=False)


def main():
    """Main entry point for autonomous FAC scan"""
    start_time = datetime.now()

    console.print("\n" + "="*60)
    console.print(f"[cyan]AUTONOMOUS FORENSIC ARTIFACT COLLECTOR - Started at {start_time.strftime('%Y-%m-%d %H:%M:%S')}[/cyan]")
    console.print("="*60 + "\n")

    try:
        # Initialize main database
        console.print("[dim]Initializing database connection...[/dim]")
        db = Database(DB_PATH)

        # Initialize VT database wrapper
        console.print("[dim]Initializing VirusTotal database...[/dim]")
        vt_db = VTDatabase(db.conn)

        console.print("[green]OK: Database initialized[/green]")

        # Initialize VT scanner
        vt_scanner = VTScanner(vt_db)

        # Initialize forensic collector
        console.print("[dim]Initializing forensic artifact collector...[/dim]")
        collector = ForensicCollector()

        # Collect executables from forensic artifacts
        console.print("\n[green]Starting forensic artifact collection (autonomous mode)...[/green]\n")
        file_paths = collector.collect_executables(include_manual=True)

        if not file_paths:
            console.print("\n[yellow]No executable files found to scan[/yellow]")
            console.print("[dim]Check if forensic tools are available and artifacts exist[/dim]")
            return 0

        # Save file list for reference
        console.print(f"\n[cyan]Collected {len(file_paths)} executable files[/cyan]")
        collector.save_file_list(file_paths)

        # Scan collected files with VirusTotal
        console.print("\n[green]Starting VirusTotal scan of collected files...[/green]\n")
        results = vt_scanner.scan_multiple_files(file_paths, allow_upload=True)

        # Display results
        console.print("\n" + "="*60)
        console.print("[cyan]Scan Results Summary:[/cyan]")
        console.print(f"  Total files: {results['total']}")
        console.print(f"  Successfully scanned: {results['scanned']}")
        console.print(f"  Malicious: [red]{results['malicious']}[/red]")
        console.print(f"  Clean: [green]{results['clean']}[/green]")
        console.print(f"  Cached: [yellow]{results['cached']}[/yellow]")
        console.print(f"  Errors: [red]{results['errors']}[/red]")

        # Calculate duration
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        console.print("\n" + "="*60)
        console.print(f"[green]SUCCESS: FAC scan completed successfully![/green]")
        console.print(f"[dim]Duration: {duration:.1f} seconds[/dim]")
        console.print(f"[dim]Finished at: {end_time.strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
        console.print("="*60 + "\n")

        # Close database
        db.close()

        return 0

    except KeyboardInterrupt:
        console.print("\n[yellow]FAC scan interrupted by user[/yellow]")
        return 1

    except Exception as e:
        console.print(f"\n[red]ERROR: FAC scan failed![/red]")
        console.print(f"[red]Error: {e}[/red]")

        # Print full traceback for debugging
        import traceback
        console.print("\n[dim]Full traceback:[/dim]")
        console.print(traceback.format_exc())

        return 1


if __name__ == "__main__":
    sys.exit(main())
