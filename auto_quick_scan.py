#!/usr/bin/env python3
"""
Autonomous Quick Scan Script
Runs independently via Task Scheduler to scan new/uncached IPs
Bypasses CLI menu system for automated execution
"""

import sys
from pathlib import Path
from datetime import datetime

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from constants import DB_PATH
from database import Database
from threat_intelligence import ThreatIntelligence
from scan_operations import quick_scan
from config import get_urlhaus_api_key, get_abuseipdb_api_key, get_ipqs_api_key

console = Console()


def main():
    """Main entry point for autonomous quick scan"""
    start_time = datetime.now()

    console.print("\n" + "="*60)
    console.print(f"[cyan]AUTONOMOUS QUICK SCAN - Started at {start_time.strftime('%Y-%m-%d %H:%M:%S')}[/cyan]")
    console.print("="*60 + "\n")

    try:
        # Initialize database
        console.print("[dim]Initializing database connection...[/dim]")
        db = Database(DB_PATH)

        # Initialize threat intelligence
        console.print("[dim]Initializing threat intelligence modules...[/dim]")
        threat_intel = ThreatIntelligence(db)

        # Load API keys from config
        console.print("[dim]Loading API keys from configuration...[/dim]")
        urlhaus_key = get_urlhaus_api_key()
        abuseipdb_key = get_abuseipdb_api_key()
        ipqs_key = get_ipqs_api_key()

        # Assign keys to ThreatIntelligence instance
        threat_intel.urlhaus_key = urlhaus_key
        threat_intel.abuseipdb_key = abuseipdb_key
        threat_intel.ipqs_key = ipqs_key

        # Log key status (masked for security)
        if urlhaus_key:
            console.print("[green]✓ URLhaus API key loaded[/green]")
        else:
            console.print("[yellow]⚠ URLhaus API key not found[/yellow]")

        if abuseipdb_key:
            console.print("[green]✓ AbuseIPDB API key loaded[/green]")
        else:
            console.print("[yellow]⚠ AbuseIPDB API key not found[/yellow]")

        if ipqs_key:
            console.print("[green]✓ IPQualityScore API key loaded[/green]")
        else:
            console.print("[dim]IPQualityScore API key not configured[/dim]")

        # Run quick scan (non-interactive mode)
        console.print("[green]Starting quick scan (autonomous mode)...[/green]\n")
        quick_scan(db, threat_intel, interactive=False)

        # Calculate duration
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        console.print("\n" + "="*60)
        console.print(f"[green]✓ Quick scan completed successfully![/green]")
        console.print(f"[dim]Duration: {duration:.1f} seconds[/dim]")
        console.print(f"[dim]Finished at: {end_time.strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
        console.print("="*60 + "\n")

        # Close database
        db.close()

        return 0

    except KeyboardInterrupt:
        console.print("\n[yellow]Quick scan interrupted by user[/yellow]")
        return 1

    except Exception as e:
        console.print(f"\n[red]ERROR: Quick scan failed![/red]")
        console.print(f"[red]Error: {e}[/red]")

        # Print full traceback for debugging
        import traceback
        console.print("\n[dim]Full traceback:[/dim]")
        console.print(traceback.format_exc())

        return 1


if __name__ == "__main__":
    sys.exit(main())
