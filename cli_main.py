#!/usr/bin/env python3
"""
Security Intelligence CLI Tool - Main Entry Point
Coordinates all modules and handles the main application loop
"""

import sys
import os
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

# Import all the module components
from config import DB_PATH, get_urlhaus_api_key, get_abuseipdb_api_key, get_ipqs_api_key, check_toml_support, CONFIG_FILE, URLHAUS_DELAY, IPAPI_DELAY, IPQS_DELAY
from database import Database
from threat_intelligence import ThreatIntelligence

from cli_menu import show_menu
from scan_operations import quick_scan, full_scan, single_ip_scan, extract_unique_ips_from_db, read_applications_from_db
from ip_operations import IPOperations
from app_browser import ApplicationBrowser
from maintenance import DatabaseMaintenance
from virustotal_integration import VirusTotalIntegration

console = Console()


def check_env_file():
    """
    Check if .env file exists in the root directory.
    Display an error message and exit if not found.
    """
    # Get the directory where this script is located (root of project)
    script_dir = Path(__file__).parent.resolve()
    env_file = script_dir / ".env"
    env_example = script_dir / ".env.example"

    if not env_file.exists():
        console.print("\n[bold red]ERROR: .env file not found![/bold red]\n")
        console.print("[yellow]The .env file is required for configuration.[/yellow]")
        console.print(f"[yellow]Expected location: {env_file}[/yellow]\n")

        if env_example.exists():
            console.print("[cyan]A .env.example template file is available.[/cyan]")
            console.print("[cyan]To set up your environment:[/cyan]")
            console.print(f"  1. Copy [bold]{env_example}[/bold] to [bold]{env_file}[/bold]")
            console.print("  2. Edit [bold].env[/bold] and update the paths for your system")
            console.print("  3. Replace %USERPROFILE% with your actual Windows user path\n")
        else:
            console.print("[cyan]Please create a .env file with the following variables:[/cyan]")
            console.print("  OUTPUT=<path to output directory>")
            console.print("  SCRIPTS=<path to scripts directory>")
            console.print("  LOGARCHIVES=<path to log archives>")
            console.print("  DB=<path to database file>\n")

        sys.exit(1)

    # Check if python-dotenv is installed
    try:
        import dotenv
    except ImportError:
        console.print("\n[yellow]Warning: python-dotenv not installed[/yellow]")
        console.print("[cyan]For better .env file support, install it:[/cyan]")
        console.print("  pip install python-dotenv")
        console.print("[dim]Falling back to system environment variables...\n[/dim]")

    return True
class SecurityIntelligenceCLI:
    """Main CLI application coordinator"""

    def __init__(self):
        """Initialize the CLI with all required components"""
        self.db = Database(DB_PATH)
        self.db.init_wfp_translations()
        self.threat_intel = ThreatIntelligence(self.db)
        self.urlhaus_key = None
        self.abuseipdb_key = None

        # Initialize operation handlers
        self.ip_ops = IPOperations(self.db, self.threat_intel)
        self.app_browser = ApplicationBrowser(self.db)
        self.vt_integration = VirusTotalIntegration(self.db)

    def load_api_key(self):
        """Load API keys from config file"""
        console.print("[dim]Loading API keys...[/dim]")

        # Load URLhaus key
        if check_toml_support():
            self.urlhaus_key = get_urlhaus_api_key()
            if self.urlhaus_key:
                console.print(f"[green]OK: URLhaus API key loaded from {CONFIG_FILE}[/green]")
                masked_key = self.urlhaus_key[:8] + "..." + self.urlhaus_key[-4:] if len(self.urlhaus_key) > 12 else "***"
                console.print(f"[dim]Key: {masked_key}[/dim]")
            else:
                console.print(f"[yellow]No URLhaus API key found in {CONFIG_FILE}[/yellow]")

        # Load AbuseIPDB key
        if check_toml_support():
            self.abuseipdb_key = get_abuseipdb_api_key()
            if self.abuseipdb_key:
                console.print(f"[green]OK: AbuseIPDB API key loaded from {CONFIG_FILE}[/green]")
                masked_key = self.abuseipdb_key[:8] + "..." + self.abuseipdb_key[-4:] if len(self.abuseipdb_key) > 12 else "***"
                console.print(f"[dim]Key: {masked_key}[/dim]")

        # CRITICAL: Pass keys to ThreatIntelligence
        console.print(f"[dim]Passing keys to ThreatIntelligence...[/dim]")
        self.threat_intel.urlhaus_key = self.urlhaus_key
        self.threat_intel.abuseipdb_key = self.abuseipdb_key
        self.threat_intel.ipqs_key = get_ipqs_api_key()
        console.print(f"[green]OK: Keys assigned to ThreatIntelligence[/green]")

    def run(self):
        """Main application loop"""
        console.print(Panel.fit(
            "[bold cyan]TOILEMAITRE - TRACE CONSOLE[/bold cyan]\n"
            "Integrating Windows Security logs with threat intelligence",
            border_style="cyan"
        ))

        # Load API key from config or prompt
        self.load_api_key()

        while True:
            try:
                choice = show_menu()

                if choice == "1":
                    quick_scan(self.db, self.threat_intel)
                elif choice == "2":
                    full_scan(self.db, self.threat_intel)
                elif choice == "3":
                    self.app_browser.browse_applications()
                elif choice == "4":
                    self.ip_ops.search_ip()
                elif choice == "5":
                    self.ip_ops.threat_summary()
                elif choice == "6":
                    self.vt_integration.virustotal_menu()
                elif choice == "7":
                    maintenance = DatabaseMaintenance(self.db, DB_PATH)
                    maintenance.database_maintenance()
                elif choice == "8":
                    single_ip_scan(self.db, self.threat_intel)
                elif choice == "9":
                    console.print("\n[cyan]Goodbye![/cyan]")
                    break

                if choice != "8":
                    Prompt.ask("\nPress Enter to continue")

            except KeyboardInterrupt:
                console.print("\n\n[yellow]Interrupted by user[/yellow]")
                if Confirm.ask("Exit application?"):
                    break
            except Exception as e:
                console.print(f"\n[red]Error: {e}[/red]")
                if not Confirm.ask("Continue?"):
                    break

        self.db.close()


def main():
    """Entry point"""
    # Check for .env file before initializing anything
    check_env_file()

    try:
        cli = SecurityIntelligenceCLI()
        cli.run()
    except Exception as e:
        console.print(f"[red]Fatal error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
