#!/usr/bin/env python3
"""
VirusTotal Integration Module
Handles VirusTotal scanning menu integration
"""

from typing import TYPE_CHECKING
from rich.console import Console
from rich.panel import Panel

if TYPE_CHECKING:
    from database import Database

console = Console()


class VirusTotalIntegration:
    """Handles VirusTotal scanning functionality integration"""

    def __init__(self, db: 'Database'):
        """
        Initialize VirusTotal integration
        
        Args:
            db: Database instance
        """
        self.db = db

    def virustotal_menu(self):
        """Access VirusTotal scanning functionality"""
        console.print(Panel("VirusTotal Scanner", style="cyan"))

        try:
            # Dynamically import vt_scanner module
            import vt_scanner
            
            # Initialize VT database wrapper with existing connection
            vt_db = vt_scanner.VTDatabase(self.db.conn)

            # Run the VT scanner menu
            vt_scanner.run_vt_scanner_menu(vt_db)

        except ImportError as e:
            console.print("[red]Error: VirusTotal scanner module not found[/red]")
            console.print(f"[yellow]Details: {e}[/yellow]")
            console.print("\n[cyan]Please ensure vt_scanner.py is in the same directory[/cyan]")
            return

        except AttributeError as e:
            console.print("[red]Error: VirusTotal scanner module is missing required functions[/red]")
            console.print(f"[yellow]Details: {e}[/yellow]")
            console.print("\n[cyan]Expected functions:[/cyan]")
            console.print("  - VTDatabase class")
            console.print("  - run_vt_scanner_menu(vt_db)")
            return

        except Exception as e:
            console.print(f"[red]Error launching VirusTotal scanner: {e}[/red]")
            console.print("\n[yellow]Check that:[/yellow]")
            console.print("  1. vt_scanner.py exists in the same directory")
            console.print("  2. You have a valid VirusTotal API key configured")
            console.print("  3. The vt_scanner module is properly formatted")
            return
