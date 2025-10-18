#!/usr/bin/env python3
"""
VirusTotal Scanner Module - Modular Version
Integrates with security_intel_cli.py database
NOW WITH FILE UPLOAD FUNCTIONALITY

This is the main entry point that uses the new modular structure.
"""

import os
import sys
from pathlib import Path

# Add the current directory to path to ensure imports work
sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console

from constants import OUTPUT_DIR, DB_PATH
from vt_db import VTDatabase
from vt_ui import run_vt_scanner_menu, show_welcome_banner
from vt_import import one_time_vt_import

console = Console()


def main():
    """Main entry point for standalone VT Scanner execution"""
    show_welcome_banner()
    
    # This would typically be passed from the main CLI
    # For standalone use, we create a temporary database connection
    try:
        import sqlite3
        db_conn = sqlite3.connect(DB_PATH)
        vt_db = VTDatabase(db_conn)
        
        # Run the scanner menu
        run_vt_scanner_menu(vt_db)
        
        # Close database connection
        db_conn.close()
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()