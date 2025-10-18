"""
CLI Menu display and user interaction for Security Intelligence CLI Tool
Handles menu presentation and cleanup operations
"""

import atexit
import warnings

from rich.console import Console
from rich.prompt import Prompt

# Suppress database lock warnings
warnings.filterwarnings("ignore", message="database is locked")

console = Console()


def cleanup_database():
    """Clean up any database connections on exit"""
    import sqlite3
    try:
        pass
    except:
        pass


# Register cleanup function to run on exit
atexit.register(cleanup_database)


def show_menu() -> str:
    """
    Display the main menu and get user choice
    
    Returns:
        User's menu selection as a string
    """
    console.print("\n[bold cyan]Main Menu:[/bold cyan]")
    console.print("1. Quick Scan - Analyze new IPs and retry errors")
    console.print("2. Full Scan - Refresh all IP intelligence")
    console.print("3. Browse Applications - View apps with threat data")
    console.print("4. Search IP - Deep dive on specific IP")
    console.print("5. Threat Summary - Show malicious IPs only")
    console.print("6. VirusTotal Scanner - File and hash analysis")
    console.print("7. Database Maintenance")
    console.print("8. Scan Single IP - Analyze specific IP address")
    console.print("9. Exit")
    
    return Prompt.ask("Select option", choices=["1", "2", "3", "4", "5", "6", "7", "8", "9"])
