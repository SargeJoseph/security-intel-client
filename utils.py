#!/usr/bin/env python3
"""
Utilities Module
Shared utilities, console setup, and common configurations
"""

import os
import sys
import csv
import platform
import warnings
from pathlib import Path
from rich.console import Console
from rich.style import Style

# Suppress database lock warnings
warnings.filterwarnings("ignore", message="database is locked")

# Initialize Rich console for global use
console = Console()

# Configure CSV field size limit based on platform
if platform.system() == 'Windows':
    csv.field_size_limit(2147483647)
else:
    csv.field_size_limit(sys.maxsize)

# Import _get_env from config to use .env file ONLY
try:
    from config import _get_env
except ImportError:
    # Fallback if config not available
    def _get_env(key: str, default: str = None) -> str:
        return default or ''

# Environment-based path configuration
OUTPUT_DIR = Path(_get_env('OUTPUT') or '.')
SCRIPTS_DIR = Path(_get_env('SCRIPTS') or '.')
MASTER_CSV = OUTPUT_DIR / "MasterNetworkReport.csv"
ARCHIVE_DIR = OUTPUT_DIR / "LogArchives"
DB_PATH = OUTPUT_DIR / "security_intel.db"

# API rate limiting configuration
URLHAUS_DELAY = 0.2  # seconds between URLhaus API calls
IPAPI_DELAY = 1.4    # seconds between IP-API calls
IPAPICO_DAILY_LIMIT = 1000  # Daily limit for IP-API.co

# Cache expiration configuration
URLHAUS_CACHE_DAYS = 7   # Days to cache URLhaus results
GEOIP_CACHE_DAYS = 30    # Days to cache GeoIP results

# Styling configurations
STYLE_SUCCESS = Style(color="green", bold=True)
STYLE_WARNING = Style(color="yellow")
STYLE_ERROR = Style(color="red", bold=True)
STYLE_INFO = Style(color="cyan")
STYLE_THREAT = Style(color="red", bold=True)


def ensure_directories():
    """Ensure required directories exist"""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    console.print(f"[dim]Output directory: {OUTPUT_DIR}[/dim]")
    console.print(f"[dim]Archive directory: {ARCHIVE_DIR}[/dim]")


def validate_ip_address(ip: str) -> bool:
    """
    Validate if a string is a valid IPv4 address

    Args:
        ip: IP address string to validate

    Returns:
        True if valid IPv4 address, False otherwise
    """
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False

        for part in parts:
            num = int(part)
            if num < 0 or num > 255:
                return False

        return True
    except (ValueError, AttributeError):
        return False


def format_file_size(size_bytes: float) -> str:
    """
    Format file size in human-readable format

    Args:
        size_bytes: Size in bytes

    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"


def truncate_string(text: str, max_length: int = 50, suffix: str = "...") -> str:
    """
    Truncate a string to a maximum length

    Args:
        text: String to truncate
        max_length: Maximum length including suffix
        suffix: Suffix to append if truncated

    Returns:
        Truncated string
    """
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix


def safe_int_parse(value, default: int = 0) -> int:
    """
    Safely parse an integer from various input types

    Args:
        value: Value to parse (str, int, or other)
        default: Default value if parsing fails

    Returns:
        Parsed integer or default value
    """
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def get_timestamp_display(iso_timestamp: str) -> str:
    """
    Format ISO timestamp for display

    Args:
        iso_timestamp: ISO format timestamp string

    Returns:
        Formatted timestamp (YYYY-MM-DD HH:MM:SS)
    """
    try:
        if not iso_timestamp:
            return "N/A"
        # Take first 19 characters (date and time, no microseconds)
        return iso_timestamp[:19].replace('T', ' ')
    except (AttributeError, IndexError):
        return "N/A"


def cleanup_on_exit():
    """Cleanup function to be called on program exit"""
    import sqlite3
    try:
        # This is called by atexit, can be used for any cleanup
        pass
    except:
        pass


def print_banner():
    """Print application banner"""
    from rich.panel import Panel

    banner_text = (
        "[bold cyan]Security Intelligence CLI Tool[/bold cyan]\n"
        "Integrating Windows Security logs with threat intelligence\n"
        f"[dim]Database: {DB_PATH}[/dim]"
    )

    console.print(Panel.fit(banner_text, border_style="cyan"))


def get_config_summary() -> dict:
    """
    Get configuration summary for display

    Returns:
        Dictionary with configuration values
    """
    return {
        'output_dir': str(OUTPUT_DIR),
        'scripts_dir': str(SCRIPTS_DIR),
        'database': str(DB_PATH),
        'archive_dir': str(ARCHIVE_DIR),
        'urlhaus_cache_days': URLHAUS_CACHE_DAYS,
        'geoip_cache_days': GEOIP_CACHE_DAYS,
        'urlhaus_delay': URLHAUS_DELAY,
        'ipapi_delay': IPAPI_DELAY
    }


def print_config():
    """Print current configuration"""
    console.print("\n[cyan]Current Configuration:[/cyan]")
    config = get_config_summary()
    for key, value in config.items():
        console.print(f"  {key.replace('_', ' ').title()}: {value}")


# Register cleanup function
import atexit
atexit.register(cleanup_on_exit)
