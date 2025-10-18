"""
VirusTotal Scanner Package
Modular VirusTotal integration for security intelligence CLI.
"""

__version__ = "1.0.0"
__author__ = "Security Intelligence CLI"
__description__ = "VirusTotal scanner with file upload capability"

# Import main components for easy access
from .vt_db import VTDatabase
from .vt_api import VTScanner
from .vt_ui import run_vt_scanner_menu, show_welcome_banner, get_menu_options
from .vt_reports import (
    view_vt_statistics, view_vendor_performance, show_malicious_process_report,
    show_upload_statistics, malicious_process_report, show_database_stats
)
from .vt_import import import_powershell_data, one_time_vt_import
from .vt_utils import (
    calculate_file_hash, validate_hash, get_file_list_from_directory,
    safe_database_operation, format_file_size, is_safe_to_upload,
    batch_process_files, display_system_info, display_disk_space
)

# Define what gets imported with "from vt_scanner import *"
__all__ = [
    # Database
    'VTDatabase',
    
    # API and Scanning
    'VTScanner',
    
    # User Interface
    'run_vt_scanner_menu',
    'show_welcome_banner',
    'get_menu_options',
    
    # Reports
    'view_vt_statistics',
    'view_vendor_performance',
    'show_malicious_process_report',
    'show_upload_statistics',
    'malicious_process_report',
    'show_database_stats',
    
    # Import/Export
    'import_powershell_data',
    'one_time_vt_import',
    
    # Utilities
    'calculate_file_hash',
    'validate_hash',
    'get_file_list_from_directory',
    'safe_database_operation',
    'format_file_size',
    'is_safe_to_upload',
    'batch_process_files',
    'display_system_info',
    'display_disk_space'
]