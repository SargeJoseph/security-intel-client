"""
VirusTotal UI Module
Handles all user interface, menu navigation, and user interaction.
"""

import sys
from pathlib import Path
from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

from constants import OUTPUT_DIR, DEFAULT_HASH_DB_PATH, DEFAULT_DETECTION_DB_PATH
from vt_db import VTDatabase
from vt_api import VTScanner
from vt_reports import (
    view_vt_statistics, view_vendor_performance, show_malicious_process_report,
    show_upload_statistics, malicious_process_report
)
from vt_import import import_powershell_data
from forensic_collector import forensic_collection_menu

console = Console()


def run_vt_scanner_menu(vt_db: VTDatabase):
    """VT Scanner menu integrated into security intel CLI with UPLOAD OPTIONS"""
    scanner = VTScanner(vt_db)

    while True:
        console.print(Panel("VirusTotal Scanner", style="cyan"))

        console.print("\n1. Scan single file")
        console.print("2. Scan multiple files from list")
        console.print("3. Scan file by hash")
        console.print("4. Upload file to VirusTotal")
        console.print("5. Forensic artifact collection")
        console.print("6. View VT statistics")
        console.print("7. View vendor performance")
        console.print("8. Import PowerShell data")
        console.print("9. Test VT CLI installation")
        console.print("10. Test scan with known file")
        console.print("11. Show Malicious Process Report")
        console.print("12. Update VT Filenames - Extract filenames from file paths")
        console.print("13. View Upload Statistics")
        console.print("14. Return to main menu")
        console.print("15. Exit")

        choice = Prompt.ask("Select option",
                          choices=["1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                                 "11", "12", "13", "14", "15"],
                          default="1")

        if choice == "1":
            _handle_single_file_scan(scanner)

        elif choice == "2":
            _handle_multiple_files_scan(scanner)

        elif choice == "3":
            _handle_hash_scan(scanner)

        elif choice == "4":
            _handle_file_upload(scanner)

        elif choice == "5":
            _handle_forensic_collection(scanner)

        elif choice == "6":
            _handle_vt_statistics(vt_db)

        elif choice == "7":
            _handle_vendor_performance(vt_db)

        elif choice == "8":
            _handle_powershell_import(vt_db)

        elif choice == "9":
            _handle_vt_cli_test(scanner)

        elif choice == "10":
            _handle_known_file_test(scanner)

        elif choice == "11":
            _handle_malicious_process_report(scanner)

        elif choice == "12":
            _handle_update_filenames(scanner)

        elif choice == "13":
            _handle_upload_statistics(vt_db)

        elif choice == "14":
            break

        elif choice == "15":
            console.print("[yellow]Exiting...[/yellow]")
            sys.exit(0)

        if choice not in ["14", "15"]:
            Prompt.ask("\nPress Enter to continue")


def _handle_single_file_scan(scanner: VTScanner):
    """Handle single file scanning"""
    file_path = Prompt.ask("Enter file path to scan")
    if Path(file_path).exists():
        result = scanner.scan_file(file_path, allow_upload=True)
        if result:
            console.print(f"\n[green]Scan completed![/green]")
            console.print(f"  File Name: {result.get('file_name', 'N/A')}")
            console.print(f"  SHA256: {result.get('sha256', 'N/A')}")
            console.print(f"  Status: {result.get('status', 'unknown')}")
            console.print(f"  Malicious: {result.get('malicious', 0)}")
            console.print(f"  Suspicious: {result.get('suspicious', 0)}")
            console.print(f"  Harmless: {result.get('harmless', 0)}")
            console.print(f"  Undetected: {result.get('undetected', 0)}")
            if result.get('cached'):
                console.print(f"  [yellow]Using cached results[/yellow]")

            # Track the scan
            scanner.vt_db.track_vt_run(
                scan_type='single_file',
                files_processed=1,
                successfully_scanned=0 if result.get('cached') else 1,
                new_scans=0 if result.get('cached') else 1,
                malicious_count=1 if result.get('malicious', 0) > 5 else 0,
                clean_count=1 if result.get('malicious', 0) <= 5 else 0,
                cached_count=1 if result.get('cached') else 0,
                errors_count=0
            )
        else:
            console.print("[red]Scan failed![/red]")
            # Track failed scan
            scanner.vt_db.track_vt_run(
                scan_type='single_file',
                files_processed=1,
                errors_count=1
            )
    else:
        console.print("[red]File not found![/red]")


def _handle_multiple_files_scan(scanner: VTScanner):
    """Handle multiple files scanning"""
    file_list_path = Prompt.ask("Enter path to file list")
    if Path(file_list_path).exists():
        with open(file_list_path, 'r') as f:
            file_paths = [line.strip() for line in f if line.strip()]

        console.print(f"[cyan]Found {len(file_paths)} files to scan[/cyan]")
        allow_upload = Confirm.ask("Allow uploading files not found in VT?")
        results = scanner.scan_multiple_files(file_paths, allow_upload=allow_upload)

        console.print(f"\n[green]Batch scan completed![/green]")
        console.print(f"  Total files: {results['total']}")
        console.print(f"  Successfully scanned: {results['scanned']}")
        console.print(f"  Malicious: {results['malicious']}")
        console.print(f"  Clean: {results['clean']}")
        console.print(f"  Not found: {results['not_found']}")
        console.print(f"  Uploaded: {results['uploaded']}")
        console.print(f"  Cached: {results['cached']}")
        console.print(f"  Errors: {results['errors']}")
    else:
        console.print("[red]File list not found![/red]")


def _handle_hash_scan(scanner: VTScanner):
    """Handle file scanning by hash"""
    sha256 = Prompt.ask("Enter SHA256 hash to scan")
    result = scanner.scan_hash(sha256)
    if result:
        console.print(f"\n[green]Hash scan completed![/green]")
        console.print(f"  SHA256: {sha256}")
        console.print(f"  Status: {result.get('status', 'unknown')}")
        if result.get('status') != 'not_found':
            console.print(f"  Malicious: {result.get('malicious', 0)}")
            console.print(f"  Suspicious: {result.get('suspicious', 0)}")
            console.print(f"  Harmless: {result.get('harmless', 0)}")
            console.print(f"  Undetected: {result.get('undetected', 0)}")

        # Track the scan
        scanner.vt_db.track_vt_run(
            scan_type='file_hash',
            files_processed=1,
            successfully_scanned=1 if result.get('status') == 'scanned' else 0,
            malicious_count=1 if result.get('malicious', 0) > 5 else 0,
            clean_count=1 if result.get('status') == 'scanned' and result.get('malicious', 0) <= 5 else 0,
            errors_count=0
        )
    else:
        console.print("[red]Hash scan failed![/red]")
        # Track failed scan
        scanner.vt_db.track_vt_run(
            scan_type='file_hash',
            files_processed=1,
            errors_count=1
        )


def _handle_file_upload(scanner: VTScanner):
    """Handle direct file upload to VirusTotal"""
    file_path = Prompt.ask("Enter file path to upload")
    if Path(file_path).exists():
        result = scanner.upload_file(file_path)
        if result:
            console.print(f"[green]Upload successful![/green]")
            if result.get('status') == 'scanned':
                console.print(f"  Malicious: {result.get('malicious', 0)}")
                console.print(f"  Clean: {result.get('harmless', 0)}")
        else:
            console.print("[red]Upload failed![/red]")
    else:
        console.print("[red]File not found![/red]")


def _handle_forensic_collection(scanner: VTScanner):
    """Handle forensic artifact collection"""
    # Note: forensic_collection_menu handles its own tracking through scan_multiple_files
    forensic_collection_menu(scanner)


def _handle_vt_statistics(vt_db: VTDatabase):
    """Display VT statistics"""
    view_vt_statistics(vt_db)


def _handle_vendor_performance(vt_db: VTDatabase):
    """Display vendor performance"""
    view_vendor_performance(vt_db)


def _handle_powershell_import(vt_db: VTDatabase):
    """Handle PowerShell data import"""
    import_powershell_data(vt_db)


def _handle_vt_cli_test(scanner: VTScanner):
    """Test VT CLI installation"""
    scanner.test_vt_cli()


def _handle_known_file_test(scanner: VTScanner):
    """Test scan with known file"""
    scanner.test_scan_known_file()


def _handle_malicious_process_report(scanner: VTScanner):
    """Show malicious process report"""
    scanner.malicious_process_report()


def _handle_update_filenames(scanner: VTScanner):
    """Update VT filenames from file paths"""
    scanner.update_vt_filenames()


def _handle_upload_statistics(vt_db: VTDatabase):
    """Display upload statistics"""
    show_upload_statistics(vt_db)


def show_welcome_banner():
    """Display welcome banner for VT Scanner"""
    console.print(Panel.fit(
        "VirusTotal Scanner Module\n"
        "Integrated Security Intelligence CLI\n"
        "Now with File Upload Capability",
        style="cyan bold"
    ))


def get_menu_options() -> List[str]:
    """Return available menu options for integration with main CLI"""
    return [
        "Scan single file",
        "Scan multiple files from list",
        "Scan file by hash",
        "Upload file to VirusTotal",
        "Forensic artifact collection",
        "View VT statistics",
        "View vendor performance",
        "Import PowerShell data",
        "Test VT CLI installation",
        "Test scan with known file",
        "Show Malicious Process Report",
        "Update VT Filenames",
        "View Upload Statistics"
    ]
