"""
VirusTotal Reports Module
Handles all reporting, statistics display, and data visualization.
"""

import json
from typing import List, Dict

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Confirm
from rich import box

from constants import (
    PAGE_SIZE,
    EXCLUDED_VENDORS,
    VT_VENDOR_CONSENSUS_THRESHOLD,
    VT_VENDOR_MIN_DETECTIONS,
    VT_VENDOR_MAX_FP_RATE
)
from vt_db import VTDatabase

console = Console()


def view_vt_statistics(vt_db: VTDatabase):
    """Display VT statistics with pagination"""
    console.print(Panel("VirusTotal Statistics", style="cyan"))

    stats = vt_db.get_stats()

    console.print(f"\n[cyan]Database Statistics:[/cyan]")
    console.print(f"  Total file hashes: {stats['total_hashes']}")
    console.print(f"  Malicious files: {stats['malicious_hashes']}")
    console.print(f"  Total VT scans: {stats['total_scans']}")
    console.print(f"  Vendors tracked: {stats['total_vendors']}")
    console.print(f"  Total uploads: {stats['total_uploads']}")
    console.print(f"  Uploads today: {stats['uploads_today']}/{stats['uploads_remaining'] + stats['uploads_today']}")

    # Show malicious files
    malicious = vt_db.get_malicious_hashes()

    if malicious:
        console.print(f"\n[red bold]Malicious Files ({len(malicious)} total):[/red bold]")

        # Pagination settings
        page_size = PAGE_SIZE
        current_page = 0
        total_pages = (len(malicious) + page_size - 1) // page_size

        while current_page < total_pages:
            start_idx = current_page * page_size
            end_idx = min(start_idx + page_size, len(malicious))
            page_items = malicious[start_idx:end_idx]

            # Create table for current page
            table = Table(box=box.ROUNDED)
            table.add_column("SHA256", style="red", no_wrap=False, max_width=65)
            table.add_column("File Name", style="cyan", no_wrap=False, max_width=30)
            table.add_column("Status", style="white")
            table.add_column("Detections", style="yellow", justify="right")
            table.add_column("File Paths", style="white", no_wrap=False, max_width=80)

            for item in page_items:
                sha256_full = item['sha256']
                file_name = item.get('file_name', 'N/A')
                paths = vt_db.get_file_paths(item['sha256'])
                path_str = "\n".join(paths[:2]) if paths else "N/A"

                table.add_row(
                    sha256_full[:65] + "...",
                    file_name,
                    item['status'],
                    str(item['max_malicious']),
                    path_str
                )

            console.print(table)

            # Show pagination info
            console.print(f"\n[cyan]Page {current_page + 1} of {total_pages} "
                         f"(showing {start_idx + 1}-{end_idx} of {len(malicious)})[/cyan]")

            # Ask to continue
            if current_page < total_pages - 1:
                if Confirm.ask("Show next page?"):
                    current_page += 1
                    console.print()
                else:
                    break
            else:
                console.print("[green]End of results[/green]")
                break
    else:
        console.print("[green]No malicious files detected![/green]")


def view_vendor_performance(vt_db: VTDatabase):
    """Display vendor reliability statistics"""
    console.print(Panel("Vendor Performance Report", style="cyan"))
    console.print(f"[dim]False Positive Logic: Vendors that detect files with <{VT_VENDOR_CONSENSUS_THRESHOLD} other vendors agreeing are flagged as potential false positives.[/dim]\n")

    vendors = vt_db.get_vendor_stats()

    if not vendors:
        console.print("[yellow]No vendor data available[/yellow]")
        return

    # Sort by reliability (highest first), then by detection count
    vendors_sorted = sorted(vendors, key=lambda x: (x['reliability_score'], x['total_detections']), reverse=True)

    # Get list of unreliable vendor names for highlighting
    unreliable_names = set(vt_db.get_unreliable_vendors())

    table = Table(title=f"Vendor Performance ({len(vendors)} total)", box=box.ROUNDED)
    table.add_column("Vendor", style="cyan")
    table.add_column("Detections", style="white", justify="right")
    table.add_column("Likely FPs", style="yellow", justify="right")
    table.add_column("FP Rate", style="white", justify="right")
    table.add_column("Reliability", style="white", justify="right")
    table.add_column("Status", style="white")

    for vendor in vendors_sorted:  # Show ALL vendors
        fp_rate = (vendor['false_positive_estimate'] / vendor['total_detections'] * 100) if vendor['total_detections'] > 0 else 0.0

        # Color code reliability
        reliability_score = vendor['reliability_score']
        is_unreliable = vendor['vendor_name'] in unreliable_names

        if reliability_score >= 0.9:
            reliability_str = f"[green]{reliability_score:.2%}[/green]"
            status = "[green]Reliable[/green]"
        elif reliability_score >= 0.7:
            reliability_str = f"[yellow]{reliability_score:.2%}[/yellow]"
            status = "[yellow]Moderate[/yellow]"
        else:
            reliability_str = f"[red]{reliability_score:.2%}[/red]"
            status = "[red]Unreliable[/red]"

        # Mark unreliable vendors (those meeting the threshold)
        unreliable_marker = " [red](!)[/red]" if is_unreliable else ""
        excluded = " [dim](Excluded)[/dim]" if vendor['vendor_name'] in EXCLUDED_VENDORS else ""

        table.add_row(
            vendor['vendor_name'] + unreliable_marker + excluded,
            str(vendor['total_detections']),
            str(vendor['false_positive_estimate']),
            f"{fp_rate:.1f}%",
            reliability_str,
            status
        )

    console.print(table)

    # Show unreliable vendors summary
    unreliable = vt_db.get_unreliable_vendors()
    if unreliable:
        console.print(f"\n[red]WARNING: {len(unreliable)} unreliable vendors detected (>{VT_VENDOR_MAX_FP_RATE:.0%} FP rate with {VT_VENDOR_MIN_DETECTIONS}+ detections)[/red]")
        console.print(f"[dim]Unreliable vendors: {', '.join(unreliable[:10])}{' ...' if len(unreliable) > 10 else ''}[/dim]")


def show_malicious_process_report(vt_db: VTDatabase):
    """Generate a report of malicious processes and their associated files"""
    console.print(Panel("Malicious Process Report", style="red"))

    cursor = vt_db.conn.cursor()

    cursor.execute('''
        SELECT
            fh.sha256,
            fh.status,
            fh.max_malicious,
            fh.total_scans,
            fp.file_path,
            GROUP_CONCAT(DISTINCT ip.process_name) as process_names
        FROM file_hashes fh
        INNER JOIN file_paths fp ON fh.sha256 = fp.sha256
        LEFT JOIN ip_processes ip ON LOWER(ip.process_name) = LOWER(fp.file_name)
        WHERE fh.max_malicious > 0
        GROUP BY fh.sha256, fp.file_path
        ORDER BY fh.max_malicious DESC
    ''')

    results = cursor.fetchall()

    if not results:
        console.print("[green]No malicious files detected![/green]")
        return

    console.print(f"[red bold]Found {len(results)} malicious file hashes[/red bold]\n")

    # Create table for malicious files
    table = Table(title="Malicious Files and Associated Processes", box=box.ROUNDED, expand=True)
    table.add_column("SHA256", style="red", no_wrap=False, max_width=60)
    table.add_column("Status", style="white")
    table.add_column("Detections", style="yellow", justify="right")
    table.add_column("Processes", style="cyan", no_wrap=False)
    table.add_column("File Paths", style="white", no_wrap=False)

    for row in results:
        sha256 = row[0]
        status = row[1]
        max_malicious = row[2]
        file_path = row[4]
        process_names = row[5] if row[5] else "0 Connection established"

        table.add_row(
            sha256[:16] + "...",
            status,
            str(max_malicious),
            process_names,
            file_path
        )

    console.print(table)

    # Show summary statistics
    cursor.execute('''
        SELECT COUNT(DISTINCT ip.process_name)
        FROM file_hashes fh
        INNER JOIN file_paths fp ON fh.sha256 = fp.sha256
        INNER JOIN ip_processes ip ON LOWER(ip.process_name) = LOWER(fp.file_name)
        WHERE fh.max_malicious > 0
    ''')
    unique_processes = cursor.fetchone()[0]

    console.print(f"\n[cyan]Summary Statistics:[/cyan]")
    console.print(f"  Total malicious files: {len(results)}")
    console.print(f"  Unique processes involved: {unique_processes}")

    if unique_processes > 0:
        cursor.execute('''
            SELECT DISTINCT ip.process_name
            FROM file_hashes fh
            INNER JOIN file_paths fp ON fh.sha256 = fp.sha256
            INNER JOIN ip_processes ip ON LOWER(ip.process_name) = LOWER(fp.file_name)
            WHERE fh.max_malicious > 0
            ORDER BY ip.process_name
            LIMIT 10
        ''')

        console.print(f"\n[cyan]Processes involved in malicious activity:[/cyan]")
        for row in cursor.fetchall():
            console.print(f"  - {row[0]}")


def malicious_process_report(vt_db: VTDatabase):
    """Show processes associated with malicious files"""
    console.print(Panel("Malicious Process Report", style="red"))

    if not vt_db.conn:
        console.print("[yellow]Database not connected.[/yellow]")
        return

    cursor = vt_db.conn.cursor()

    # Get malicious processes with their latest VT scan
    cursor.execute('''
        SELECT
            ip_processes.process_name AS process_name,
            COUNT(DISTINCT ip_processes.ip_address) AS ip_count,
            file_hashes.sha256,
            MAX(vt_scan_history.malicious) AS max_detections,
            file_hashes.total_scans,
            (SELECT detecting_vendors
            FROM vt_scan_history
            WHERE vt_scan_history.sha256 = file_hashes.sha256
            ORDER BY scan_timestamp DESC
            LIMIT 1) AS latest_vendors
        FROM ip_processes
        INNER JOIN file_paths ON LOWER(ip_processes.process_name) = LOWER(file_paths.file_name)
        INNER JOIN file_hashes ON file_paths.sha256 = file_hashes.sha256
        INNER JOIN vt_scan_history ON file_hashes.sha256 = vt_scan_history.sha256
        WHERE vt_scan_history.malicious > 0
        GROUP BY ip_processes.process_name, file_hashes.sha256
        ORDER BY max_detections DESC, ip_count DESC
    ''')

    results = cursor.fetchall()

    if not results:
        console.print("[green]No malicious processes found with VT data[/green]")
        return

    console.print(f"[red bold]Found {len(results)} malicious process-hash combinations[/red bold]\n")

    table = Table(box=box.ROUNDED)
    table.add_column("Process Name", style="red bold")
    table.add_column("IPs", style="yellow", justify="right")
    table.add_column("SHA256", style="white", max_width=20)
    table.add_column("Detections", style="red", justify="right")
    table.add_column("Total Scans", style="white", justify="right")
    table.add_column("Top Vendors", style="dim", max_width=40)

    for row in results:
        # Parse vendor JSON and show top 3
        vendors = json.loads(row[5]) if row[5] else []
        top_vendors = ", ".join(vendors[:3]) if vendors else "N/A"

        table.add_row(
            row[0],  # process_name
            str(row[1]),  # ip_count
            row[2][:16] + "...",  # sha256 truncated
            str(row[3]),  # max_detections
            str(row[4]),  # total_scans
            top_vendors
        )

    console.print(table)


def show_upload_statistics(vt_db: VTDatabase):
    """Display upload statistics"""
    console.print(Panel("Upload Statistics", style="cyan"))

    stats = vt_db.get_stats()
    console.print(f"\n[cyan]Upload Statistics:[/cyan]")
    console.print(f"  Uploads today: {stats['uploads_today']}/{stats['uploads_remaining'] + stats['uploads_today']}")
    console.print(f"  Remaining today: {stats['uploads_remaining']}")
    console.print(f"  Total uploads: {stats['total_uploads']}")

    # Show recent uploads
    cursor = vt_db.conn.cursor()
    cursor.execute('''
        SELECT
            u.upload_timestamp,
            u.upload_success,
            u.error_message,
            h.file_name
        FROM vt_uploads u
        LEFT JOIN file_hashes h ON u.sha256 = h.sha256
        ORDER BY u.upload_timestamp DESC
        LIMIT 10
    ''')

    recent_uploads = cursor.fetchall()

    if recent_uploads:
        console.print(f"\n[cyan]Recent Uploads (last 10):[/cyan]")

        table = Table(box=box.ROUNDED)
        table.add_column("Timestamp", style="dim")
        table.add_column("File Name", style="cyan")
        table.add_column("Status", style="white")
        table.add_column("Error", style="red", max_width=30)

        for upload in recent_uploads:
            timestamp = upload[0]
            success = upload[1]
            error = upload[2] or ""
            file_name = upload[3] or "Unknown"

            status = "[green]Success[/green]" if success else "[red]Failed[/red]"

            table.add_row(
                timestamp[:19],  # Truncate to remove milliseconds
                file_name,
                status,
                error
            )

        console.print(table)


def show_database_stats(vt_db: VTDatabase):
    """Display comprehensive database statistics"""
    console.print(Panel("Database Statistics", style="cyan"))

    stats = vt_db.get_stats()

    console.print(f"\n[cyan]Overall Statistics:[/cyan]")
    console.print(f"  Total file hashes: {stats['total_hashes']}")
    console.print(f"  Malicious files: {stats['malicious_hashes']}")
    console.print(f"  Total VT scans: {stats['total_scans']}")
    console.print(f"  Vendors tracked: {stats['total_vendors']}")
    console.print(f"  Total uploads: {stats['total_uploads']}")
    console.print(f"  Uploads today: {stats['uploads_today']}")

    # Get additional stats from database
    cursor = vt_db.conn.cursor()

    # File size statistics
    cursor.execute('''
        SELECT
            COUNT(*) as total_files,
            AVG(file_size) as avg_size,
            MAX(file_size) as max_size
        FROM file_hashes
        WHERE file_size IS NOT NULL
    ''')
    size_stats = cursor.fetchone()

    if size_stats and size_stats[0] > 0:
        console.print(f"\n[cyan]File Size Statistics:[/cyan]")
        console.print(f"  Files with size data: {size_stats[0]}")
        console.print(f"  Average file size: {size_stats[1] / 1024:.1f} KB")
        console.print(f"  Largest file: {size_stats[2] / (1024*1024):.1f} MB")

    # Scan type distribution
    cursor.execute('''
        SELECT
            scan_type,
            COUNT(*) as count
        FROM vt_scan_history
        GROUP BY scan_type
        ORDER BY count DESC
    ''')
    scan_types = cursor.fetchall()

    if scan_types:
        console.print(f"\n[cyan]Scan Type Distribution:[/cyan]")
        for scan_type, count in scan_types:
            console.print(f"  {scan_type or 'Unknown'}: {count}")

    # Recent activity
    cursor.execute('''
        SELECT
            COUNT(*) as recent_scans
        FROM vt_scan_history
        WHERE scan_timestamp > datetime('now', '-7 days')
    ''')
    recent_scans = cursor.fetchone()[0]

    console.print(f"\n[cyan]Recent Activity:[/cyan]")
    console.print(f"  Scans in last 7 days: {recent_scans}")
