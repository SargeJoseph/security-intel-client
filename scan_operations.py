"""
Scan Operations for Security Intelligence CLI Tool
Handles quick scan, full scan, and IP analysis operations
"""

import time
from datetime import datetime, timedelta
import json
from typing import List, Dict

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.prompt import Confirm, Prompt


from config import URLHAUS_DELAY, IPAPI_DELAY, IPQS_DELAY, URLHAUS_CACHE_DAYS, GEOIP_CACHE_DAYS
ABUSEIPDB_DELAY = 1.0  # seconds between AbuseIPDB API calls
ABUSEIPDB_CACHE_DAYS = 7
GREYNOISE_CACHE_DAYS = 30  # Extended cache to conserve API quota
IPQS_CACHE_DAYS = 14  # IPQualityScore cache period

console = Console()


def validate_ip_address(ip: str) -> bool:
    """Validate IPv4 address format"""
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit():
                return False
            num = int(part)
            if num < 0 or num > 255:
                return False
        return True
    except (ValueError, AttributeError):
        return False


def extract_unique_ips_from_db(db) -> list[str]:
    """
    Extract all unique IP addresses from both source and destination columns.
    Args:
        db: Database instance
    Returns:
        Sorted list of unique IP addresses
    """
    if not db.conn:
        return []

    cursor = db.conn.cursor()

    cursor.execute('''
        SELECT unique_source_ips, unique_dest_ips
        FROM security_events
        WHERE unique_source_ips IS NOT NULL OR unique_dest_ips IS NOT NULL
    ''')

    all_ips = set()

    for row in cursor.fetchall():
        if row['unique_source_ips']:
            all_ips.update(ip.strip() for ip in row['unique_source_ips'].split(',') if ip.strip())
        if row['unique_dest_ips']:
            all_ips.update(ip.strip() for ip in row['unique_dest_ips'].split(',') if ip.strip())

    return sorted(all_ips)


def single_ip_scan(db, threat_intel):
    """
    Scan and analyze a single user-provided IP address

    Args:
        db: Database instance
        threat_intel: ThreatIntelligence instance
    """
    console.print(Panel("Single IP Scan", style="cyan"))

    ip = Prompt.ask("Enter IP address to scan")

    if not ip:
        console.print("[yellow]No IP address provided[/yellow]")
        return

    # Validate IP format
    if not validate_ip_address(ip):
        console.print("[red]Invalid IP address format[/red]")
        console.print("[yellow]Please enter a valid IPv4 address (e.g., 192.168.1.1)[/yellow]")
        return

    console.print(f"[cyan]Analyzing IP: {ip}[/cyan]")

    # Get existing intelligence or start fresh
    intel = db.get_ip_intelligence(ip) or {}
    updates_made = False

    try:
        # 1. URLHAUS ANALYSIS
        if (hasattr(threat_intel, 'urlhaus_key') and threat_intel.urlhaus_key):
            if (not intel.get('urlhaus_checked') or
                intel.get('urlhaus_status') == 'error' or
                (intel.get('urlhaus_checked') and
                 datetime.fromisoformat(intel['urlhaus_checked']) <
                 datetime.now() - timedelta(days=URLHAUS_CACHE_DAYS))):

                console.print("[dim]🔍 Checking URLhaus...[/dim]")
                urlhaus_data = threat_intel.lookup_urlhaus(ip, threat_intel.urlhaus_key)
                intel['urlhaus_status'] = urlhaus_data['status']
                intel['urlhaus_details'] = urlhaus_data['details']
                intel['urlhaus_checked'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                updates_made = True
                time.sleep(URLHAUS_DELAY)

                if urlhaus_data['status'] == 'malicious':
                    console.print("[red]⚠ MALICIOUS activity detected by URLhaus[/red]")
        else:
            console.print("[dim]🔍 URLhaus not configured[/dim]")

        # 2. ABUSEIPDB ANALYSIS
        if (hasattr(threat_intel, 'abuseipdb_key') and
            threat_intel.abuseipdb_key and
            hasattr(threat_intel, 'lookup_abuseipdb')):

            if (not intel.get('abuseipdb_checked') or
                intel.get('abuseipdb_confidence_score') is None or
                (intel.get('abuseipdb_checked') and
                 datetime.fromisoformat(intel['abuseipdb_checked']) <
                 datetime.now() - timedelta(days=ABUSEIPDB_CACHE_DAYS))):

                console.print("[dim]🔍 Checking AbuseIPDB...[/dim]")
                abuseipdb_data = threat_intel.lookup_abuseipdb(ip, threat_intel.abuseipdb_key)

                if abuseipdb_data['status'] == 'success':
                    intel['abuseipdb_confidence_score'] = abuseipdb_data['confidence_score']
                    intel['abuseipdb_categories'] = json.dumps(abuseipdb_data['categories'])
                    intel['abuseipdb_total_reports'] = abuseipdb_data['total_reports']
                    intel['abuseipdb_checked'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    updates_made = True

                    console.print(f"[green]✓ AbuseIPDB confidence: {abuseipdb_data['confidence_score']}% ({abuseipdb_data['total_reports']} reports)[/green]")

                    # Also update ISP and country from AbuseIPDB if available
                    if abuseipdb_data.get('isp'):
                        intel['isp'] = abuseipdb_data.get('isp')
                    if abuseipdb_data.get('country'):
                        intel['country'] = abuseipdb_data.get('country')
                else:
                    # Store 0 to prevent NoneType comparison errors
                    intel['abuseipdb_confidence_score'] = 0
                    intel['abuseipdb_checked'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    updates_made = True
                    console.print("[yellow]⚠ AbuseIPDB lookup failed or no data[/yellow]")

                time.sleep(ABUSEIPDB_DELAY)
        else:
            console.print("[dim]🔍 AbuseIPDB not configured[/dim]")

        # 3. GEOIP ANALYSIS WITH PRIMARY SOURCE SELECTION
        if (not intel.get('geoip_checked') or
            (intel.get('geoip_checked') and
             datetime.fromisoformat(intel['geoip_checked']) <
             datetime.now() - timedelta(days=GEOIP_CACHE_DAYS))):

            console.print("[dim]🔍 Checking GeoIP with primary source selection...[/dim]")

            # Get AbuseIPDB confidence (if available)
            abuse_confidence = intel.get('abuseipdb_confidence_score', 0)
            has_abuse_data = intel.get('abuseipdb_checked') is not None

            # Get fresh GeoIP data
            geoip_data = threat_intel.lookup_geoip(ip)

            # PRIMARY SOURCE SELECTION LOGIC
            if abuse_confidence > 50 and has_abuse_data:
                # PRIMARY SOURCE: AbuseIPDB (confidence > 50%)
                console.print(f"[dim]🎯 Using AbuseIPDB as primary source (confidence: {abuse_confidence}%)[/dim]")
                intel['data_source'] = 'abuseipdb'

                # Country and ISP from AbuseIPDB (already set above), city from GeoIP
                if geoip_data.get('city'):
                    intel['city'] = geoip_data.get('city')
            else:
                # PRIMARY SOURCE: GeoIP (confidence ≤ 50% or no AbuseIPDB data)
                console.print("[dim]🎯 Using GeoIP as primary source[/dim]")
                intel['data_source'] = 'geoip'
                intel['country'] = geoip_data.get('country')
                intel['city'] = geoip_data.get('city')
                intel['isp'] = geoip_data.get('isp')

            intel['geoip_checked'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            updates_made = True
            time.sleep(IPAPI_DELAY)

        # 4. IPQS FRAUD SCORE
        # Only scan if URLhaus is malicious OR AbuseIPDB confidence > 50
        is_suspicious = (intel.get('urlhaus_status') == 'malicious' or
                       intel.get('abuseipdb_confidence_score', 0) > 50)

        if (hasattr(threat_intel, 'ipqs_key') and threat_intel.ipqs_key):
            if is_suspicious:
                if (not intel.get('ipqs_checked') or
                    (intel.get('ipqs_checked') and
                     datetime.fromisoformat(intel['ipqs_checked']) <
                     datetime.now() - timedelta(days=IPQS_CACHE_DAYS))):

                    console.print("[dim]🔍 Checking IPQualityScore...[/dim]")
                    ipqs_data = threat_intel.lookup_ipqs(ip, threat_intel.ipqs_key)

                    if ipqs_data['status'] == 'success':
                        intel['ipqs_fraud_score'] = ipqs_data.get('fraud_score', 0)
                        intel['ipqs_checked'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        updates_made = True
                        console.print(f"[green]✓ IPQS Fraud Score: {ipqs_data.get('fraud_score', 0)}[/green]")
                    else:
                        console.print("[yellow]⚠ IPQS lookup failed or no data[/yellow]")

                    time.sleep(IPQS_DELAY)
            else:
                console.print("[dim]🔍 IPQS skipped (IP not flagged by URLhaus or AbuseIPDB)[/dim]")
        else:
            console.print("[dim]🔍 IPQS not configured[/dim]")

        # 5. GREYNOISE ANALYSIS
        # Only scan if URLhaus is malicious OR AbuseIPDB confidence > 50
        is_suspicious = (intel.get('urlhaus_status') == 'malicious' or
                       intel.get('abuseipdb_confidence_score', 0) > 50)

        if is_suspicious:
            if (not intel.get('greynoise_checked') or
                (intel.get('greynoise_checked') and
                 datetime.fromisoformat(intel['greynoise_checked']) <
                 datetime.now() - timedelta(days=GREYNOISE_CACHE_DAYS))):

                console.print("[dim]🔍 Checking GreyNoise...[/dim]")
                greynoise_data = threat_intel.lookup_greynoise(ip)

                if greynoise_data['status'] in ('success', 'not_found'):
                    intel['greynoise_noise'] = greynoise_data.get('noise', False)
                    intel['greynoise_riot'] = greynoise_data.get('riot', False)
                    intel['greynoise_classification'] = greynoise_data.get('classification')
                    intel['greynoise_last_seen'] = greynoise_data.get('last_seen')
                    intel['greynoise_checked'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    updates_made = True

                    if greynoise_data['status'] == 'success':
                        console.print(f"[green]✓ GreyNoise classification: {greynoise_data.get('classification', 'unknown')}[/green]")
                    else:
                        console.print("[dim]GreyNoise: IP not seen in their database[/dim]")
                elif greynoise_data['status'] == 'rate_limit':
                    console.print("[yellow]⚠ GreyNoise rate limit exceeded (25/week for Community API)[/yellow]")
                    console.print("[dim]Consider upgrading to paid plan for higher limits[/dim]")
                else:
                    console.print("[yellow]⚠ GreyNoise lookup failed or no data[/yellow]")

                time.sleep(1.0)
        else:
            console.print("[dim]🔍 GreyNoise skipped (IP not flagged by URLhaus or AbuseIPDB)[/dim]")

        # 6. REVERSE DNS LOOKUP
        if not intel.get('reverse_dns') or intel.get('reverse_dns') == 'N/A':
            console.print("[dim]🔍 Performing reverse DNS lookup...[/dim]")
            intel['reverse_dns'] = threat_intel.reverse_dns(ip)
            intel['dns_checked'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            updates_made = True

        # UPDATE DATABASE WITH ALL COLLECTED INTELLIGENCE
        if updates_made:
            db.update_ip_intelligence(ip, intel)
            console.print("[green]✅ All threat intelligence updated in database[/green]")

        # DISPLAY COMPREHENSIVE RESULTS
        _display_individual_ip_summary(db, ip)

    except Exception as e:
        console.print(f"[red]❌ Error during IP analysis: {e}[/red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")


def read_applications_from_db(db) -> List[Dict]:
    """
    Read applications from database instead of CSV

    Args:
        db: Database instance

    Returns:
        List of application dictionaries
    """
    if not db.conn:
        return []

    cursor = db.conn.cursor()
    cursor.execute('''
        SELECT * FROM security_events
        ORDER BY total_connections DESC, total_connections DESC
    ''')
    return [dict(row) for row in cursor.fetchall()]


def quick_scan(db, threat_intel, interactive=True):
    """
    Scan only new/uncached IPs using database source

    Args:
        db: Database instance
        threat_intel: ThreatIntelligence instance
        interactive: If False, skip all user prompts (default: True)
    """
    # Track IPs scanned in this session
    scanned_ips = []

    console.print(Panel("Quick Scan - Analyzing new IPs from database", style="cyan"))

    # Get IPs from database instead of CSV
    all_ips = extract_unique_ips_from_db(db)
    console.print(f"Found {len(all_ips)} unique IPs in database")

    to_scan = []
    error_ips = []
    new_ips = []

    for ip in all_ips:
        intel = db.get_ip_intelligence(ip)
        if not intel:
            new_ips.append(ip)
            to_scan.append(ip)
        elif intel.get('urlhaus_status') == 'error':
            error_ips.append(ip)
            to_scan.append(ip)

    if not to_scan:
        console.print("[green]No new IPs to scan and no errors to retry![/green]")
        return

    console.print(f"[yellow]Found {len(new_ips)} new IPs to analyze[/yellow]")
    if error_ips:
        console.print(f"[yellow]Found {len(error_ips)} IPs with errors to retry[/yellow]")

    _analyze_ips(db, threat_intel, to_scan, scanned_ips, interactive=interactive)

def full_scan(db, threat_intel, interactive=True):
    """
    Re-analyze all IPs with stale data

    Args:
        db: Database instance
        threat_intel: ThreatIntelligence instance
        interactive: If False, skip all user prompts (default: True)
    """
    # Track IPs scanned in this session
    scanned_ips = []

    console.print(Panel("Full Scan - Refreshing all IP intelligence", style="cyan"))

    # Get IPs from database instead of CSV
    all_ips = extract_unique_ips_from_db(db)
    console.print(f"Found {len(all_ips)} unique IPs in database")

    stale_urlhaus = set(db.get_stale_ips('urlhaus', URLHAUS_CACHE_DAYS))
    stale_geoip = set(db.get_stale_ips('geoip', GEOIP_CACHE_DAYS))

    to_scan = list(stale_urlhaus | stale_geoip | set(all_ips))

    console.print(f"[yellow]Analyzing {len(to_scan)} IPs[/yellow]")

    _analyze_ips(db, threat_intel, to_scan, scanned_ips, interactive=interactive)

def _analyze_ips(db, threat_intel, ips: List[str], scanned_ips: List[str], interactive=True):
    """
    Analyze list of IPs with progress bar

    Args:
        db: Database instance
        threat_intel: ThreatIntelligence instance
        ips: List of IP addresses to analyze
        scanned_ips: List to track scanned IPs in this session
        interactive: If False, skip all user prompts (default: True)
    """
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:

        task = progress.add_task("Analyzing IPs...", total=len(ips))

        for ip in ips:
            progress.update(task, description=f"Analyzing {ip}")
            scanned_ips.append(ip)

            try:
                intel = db.get_ip_intelligence(ip) or {}
                updates_made = False

                # Check if URLhaus lookup is needed
                if hasattr(threat_intel, 'urlhaus_key') and threat_intel.urlhaus_key:
                    if not intel.get('urlhaus_checked') or \
                       intel.get('urlhaus_status') == 'error' or \
                       (intel.get('urlhaus_checked') and
                        datetime.fromisoformat(intel['urlhaus_checked']) <
                        datetime.now() - timedelta(days=URLHAUS_CACHE_DAYS)):

                        urlhaus_data = threat_intel.lookup_urlhaus(ip, threat_intel.urlhaus_key)
                        intel['urlhaus_status'] = urlhaus_data['status']
                        intel['urlhaus_details'] = urlhaus_data['details']
                        intel['urlhaus_checked'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        updates_made = True
                        time.sleep(URLHAUS_DELAY)

                # AbuseIPDB lookup - using URLhaus key for now
                if hasattr(threat_intel, 'abuseipdb_key') and threat_intel.abuseipdb_key and hasattr(threat_intel, 'lookup_abuseipdb'):
                    if (not intel.get('abuseipdb_checked') or
                        intel.get('abuseipdb_confidence_score') is None or
                        (intel.get('abuseipdb_checked') and
                         datetime.fromisoformat(intel['abuseipdb_checked']) <
                         datetime.now() - timedelta(days=ABUSEIPDB_CACHE_DAYS))):

                        abuseipdb_data = threat_intel.lookup_abuseipdb(ip, threat_intel.abuseipdb_key)
                        if abuseipdb_data['status'] == 'success':
                            intel['abuseipdb_confidence_score'] = abuseipdb_data['confidence_score']
                            intel['abuseipdb_categories'] = json.dumps(abuseipdb_data['categories'])
                            intel['abuseipdb_total_reports'] = abuseipdb_data['total_reports']
                            intel['abuseipdb_checked'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            # Also update additional fields from AbuseIPDB
                            if abuseipdb_data.get('usage_type'):
                                intel['usage_type'] = abuseipdb_data.get('usage_type')
                            if abuseipdb_data.get('domain'):
                                intel['domain'] = abuseipdb_data.get('domain')
                            updates_made = True
                        else:
                            # Store 0 to prevent NoneType comparison errors
                            intel['abuseipdb_confidence_score'] = 0
                            intel['abuseipdb_checked'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            updates_made = True

                        time.sleep(ABUSEIPDB_DELAY)



                # Check if GeoIP lookup is needed
                if not intel.get('geoip_checked') or \
                   (intel.get('geoip_checked') and
                    datetime.fromisoformat(intel['geoip_checked']) <
                    datetime.now() - timedelta(days=GEOIP_CACHE_DAYS)):

                    # Use enhanced GeoIP with primary source selection
                    abuse_confidence = intel.get('abuseipdb_confidence_score', 0)
                    has_abuse_data = intel.get('abuseipdb_checked') is not None
                    geoip_data = threat_intel.lookup_geoip(ip)

                    # PRIMARY SOURCE SELECTION LOGIC (same as single IP scan)
                    if abuse_confidence > 50 and has_abuse_data:
                        # Use AbuseIPDB as primary source
                        intel['data_source'] = 'abuseipdb'
                        # Country and ISP from AbuseIPDB (already set), city from GeoIP
                        intel['city'] = geoip_data.get('city')
                    else:
                        # Use GeoIP as primary source
                        intel['data_source'] = 'geoip'
                        intel['country'] = geoip_data.get('country')
                        intel['city'] = geoip_data.get('city')
                        intel['isp'] = geoip_data.get('isp')

                    intel['geoip_checked'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    updates_made = True
                    time.sleep(IPAPI_DELAY)

                # Check if IPQS lookup is needed
                # Only scan if URLhaus is malicious OR AbuseIPDB confidence > 50
                if hasattr(threat_intel, 'ipqs_key') and threat_intel.ipqs_key:
                    is_suspicious = (intel.get('urlhaus_status') == 'malicious' or
                                   intel.get('abuseipdb_confidence_score', 0) > 50)

                    if is_suspicious:
                        IPQS_CACHE_DAYS = 14 # Define cache period
                        if (not intel.get('ipqs_checked') or
                            (intel.get('ipqs_checked') and
                             datetime.fromisoformat(intel['ipqs_checked']) <
                             datetime.now() - timedelta(days=IPQS_CACHE_DAYS))):

                            ipqs_data = threat_intel.lookup_ipqs(ip, threat_intel.ipqs_key)

                            if ipqs_data['status'] == 'success':
                                intel['ipqs_fraud_score'] = ipqs_data.get('fraud_score', 0)
                                intel['ipqs_checked'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                updates_made = True

                            time.sleep(IPQS_DELAY) # Use delay from config

                # Check if GreyNoise lookup is needed
                # GreyNoise Community API: 25 requests/week limit - use sparingly!
                # Only scan if URLhaus is malicious OR AbuseIPDB confidence > 50
                is_suspicious = (intel.get('urlhaus_status') == 'malicious' or
                               intel.get('abuseipdb_confidence_score', 0) > 50)

                if is_suspicious:
                    GREYNOISE_CACHE_DAYS = 30 # Extended cache to conserve API quota
                    if (not intel.get('greynoise_checked') or
                        (intel.get('greynoise_checked') and
                         datetime.fromisoformat(intel['greynoise_checked']) <
                         datetime.now() - timedelta(days=GREYNOISE_CACHE_DAYS))):

                        greynoise_data = threat_intel.lookup_greynoise(ip)

                        if greynoise_data['status'] in ('success', 'not_found'):
                            intel['greynoise_noise'] = greynoise_data.get('noise', False)
                            intel['greynoise_riot'] = greynoise_data.get('riot', False)
                            intel['greynoise_classification'] = greynoise_data.get('classification')
                            intel['greynoise_last_seen'] = greynoise_data.get('last_seen')
                            intel['greynoise_checked'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            updates_made = True
                        elif greynoise_data['status'] == 'rate_limit':
                            console.print(f"\n[yellow]⚠ GreyNoise rate limit exceeded (25/week for Community API)[/yellow]")
                            break  # Stop scanning to avoid wasting API calls

                        time.sleep(1.0) # GreyNoise rate limit is ~1 req/sec

                # Check if reverse DNS is needed
                if not intel.get('reverse_dns') or intel.get('reverse_dns') == 'N/A':
                    intel['reverse_dns'] = threat_intel.reverse_dns(ip)
                    intel['dns_checked'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    updates_made = True

                # Update database if any changes were made
                if updates_made:
                    db.update_ip_intelligence(ip, intel)

            except Exception as e:
                console.print(f"\n[red]Error analyzing {ip}: {e}[/red]")

            progress.advance(task)

    console.print("[green]Analysis complete![/green]")

    # Display comprehensive summary
    _display_quick_scan_summary(db, threat_intel, scanned_ips, interactive=interactive)


def _display_quick_scan_summary(db, threat_intel, scanned_ips=None, interactive=True):
    """
    Display comprehensive summary of quick scan results

    Args:
        db: Database instance
        threat_intel: ThreatIntelligence instance
        scanned_ips: List of IPs scanned in this session
        interactive: If False, skip all user prompts (default: True)
    """

    # Get stats from database
    stats = db.get_stats()
    # total_ips = stats['total_ips']
    malicious_ips = stats['malicious_ips']

    console.print(Panel("📊 Quick Scan Summary", style="cyan"))

    # Get recent malicious IPs for display
    malicious_ips_list = _get_recent_malicious_ips(db)

    # Create summary table
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="cyan", width=20)
    table.add_column("Count", style="white", width=10)
    table.add_column("Details", style="yellow")

    # Total IPs row
    # table.add_row("Total IPs Analyzed", str(total_ips), "All IPs in database")

    # Malicious IPs row
    if malicious_ips > 0:
        table.add_row("Malicious IPs", f"[red bold]{malicious_ips}[/red bold]", "High risk IPs detected")
    else:
        table.add_row("Malicious IPs", "[green]0[/green]", "No high risk IPs")

    # Recent threats row
    if malicious_ips_list:
        threat_details = f"{len(malicious_ips_list)} recent threats"
        table.add_row("Recent Threats", f"[red]{len(malicious_ips_list)}[/red]", threat_details)
    else:
        table.add_row("Recent Threats", "[green]0[/green]", "No recent threats")

    console.print(table)

    # Show individual intelligence for newly scanned IPs
    if scanned_ips:
        _display_newly_scanned_intelligence(db, scanned_ips)

    # Show recent malicious IPs if any
    if malicious_ips_list:
        console.print("\n[red bold]⚠ Recent Malicious IPs:[/red bold]")
        threat_table = Table(box=box.SIMPLE, show_header=True, header_style="red")
        threat_table.add_column("IP Address", style="red bold")
        threat_table.add_column("Threat Source", style="white")
        threat_table.add_column("Country", style="yellow")
        threat_table.add_column("Last Seen", style="dim")

        for ip_info in malicious_ips_list[:5]:  # Show top 5
            threat_table.add_row(
                ip_info['ip_address'],
                ip_info['threat_source'],
                ip_info.get('country', 'N/A'),
                ip_info.get('last_seen', 'N/A')[:19] if ip_info.get('last_seen') else 'N/A'
            )

        console.print(threat_table)

        if len(malicious_ips_list) > 5:
            console.print(f"[dim]... and {len(malicious_ips_list) - 5} more malicious IPs[/dim]")

    # Show individual intelligence for recently scanned malicious IPs
    _display_recent_malicious_intelligence(db, malicious_ips_list, interactive=interactive)


def _get_recent_malicious_ips(db, limit: int = 10):
    """
    Get recently detected malicious IPs from database
    """
    if not db.conn:
        return []

    cursor = db.conn.cursor()

    # Get IPs with malicious activity (URLhaus or high AbuseIPDB score)
    query = (
        "SELECT ip_address, urlhaus_status, abuseipdb_confidence_score, "
        "country, isp, last_seen FROM ip_intelligence "
        "WHERE urlhaus_status = 'malicious' OR abuseipdb_confidence_score > 80 "
        "ORDER BY last_seen DESC LIMIT ?"
    )
    cursor.execute(query, (limit,))

    results = []
    for row in cursor.fetchall():
        ip_info = dict(row)

        # Determine threat source
        if ip_info.get('urlhaus_status') == 'malicious':
            threat_source = 'URLhaus'
        elif ip_info.get('abuseipdb_confidence_score', 0) > 80:
            threat_source = f"AbuseIPDB ({ip_info['abuseipdb_confidence_score']}%)"
        else:
            threat_source = 'Unknown'

        results.append({
            'ip_address': ip_info['ip_address'],
            'threat_source': threat_source,
            'country': ip_info.get('country'),
            'last_seen': ip_info.get('last_seen')
        })

    return results


def _display_individual_ip_summary(db, ip: str):
    """
    Display comprehensive intelligence for a single IP (same as single IP scan)
    """

    # Get intelligence from database
    intel = db.get_ip_intelligence(ip)
    if not intel:
        console.print(f"[yellow]No intelligence data found for {ip}[/yellow]")
        return

    console.print(Panel(f"📊 IP Intelligence: {ip}", style="cyan"))

    # Create comprehensive table (same as single IP scan)
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta")
    table.add_column("Source", style="cyan", width=12)
    table.add_column("Status", style="white", width=20)
    table.add_column("Details", style="yellow")
    table.add_column("IPQS Score", style="magenta", justify="right")

    # URLHAUS ROW
    urlhaus_status = intel.get('urlhaus_status', 'Not checked')
    status_style = {
        'malicious': '[red bold]MALICIOUS[/red bold]',
        'clean': '[green]Clean[/green]',
        'unknown': '[yellow]Unknown[/yellow]',
        'error': '[dim]Error[/dim]'
    }.get(urlhaus_status, f'[white]{urlhaus_status}[/white]')

    urlhaus_details = ""
    if urlhaus_status == 'malicious' and intel.get('urlhaus_details'):
        try:
            details = json.loads(intel['urlhaus_details'])
            if 'urls' in details:
                urlhaus_details = f"{len(details['urls'])} malicious URLs"
        except:
            urlhaus_details = "Malicious activity detected"

    table.add_row("URLhaus", status_style, urlhaus_details)

    # ABUSEIPDB ROW
    abuse_score = intel.get('abuseipdb_confidence_score')
    if abuse_score is not None:
        if abuse_score > 80:
            abuse_style = "[red bold]High Risk[/red bold]"
        elif abuse_score > 50:
            abuse_style = "[yellow]Suspicious[/yellow]"
        else:
            abuse_style = "[green]Low Risk[/green]"

        reports = intel.get('abuseipdb_total_reports', 0)
        abuse_details = f"{reports} reports"

        # Show categories if available
        categories_json = intel.get('abuseipdb_categories')
        if categories_json:
            try:
                categories = json.loads(categories_json)
                if categories:
                    abuse_details += f" | Categories: {', '.join(map(str, categories[:2]))}"
                    if len(categories) > 2:
                        abuse_details += "..."
            except:
                pass
    else:
        abuse_style = "[dim]Not checked[/dim]"
        abuse_details = "No API key or data"

    table.add_row("AbuseIPDB", abuse_style, abuse_details)

    # IPQS ROW
    ipqs_score = intel.get('ipqs_fraud_score')
    if ipqs_score is not None:
        if ipqs_score >= 85:
            ipqs_style = "[red bold]High Risk[/red bold]"
        elif ipqs_score >= 75:
            ipqs_style = "[yellow]Suspicious[/yellow]"
        else:
            ipqs_style = "[green]Low Risk[/green]"
        ipqs_details = f"Score: {ipqs_score}"
    else:
        ipqs_style = "[dim]Not checked[/dim]"
        ipqs_details = "N/A"

    table.add_row("IPQualityScore", ipqs_style, ipqs_details)

    # GREYNOISE ROW
    classification = intel.get('greynoise_classification')
    if classification:
        if classification == 'malicious':
            gn_style = "[red bold]Malicious[/red bold]"
        elif classification == 'benign':
            gn_style = "[green]Benign[/green]"
        else:
            gn_style = f"[yellow]{classification.title()}[/yellow]"
        gn_details = f"Last Seen: {intel.get('greynoise_last_seen', 'N/A')}"
    else:
        gn_style = "[dim]Not checked[/dim]"
        gn_details = "N/A"

    table.add_row("GreyNoise", gn_style, gn_details)

    # GEOIP ROW
    country = intel.get('country', 'N/A')
    city = intel.get('city', 'N/A')
    isp = intel.get('isp', 'N/A')
    data_source = intel.get('data_source', 'geoip')

    geo_details = f"{country}"
    if city != 'N/A':
        geo_details += f", {city}"
    if isp != 'N/A':
        geo_details += f" | {isp}"

    source_indicator = "🎯" if data_source == 'abuseipdb' else "📍"
    geo_style = f"[blue]{source_indicator} {data_source.title()}[/blue]"

    table.add_row("Location", geo_style, geo_details)

    # REVERSE DNS ROW
    reverse_dns = intel.get('reverse_dns', 'N/A')
    table.add_row("DNS", "[cyan]Resolved[/cyan]", reverse_dns)

    console.print(table)

    # Data source explanation
    data_source = intel.get('data_source', 'geoip')
    if data_source == 'abuseipdb':
        console.print(f"\n[dim]📍 Location data source: AbuseIPDB (confidence > 50%)[/dim]")
    else:
        console.print(f"\n[dim]📍 Location data source: GeoIP[/dim]")

    # Last checked timestamp
    if intel.get('last_seen'):
        console.print(f"[dim]🕒 Last updated: {intel.get('last_seen', 'N/A')[:19]}[/dim]")

    console.print("")  # Empty line for separation



def _display_recent_malicious_intelligence(db, malicious_ips_list, interactive=True):
    """
    Display comprehensive intelligence for recently scanned malicious IPs

    Args:
        db: Database instance
        malicious_ips_list: List of malicious IPs to display
        interactive: If False, skip user prompts (default: True)
    """

    if not malicious_ips_list:
        return

    console.print("\n" + "="*60)
    console.print(Panel("🔍 Individual IP Intelligence Details", style="cyan"))

    # Show individual summaries for malicious IPs
    for ip_info in malicious_ips_list[:3]:  # Show details for first 3 malicious IPs
        ip_address = ip_info['ip_address']
        console.print(f"\n[bold]Detailed analysis for: {ip_address}[/bold]")
        _display_individual_ip_summary(db, ip_address)

    # Ask if user wants to see more
    if len(malicious_ips_list) > 3:
        if interactive and Confirm.ask(f"Show details for remaining {len(malicious_ips_list) - 3} malicious IPs?"):
            for ip_info in malicious_ips_list[3:]:
                ip_address = ip_info['ip_address']
                console.print(f"\n[bold]Detailed analysis for: {ip_address}[/bold]")
                _display_individual_ip_summary(db, ip_address)



def _display_newly_scanned_intelligence(db, scanned_ips, interactive=True):
    """
    Display comprehensive intelligence for IPs scanned in this session

    Args:
        db: Database instance
        scanned_ips: List of IPs scanned in this session
        interactive: If False, skip user prompts (default: True)
    """

    console.print("\n" + "="*60)
    console.print(Panel("🔄 Newly Scanned IP Intelligence", style="green"))
    console.print(f"[dim]Showing intelligence for {len(scanned_ips)} IPs scanned in this session[/dim]")

    # Show individual summaries for scanned IPs
    display_count = min(5, len(scanned_ips))  # Show max 5 IPs by default

    for i, ip_address in enumerate(scanned_ips[:display_count]):
        console.print(f"\n[bold]{i+1}/{len(scanned_ips)}: Detailed analysis for {ip_address}[/bold]")
        _display_individual_ip_summary(db, ip_address)

    # Ask if user wants to see more
    if len(scanned_ips) > display_count:
        remaining = len(scanned_ips) - display_count
        if interactive and Confirm.ask(f"Show details for remaining {remaining} scanned IPs?"):
            for i, ip_address in enumerate(scanned_ips[display_count:], display_count + 1):
                console.print(f"\n[bold]{i}/{len(scanned_ips)}: Detailed analysis for {ip_address}[/bold]")
                _display_individual_ip_summary(db, ip_address)
