#!/usr/bin/env python3
"""
IP Operations Module
Handles IP search and threat summary functionality
"""

import json
from typing import TYPE_CHECKING, List, Dict
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich import box

if TYPE_CHECKING:
    from database import Database


console = Console()


class IPOperations:
    """Handles IP search and threat summary operations"""

    def __init__(self, db: 'Database', threat_intel):
        """
        Initialize IP operations handler

        Args:
            db: Database instance
            threat_intel: ThreatIntelligence instance
        """
        self.db = db
        self.threat_intel = threat_intel

    def search_ip(self):
        """Deep dive on specific IP"""
        ip = Prompt.ask("Enter IP address to search")

        console.print(Panel(f"IP Intelligence: {ip}", style="cyan"))

        intel = self.db.get_ip_intelligence(ip)
        if not intel:
            console.print("[yellow]IP not in database, fetching intelligence...[/yellow]")
            self._analyze_single_ip(ip)
            intel = self.db.get_ip_intelligence(ip)

        if intel:
            self._display_ip_intelligence(intel)

    def _display_ip_intelligence(self, intel: dict):
        """Display IP intelligence information"""
        status = intel.get('urlhaus_status', 'unknown')

        # Display threat status
        if status == 'malicious':
            console.print("[red bold]WARNING: URLhaus Status: MALICIOUS[/red bold]")
            if intel.get('urlhaus_details'):
                try:
                    details = json.loads(intel['urlhaus_details'])
                    if 'urls' in details and details['urls']:
                        console.print(f"  Associated URLs: {len(details['urls'])}")
                        # Display threat information from URLs
                        threats = set()
                        for url_entry in details['urls']:
                            if 'threat' in url_entry and url_entry['threat']:
                                threats.add(url_entry['threat'])
                        if threats:
                            console.print(f"  Threats: {', '.join(sorted(threats))}")
                except (json.JSONDecodeError, TypeError):
                    pass
        elif status == 'clean':
            console.print("[green]OK: URLhaus Status: Clean[/green]")
        else:
            console.print(f"[yellow]URLhaus Status: {status}[/yellow]")

        # Display geographic information
        console.print(f"\n[cyan]Geographic Info:[/cyan]")
        console.print(f"  Country: {intel.get('country', 'N/A')}")
        console.print(f"  City: {intel.get('city', 'N/A')}")
        console.print(f"  ISP: {intel.get('isp', 'N/A')}")

        # Display reverse DNS
        console.print(f"\n[cyan]Reverse DNS:[/cyan] {intel.get('reverse_dns', 'N/A')}")

    def _export_events_to_csv(self, events: List[Dict], ip: str):
        """Export events to CSV file"""
        import csv
        from datetime import datetime
        from pathlib import Path

        # Create filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_ip = ip.replace('.', '_').replace(':', '_')
        filename = f"IP_Search_Results_{safe_ip}_{timestamp}.csv"

        # Use OUTPUT directory from config
        from config import OUTPUT_DIR
        csv_path = OUTPUT_DIR / filename

        try:
            with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
                # Define field names for CSV
                fieldnames = [
                    'Timestamp', 'Event_ID', 'Process', 'Direction',
                    'Local_IP', 'Local_Port', 'Remote_IP', 'Remote_Port',
                    'Protocol', 'Filter_Reason', 'Layer', 'Action'
                ]

                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for event in events:
                    # Translate Windows codes for CSV export
                    direction = self._translate_windows_codes(event.get('direction', 'N/A'))
                    protocol = self._translate_windows_codes(event.get('protocol', 'N/A'))
                    filter_reason = self._translate_windows_codes(event.get('filter_reason', 'N/A'))
                    layer = self._translate_windows_codes(event.get('layer', 'N/A'))

                    writer.writerow({
                        'Timestamp': event.get('timestamp', 'N/A'),
                        'Event_ID': event.get('event_id', 'N/A'),
                        'Process': event.get('process', 'N/A'),
                        'Direction': direction,
                        'Local_IP': event.get('local_ip', 'N/A'),
                        'Local_Port': event.get('local_port', 'N/A'),
                        'Remote_IP': event.get('remote_ip', 'N/A'),
                        'Remote_Port': event.get('remote_port', 'N/A'),
                        'Protocol': protocol,
                        'Filter_Reason': filter_reason,
                        'Layer': layer,
                        'Action': event.get('action', 'N/A')
                    })

            console.print(f"[green]OK: Results exported to: {csv_path}[/green]")
            console.print(f"[dim]Total events exported: {len(events)}[/dim]")

        except Exception as e:
            console.print(f"[red]Error exporting to CSV: {e}[/red]")
    def _analyze_single_ip(self, ip: str):
        """Analyze a single IP address with threat intelligence"""
        from datetime import datetime, timedelta
        import time

        # Rate limiting delays
        URLHAUS_DELAY = 0.2
        IPAPI_DELAY = 1.4

        intel = {}

        try:
            # URLhaus lookup
            urlhaus_data = self.threat_intel.lookup_urlhaus(ip, None)
            intel['urlhaus_status'] = urlhaus_data['status']
            intel['urlhaus_details'] = urlhaus_data['details']
            intel['urlhaus_checked'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            time.sleep(URLHAUS_DELAY)

            # GeoIP lookup
            geoip_data = self.threat_intel.lookup_geoip(ip)
            intel.update(geoip_data)
            intel['geoip_checked'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            time.sleep(IPAPI_DELAY)

            # Reverse DNS
            intel['reverse_dns'] = self.threat_intel.reverse_dns(ip)
            intel['dns_checked'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Save to database
            self.db.update_ip_intelligence(ip, intel)

        except Exception as e:
            console.print(f"[red]Error analyzing {ip}: {e}[/red]")

    def threat_summary(self):
        """Show only flagged/suspicious IPs"""
        console.print(Panel("Threat Summary", style="red"))

        if not self.db.conn:
            console.print("[yellow]Database not connected.[/yellow]")
            return

        try:
            cursor = self.db.conn.cursor()
            cursor.execute('''
                SELECT * FROM ip_intelligence
                WHERE urlhaus_status = 'malicious'
                ORDER BY last_seen DESC
            ''')

            threats = [dict(row) for row in cursor.fetchall()]
        except AttributeError:
            console.print("[red]Database connection error.[/red]")
            return

        if not threats:
            console.print("[green]No malicious IPs detected![/green]")
            return

        console.print(f"[red bold]Found {len(threats)} malicious IPs![/red bold]\n")

        table = Table(title="Malicious IPs", box=box.ROUNDED)
        table.add_column("IP", style="red bold")
        table.add_column("Country", style="yellow")
        table.add_column("Last Seen", style="white")
        table.add_column("Reverse DNS", style="white", max_width=30)

        for threat in threats:
            table.add_row(
                threat['ip_address'],
                threat.get('country', 'N/A'),
                threat.get('last_seen', 'N/A')[:19],
                threat.get('reverse_dns', 'N/A')
            )

        console.print(table)

        # Optional: Show detailed threat information
        if Confirm.ask("\nView details for a specific malicious IP?"):
            ip = Prompt.ask("Enter IP address")
            matching = [t for t in threats if t['ip_address'] == ip]
            if matching:
                self._display_ip_intelligence(matching[0])
            else:
                console.print("[yellow]IP not found in threat list[/yellow]")
    def _translate_windows_codes(self, value: str) -> str:
        """
        Translate Windows event codes to human-readable values
        """
        if not value or not isinstance(value, str):
            return value

        # Windows Filtering Platform direction codes
        direction_mapping = {
            '%%14592': 'Inbound',
            '%%14593': 'Outbound',
            '%%14594': 'Listen',
            '%%14595': 'Accept'
        }

        # Windows Filtering Platform layer codes
        layer_mapping = {
            '%%14608': 'Transport',
            '%%14609': 'Network',
            '%%14610': 'Datagram',
            '%%14611': 'Stream',
            '%%14612': 'Resource',
            '%%14613': 'Callout'
        }

        # Protocol codes
        protocol_mapping = {
            '6': 'TCP',
            '17': 'UDP',
            '1': 'ICMP',
            '2': 'IGMP',
            '4':  'IP',
            '58': 'ICMPv6'
        }

        # Check direction first
        if value in direction_mapping:
            return direction_mapping[value]

        # Check layer next
        if value in layer_mapping:
            return layer_mapping[value]

        # Check protocol
        if value in protocol_mapping:
            return protocol_mapping[value]

        # For filter reason, use simple categorization
        try:
            reason_code = int(value)

            # Check if it's a standard WFP code first
            standard_wfp_codes = {
                0: 'No matching filter',
                1: 'Generic',
                2: 'Flow deleted',
                3: 'Reauthorized',
                4: 'Policy change',
                5: 'New flow',
                6: 'Normal termination',
                7: 'Abnormal termination',
                8: 'Expired flow',
                9: 'User mode request',
            }

            if reason_code in standard_wfp_codes:
                return standard_wfp_codes[reason_code]

            # Categorize unknown codes
            if 200000 <= reason_code <= 400000:
                return f"App Policy ({reason_code})"
            elif 268435456 <= reason_code <= 268435481:
                return f"WFP Policy ({reason_code})"
            else:
                return f"Policy ({reason_code})"

        except (ValueError, TypeError):
            # Return original value if it's not a number
            return value

        # Return original value if no mapping found
        return value
