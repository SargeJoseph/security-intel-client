#!/usr/bin/env python3
"""
Application Browser Module
Handles application browsing and detailed IP analysis
"""

from typing import List, Dict, TYPE_CHECKING
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich import box

if TYPE_CHECKING:
    from database import Database

console = Console()


class ApplicationBrowser:
    """Handles browsing applications with enriched IP data"""

    def __init__(self, db: 'Database'):
        """
        Initialize application browser

        Args:
            db: Database instance
        """
        self.db = db

    def browse_applications(self):
        """Browse applications with enriched IP data from database"""
        console.print(Panel("Application Browser", style="cyan"))

        apps = self._read_applications_from_db()
        if not apps:
            console.print("[yellow]No applications found in database[/yellow]")
            return

        # Display applications table
        self._display_applications_table(apps)

        # Allow user to drill down into specific application
        if Confirm.ask("\nView details for an application?"):
            app_path = Prompt.ask("Enter application path (or partial match)")
            self._show_app_details(app_path, apps)

    def _read_applications_from_db(self) -> List[Dict]:
        """Read applications from database"""
        if not self.db.conn:
            return []

        cursor = self.db.conn.cursor()
        cursor.execute('''
            SELECT * FROM security_events
            ORDER BY CAST(total_connections AS INTEGER) DESC
        ''')
        return [dict(row) for row in cursor.fetchall()]

    def _display_applications_table(self, apps: List[Dict]):
        """Display table of applications with threat counts"""
        table = Table(title="Applications", box=box.ROUNDED)
        table.add_column("#", style="white", justify="right")
        table.add_column("App Path", style="cyan", no_wrap=True, max_width=100, justify="right")
        table.add_column("Total", style="white", justify="right")
        table.add_column("Denied", style="red", justify="right")
        table.add_column("IPs", style="yellow", justify="right")
        table.add_column("Threats", style="magenta", justify="right")

        for i, app in enumerate(apps, 1):
            app_path = app.get('application_path', 'Unknown')
            total = app.get('total_connections', 0)
            denied = app.get('denied_connections', 0)

            # Combine unique_dest_ips and unique_source_ips, deduplicate
            dest_ips = [ip.strip() for ip in app.get('unique_dest_ips', '').split(',') if ip.strip()]
            source_ips = [ip.strip() for ip in app.get('unique_source_ips', '').split(',') if ip.strip()]
            all_ips = list(set(dest_ips + source_ips))
            ip_count = len(all_ips)

            # Count threats for this application
            threats = self._count_threats(all_ips)

            # Format threat count with color
            threat_style = "red bold" if threats > 0 else "green"

            # Truncate long paths from the left to ensure the filename is always visible
            max_len = 100
            if len(app_path) > max_len:
                display_path = "…" + app_path[-(max_len - 1):]
            else:
                display_path = app_path

            table.add_row(
                str(i),
                display_path,
                str(total),
                str(denied),
                str(ip_count),
                f"[{threat_style}]{threats}[/{threat_style}]"
            )

        console.print(table)

    def _count_threats(self, ips: List[str]) -> int:
        """Count malicious IPs in a list"""
        threats = 0
        for ip in ips:
            intel = self.db.get_ip_intelligence(ip)
            if intel and intel.get('urlhaus_status') == 'malicious':
                threats += 1
        return threats

    def _show_app_details(self, search: str, apps: List[Dict]):
        """Show detailed IP info for an application"""
        # Find matching applications
        matches = [app for app in apps
                   if search.lower() in app.get('application_path', '').lower()]

        if not matches:
            console.print("[red]No matching application found[/red]")
            return

        if len(matches) > 1:
            console.print(f"[yellow]Found {len(matches)} matches:[/yellow]")
            for i, match in enumerate(matches[:5], 1):
                console.print(f"  {i}. {match['application_path']}")

            if len(matches) <= 5:
                choice = Prompt.ask("Select number",
                                   choices=[str(i) for i in range(1, len(matches) + 1)])
                app = matches[int(choice) - 1]
            else:
                console.print(f"[yellow]Showing first match (refine search for others)[/yellow]")
                app = matches[0]
        else:
            app = matches[0]

        # Display application details
        self._display_app_intelligence(app)

    def _display_app_intelligence(self, app: Dict):
        """Display detailed intelligence for an application"""
        console.print(f"\n[cyan]Application: {app['application_path']}[/cyan]")
        console.print(f"[cyan]Total Connections:[/cyan] {app.get('total_connections', 0)}")
        console.print(f"[cyan]Denied Connections:[/cyan] {app.get('denied_connections', 0)}")

        # Combine unique_dest_ips and unique_source_ips, deduplicate
        dest_ips = [ip.strip() for ip in app.get('unique_dest_ips', '').split(',') if ip.strip()]
        source_ips = [ip.strip() for ip in app.get('unique_source_ips', '').split(',') if ip.strip()]
        ips = sorted(set(dest_ips + source_ips))

        if not ips:
            console.print("[yellow]No IPs associated with this application[/yellow]")
            return

        # Create table for IP details (one IP per row)
        table = Table(title=f"IP Addresses ({len(ips)} total)", box=box.ROUNDED)
        table.add_column("IP", style="cyan")
        table.add_column("Status", style="white")
        table.add_column("Abuse Score", style="yellow", justify="right")
        table.add_column("IPQS Score", style="magenta", justify="right")
        table.add_column("GreyNoise", style="blue")
        table.add_column("Country", style="yellow")
        table.add_column("City", style="yellow")
        table.add_column("ISP", style="white", max_width=30)

        malicious_count = 0
        clean_count = 0
        unknown_count = 0

        for ip in ips:
            intel = self.db.get_ip_intelligence(ip)

            if not intel:
                table.add_row(ip, "[yellow]Not analyzed[/yellow]", "", "", "", "", "", "")
                unknown_count += 1
                continue

            status = intel.get('urlhaus_status', 'unknown')

            # Format status with color
            status_display = {
                'malicious': '[red bold]MALICIOUS[/red bold]',
                'clean': '[green]Clean[/green]',
                'unknown': '[yellow]Unknown[/yellow]',
                'error': '[dim]Error[/dim]'
            }.get(status, status)

            if status == 'malicious':
                malicious_count += 1
            elif status == 'clean':
                clean_count += 1
            else:
                unknown_count += 1

            # Format AbuseIPDB score
            abuse_score = intel.get('abuseipdb_confidence_score')
            if abuse_score is not None:
                if abuse_score > 80:
                    score_display = f"[red bold]{abuse_score}%[/red bold]"
                elif abuse_score > 50:
                    score_display = f"[yellow]{abuse_score}%[/yellow]"
                else:
                    score_display = f"[green]{abuse_score}%[/green]"
            else:
                score_display = "[dim]N/A[/dim]"

            # Format IPQS score
            ipqs_score = intel.get('ipqs_fraud_score')
            if ipqs_score is not None:
                if ipqs_score >= 85:
                    ipqs_display = f"[red bold]{ipqs_score}[/red bold]"
                elif ipqs_score >= 75:
                    ipqs_display = f"[yellow]{ipqs_score}[/yellow]"
                else:
                    ipqs_display = f"[green]{ipqs_score}[/green]"
            else:
                ipqs_display = "[dim]N/A[/dim]"

            # Format GreyNoise status
            classification = intel.get('greynoise_classification')
            if classification:
                if classification == 'malicious':
                    gn_display = f"[red bold]{classification.title()}[/red bold]"
                elif classification == 'benign':
                    gn_display = f"[green]{classification.title()}[/green]"
                else:
                    gn_display = f"[yellow]{classification.title()}[/yellow]"
            else:
                gn_display = "[dim]N/A[/dim]"

            table.add_row(
                ip,
                status_display,
                score_display,
                ipqs_display,
                gn_display,
                intel.get('country', 'N/A'),
                intel.get('city', 'N/A'),
                intel.get('isp', 'N/A')
            )

        console.print(table)

        # Display summary statistics
        console.print(f"\n[cyan]Threat Summary:[/cyan]")
        if malicious_count > 0:
            console.print(f"  [red bold]WARNING: {malicious_count} malicious IPs[/red bold]")
        console.print(f"  [green]OK: {clean_count} clean IPs[/green]")
        if unknown_count > 0:
            console.print(f"  [yellow]? {unknown_count} unknown/not analyzed[/yellow]")
