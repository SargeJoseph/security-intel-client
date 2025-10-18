#!/usr/bin/env python3
"""
Forensic Artifact Collector
Python equivalent of the PowerShell process builder for VT scanning
"""

import os
import csv
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Set
import glob

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from config import FORENSIC_TOOLS_DIR, FORENSIC_OUTPUT_DIR

console = Console()

class ForensicCollector:
    """Collects executable files from Windows forensic artifacts"""

    def __init__(self, output_dir: Optional[Path] = None):
        # Import _get_env from config to use .env file ONLY
        try:
            from config import _get_env
            default_output = Path(_get_env('OUTPUT') or '.')
        except ImportError:
            default_output = Path('.')
        self.output_dir = output_dir or default_output
        self.forensic_tools_dir = FORENSIC_TOOLS_DIR
        self.forensic_output_dir = FORENSIC_OUTPUT_DIR
        self.forensic_output_dir.mkdir(exist_ok=True)

        # Executable extensions to look for
        self.executable_extensions = {'.exe', '.bat', '.cmd', '.msi', '.msp', '.scr', '.ps1', '.com'}

    def check_forensic_tools(self) -> Dict[str, bool]:
        """Check if forensic tools are available"""
        tools = {
            'PECmd': self.forensic_tools_dir / "PECmd.exe",
            'AmcacheParser': self.forensic_tools_dir / "AmcacheParser.exe"
        }

        available = {}
        for tool_name, tool_path in tools.items():
            available[tool_name] = tool_path.exists()
            if available[tool_name]:
                console.print(f"[green]OK: {tool_name} found[/green]")
            else:
                console.print(f"[yellow]? {tool_name} not found at {tool_path}[/yellow]")

        return available

    def parse_prefetch(self) -> List[str]:
        """Parse Prefetch files using PECmd"""
        console.print("[cyan]1. Processing Prefetch files...[/cyan]")

        prefetch_dir = Path("C:/Windows/Prefetch")
        if not prefetch_dir.exists():
            console.print("[yellow]   Prefetch directory not found[/yellow]")
            return []

        pecmd_path = self.forensic_tools_dir / "PECmd.exe"
        if not pecmd_path.exists():
            console.print("[yellow]   PECmd.exe not found, skipping Prefetch[/yellow]")
            return []

        try:
            # Run PECmd to extract Prefetch info
            result = subprocess.run(
                [str(pecmd_path), "-d", str(prefetch_dir), "--csv", str(self.forensic_output_dir), "-q"],
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode == 0:
                console.print("[green]   Prefetch processing completed[/green]")
            else:
                console.print(f"[yellow]   PECmd completed with exit code {result.returncode}[/yellow]")

        except subprocess.TimeoutExpired:
            console.print("[red]   Prefetch processing timed out[/red]")
        except Exception as e:
            console.print(f"[red]   Prefetch processing error: {e}[/red]")

        return self._extract_from_timeline_csv()

    def parse_amcache(self) -> List[str]:
        """Parse AmCache using AmcacheParser"""
        console.print("[cyan]2. Processing AmCache...[/cyan]")

        amcache_path = Path("C:/Windows/appcompat/Programs/Amcache.hve")
        try:
            if not amcache_path.exists():
                console.print("[yellow]   Amcache.hve not found[/yellow]")
                return []
        except PermissionError:
            console.print("[red]   Permission denied: Cannot access Amcache.hve. Try running as an administrator.[/red]")
            return []

        amcache_parser_path = self.forensic_tools_dir / "AmcacheParser.exe"
        if not amcache_parser_path.exists():
            console.print("[yellow]   AmcacheParser.exe not found, skipping AmCache[/yellow]")
            return []

        try:
            # Run AmcacheParser
            result = subprocess.run(
                [str(amcache_parser_path), "-f", str(amcache_path), "--csv", str(self.forensic_output_dir), "-q"],
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode == 0:
                console.print("[green]   AmCache processing completed[/green]")
            else:
                console.print(f"[yellow]   AmcacheParser completed with exit code {result.returncode}[/yellow]")

        except subprocess.TimeoutExpired:
            console.print("[red]   AmCache processing timed out[/red]")
        except Exception as e:
            console.print(f"[red]   AmCache processing error: {e}[/red]")

        return self._extract_from_amcache_csv()

    def _extract_from_timeline_csv(self) -> List[str]:
        """Extract executable paths from Timeline CSV"""
        console.print("   Processing Timeline CSV...")

        timeline_files = list(self.forensic_output_dir.glob("*Timeline.csv"))
        if not timeline_files:
            console.print("[yellow]   No Timeline CSV found[/yellow]")
            return []

        # Get the most recent timeline file
        timeline_file = max(timeline_files, key=lambda x: x.stat().st_mtime)
        console.print(f"   Found Timeline CSV: {timeline_file.name}")

        executable_paths = set()

        try:
            with open(timeline_file, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)
                timeline_data = list(reader)

            console.print(f"   Total timeline entries: {len(timeline_data)}")

            # Filter for executables with volume paths
            valid_exes = [
                row for row in timeline_data
                if row.get('ExecutableName')
                and 'VOLUME{' in row['ExecutableName']
                and any(row['ExecutableName'].lower().endswith(ext) for ext in self.executable_extensions)
            ]

            console.print(f"   Volume-based executable entries: {len(valid_exes)}")

            # Clean paths (replace VOLUME IDs with C:)
            timeline_paths = set()
            for row in valid_exes:
                raw_path = row['ExecutableName']
                # Handle VOLUME format: \VOLUME{guid}\path -> c:\path
                if '\\VOLUME{' in raw_path.upper():
                    # Split on } and take everything after it
                    parts = raw_path.split('}')
                    if len(parts) > 1:
                        clean_path = 'c:' + parts[-1]
                    else:
                        clean_path = raw_path
                else:
                    clean_path = raw_path

                # Ensure it starts with c: if it starts with backslash
                if clean_path.startswith('\\') and not clean_path[1:3] == ':\\':
                    clean_path = 'c:' + clean_path

                # Convert to lowercase
                clean_path = clean_path.lower()
                timeline_paths.add(clean_path)

            console.print(f"   Unique timeline paths: {len(timeline_paths)}")
            executable_paths.update(timeline_paths)

        except Exception as e:
            console.print(f"[red]   Error processing timeline CSV: {e}[/red]")

        return list(executable_paths)

    def _extract_from_amcache_csv(self) -> List[str]:
        """Extract executable paths from AmCache CSV"""
        console.print("   Processing AmCache data...")

        amcache_files = list(self.forensic_output_dir.glob("*Amcache*UnassociatedFileEntries*.csv"))
        if not amcache_files:
            console.print("[yellow]   No AmCache CSV found[/yellow]")
            return []

        # Get the most recent AmCache file
        amcache_file = max(amcache_files, key=lambda x: x.stat().st_mtime)
        console.print(f"   Found AmCache CSV: {amcache_file.name}")

        executable_paths = set()

        try:
            with open(amcache_file, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)
                amcache_data = list(reader)

            # Filter for executables
            valid_files = [
                row for row in amcache_data
                if any(row.get('Name', '').lower().endswith(ext) for ext in self.executable_extensions)
            ]

            amcache_paths = set()
            for row in valid_files:
                if row.get('FullPath'):
                    clean_path = row['FullPath'].replace('\\VOLUME{', 'C:').split('}')[-1]
                    amcache_paths.add(clean_path)
                elif row.get('Name'):
                    amcache_paths.add(row['Name'])

            console.print(f"   Unique AmCache paths: {len(amcache_paths)}")
            executable_paths.update(amcache_paths)

        except Exception as e:
            console.print(f"[red]   Error processing AmCache CSV: {e}[/red]")

        return list(executable_paths)

    def load_manual_scan_file(self, manual_scan_path: Optional[str] = None) -> List[str]:
        """Load additional files from manual scan file"""
        if not manual_scan_path:
            manual_scan_path = "C:/Users/frapp/Documents/PowerShell/Scripts/Output/temp-scan.txt"

        manual_scan_file = Path(manual_scan_path)
        if not manual_scan_file.exists():
            console.print(f"[yellow]Manual scan file not found: {manual_scan_file}[/yellow]")
            return []

        try:
            with open(manual_scan_file, 'r', encoding='utf-8') as f:
                manual_files = [line.strip() for line in f if line.strip()]

            # Verify files exist
            valid_files = [f for f in manual_files if Path(f).exists()]
            console.print(f"[green]Added {len(valid_files)} manual files from {manual_scan_file}[/green]")

            return valid_files

        except Exception as e:
            console.print(f"[red]Error loading manual scan file: {e}[/red]")
            return []

    def verify_files_exist(self, file_paths: List[str]) -> List[str]:
        """Verify that collected files actually exist"""
        console.print("   Verifying files exist...")

        valid_files = []
        for file_path in file_paths:
            if Path(file_path).exists():
                valid_files.append(file_path)

        console.print(f"   Valid files found: {len(valid_files)}")
        return valid_files

    def cleanup_old_csv_files(self):
        """Clean up old CSV files, keep only the newest"""
        console.print("\n[cyan]Cleaning up old CSV files...[/cyan]")

        # Keep only the latest file for each type
        file_patterns = [
            "*Timeline.csv",
            "*PECmd_Output.csv",
            "*Amcache*.csv"
        ]

        for pattern in file_patterns:
            files = list(self.forensic_output_dir.glob(pattern))
            if len(files) > 1:
                # Sort by modification time, newest first
                files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                # Remove all but the newest file
                for old_file in files[1:]:
                    try:
                        old_file.unlink()
                        console.print(f"   Removed: {old_file.name}")
                    except Exception as e:
                        console.print(f"   Failed to remove {old_file.name}: {e}")

        console.print("[green]Kept only the latest forensic CSV files.[/green]")

    def collect_executables(self, include_manual: bool = True) -> List[str]:
        """Main method to collect all executable files"""
        console.print(Panel("Forensic Artifact Collection", style="cyan"))

        # Check available tools
        available_tools = self.check_forensic_tools()

        all_executable_paths = set()

        # Parse Prefetch if available
        if available_tools.get('PECmd', False):
            prefetch_paths = self.parse_prefetch()
            all_executable_paths.update(prefetch_paths)

        # Parse AmCache if available
        if available_tools.get('AmcacheParser', False):
            amcache_paths = self.parse_amcache()
            all_executable_paths.update(amcache_paths)

        # Add manual files if requested
        if include_manual:
            manual_files = self.load_manual_scan_file()
            all_executable_paths.update(manual_files)

        # Verify files exist
        valid_files = self.verify_files_exist(list(all_executable_paths))

        # Cleanup old CSV files
        self.cleanup_old_csv_files()

        # Show summary
        console.print(Panel("Collection Complete", style="green"))
        console.print(f"   Found {len(valid_files)} valid executable paths")

        if not valid_files:
            console.print("[red]No valid executable files found to scan![/red]")
            console.print("[yellow]Please check your forensic data sources.[/yellow]")

        return valid_files

    def save_file_list(self, file_paths: List[str], output_file: Optional[Path] = None):
        """Save the file list to a text file"""
        if not output_file:
            output_file = self.output_dir / "forensic_file_list.txt"

        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                for file_path in file_paths:
                    f.write(f"{file_path}\n")

            console.print(f"[green]Saved file list to: {output_file}[/green]")

        except Exception as e:
            console.print(f"[red]Error saving file list: {e}[/red]")


def forensic_collection_menu(vt_scanner):
    """Menu for forensic collection integrated with VT scanner"""
    collector = ForensicCollector()

    while True:
        console.print(Panel("Forensic Artifact Collection", style="cyan"))

        console.print("\n1. Collect executables from forensic artifacts")
        console.print("2. Scan collected files with VirusTotal")
        console.print("3. Collect and scan automatically")
        console.print("4. Load files from manual scan list")
        console.print("5. Return to main menu")

        choice = Prompt.ask("Select option", choices=["1", "2", "3", "4", "5"], default="1")

        if choice == "1":
            # Collect only
            file_paths = collector.collect_executables()
            if file_paths:
                collector.save_file_list(file_paths)
                if Confirm.ask("Scan these files now?"):
                    results = vt_scanner.scan_multiple_files(file_paths, allow_upload=True)
                    display_scan_results(results)

        elif choice == "2":
            # Scan existing list
            list_file = Prompt.ask("Enter path to file list",
                                 default=str(collector.output_dir / "forensic_file_list.txt"))
            if Path(list_file).exists():
                with open(list_file, 'r') as f:
                    file_paths = [line.strip() for line in f if line.strip()]

                console.print(f"[cyan]Found {len(file_paths)} files to scan[/cyan]")
                results = vt_scanner.scan_multiple_files(file_paths, allow_upload=True)
                display_scan_results(results)
            else:
                console.print("[red]File list not found![/red]")

        elif choice == "3":
            # Collect and scan automatically
            file_paths = collector.collect_executables()
            if file_paths:
                results = vt_scanner.scan_multiple_files(file_paths, allow_upload=True)
                display_scan_results(results)

        elif choice == "4":
            # Load manual files only
            manual_files = collector.load_manual_scan_file()
            if manual_files:
                console.print(f"[cyan]Found {len(manual_files)} manual files[/cyan]")
                if Confirm.ask("Scan these files?"):
                    results = vt_scanner.scan_multiple_files(manual_files)
                    display_scan_results(results)

        elif choice == "5":
            break

        if choice != "5":
            Prompt.ask("\nPress Enter to continue")


def display_scan_results(results: Dict):
    """Display scan results in a formatted way"""
    console.print(Panel("Scan Results", style="cyan"))
    console.print(f"  Total files: {results['total']}")
    console.print(f"  Successfully scanned: {results['scanned']}")
    console.print(f"  Malicious: [red]{results['malicious']}[/red]")
    console.print(f"  Clean: [green]{results['clean']}[/green]")
    console.print(f"  Cached: [yellow]{results['cached']}[/yellow]")
    console.print(f"  Errors: [red]{results['errors']}[/red]")


if __name__ == "__main__":
    collector = ForensicCollector()
    file_paths = collector.collect_executables()

    if file_paths:
        collector.save_file_list(file_paths)
        console.print(f"\n[green]Collection complete! Found {len(file_paths)} files.[/green]")
