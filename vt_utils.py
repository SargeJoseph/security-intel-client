"""
VirusTotal Utilities Module
Contains utility functions, helper methods, and common operations.
"""

import hashlib
import os
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.prompt import Confirm

from constants import VT_SCAN_DELAY, DB_MAX_RETRIES, DB_RETRY_DELAY

console = Console()


def calculate_file_hash(file_path: str, hash_type: str = "sha256") -> Optional[str]:
    """Calculate hash of a file with specified algorithm"""
    try:
        if hash_type.lower() == "sha256":
            hash_obj = hashlib.sha256()
        elif hash_type.lower() == "md5":
            hash_obj = hashlib.md5()
        elif hash_type.lower() == "sha1":
            hash_obj = hashlib.sha1()
        else:
            console.print(f"[red]Unsupported hash type: {hash_type}[/red]")
            return None

        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest().lower()
    except Exception as e:
        console.print(f"[red]Error calculating {hash_type} for {file_path}: {e}[/red]")
        return None


def validate_hash(hash_string: str) -> bool:
    """Validate if a string is a valid SHA256 hash"""
    if len(hash_string) != 64:
        return False
    
    try:
        int(hash_string, 16)
        return True
    except ValueError:
        return False


def get_file_list_from_directory(directory: str, extensions: List[str] = None) -> List[str]:
    """Get list of files from directory with optional extension filtering"""
    directory_path = Path(directory)
    
    if not directory_path.exists():
        console.print(f"[red]Directory not found: {directory}[/red]")
        return []
    
    if not directory_path.is_dir():
        console.print(f"[red]Path is not a directory: {directory}[/red]")
        return []

    file_list = []
    
    try:
        if extensions:
            for ext in extensions:
                file_list.extend([str(p) for p in directory_path.rglob(f"*{ext}") if p.is_file()])
        else:
            file_list = [str(p) for p in directory_path.rglob('*') if p.is_file()]
        
        console.print(f"[cyan]Found {len(file_list)} files in {directory}[/cyan]")
        return file_list
        
    except Exception as e:
        console.print(f"[red]Error scanning directory {directory}: {e}[/red]")
        return []


def safe_database_operation(operation_func, max_retries: int = DB_MAX_RETRIES, **kwargs) -> Any:
    """Safely execute database operations with retry logic"""
    for attempt in range(max_retries):
        try:
            return operation_func(**kwargs)
        except Exception as e:
            if "database is locked" in str(e) and attempt < max_retries - 1:
                console.print(f"[yellow]Database locked, retry {attempt + 1}/{max_retries}[/yellow]")
                time.sleep(DB_RETRY_DELAY * (attempt + 1))
                continue
            else:
                console.print(f"[red]Database operation failed: {e}[/red]")
                raise
    return None


def format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable format"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.1f} {size_names[i]}"


def is_safe_to_upload(file_path: str) -> bool:
    """Check if a file is safe to upload to VirusTotal"""
    path = Path(file_path)
    
    if not path.exists():
        console.print(f"[red]File not found: {file_path}[/red]")
        return False
    
    if not path.is_file():
        console.print(f"[red]Path is not a file: {file_path}[/red]")
        return False
    
    # Check file size
    file_size = path.stat().st_size
    if file_size > 650 * 1024 * 1024:  # 650MB VT limit
        console.print(f"[red]File too large: {format_file_size(file_size)}[/red]")
        return False
    
    if file_size == 0:
        console.print(f"[yellow]File is empty: {file_path}[/yellow]")
        return Confirm.ask("Upload empty file anyway?")
    
    return True


def extract_filename_from_path(file_path: str) -> str:
    """Extract filename from full path"""
    return Path(file_path).name.lower()


def batch_process_files(file_paths: List[str], process_func, batch_size: int = 10, **kwargs) -> Dict:
    """Process files in batches with progress tracking"""
    results = {
        'processed': 0,
        'successful': 0,
        'failed': 0,
        'errors': []
    }

    total_files = len(file_paths)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("•"),
        TextColumn("[progress.details]{task.fields[details]}"),
        console=console
    ) as progress:

        task = progress.add_task(
            "Processing files...",
            total=total_files,
            details="Starting..."
        )

        for i in range(0, total_files, batch_size):
            batch = file_paths[i:i + batch_size]
            batch_details = f"Batch {i//batch_size + 1}/{(total_files + batch_size - 1)//batch_size}"
            
            progress.update(
                task,
                description="Processing files",
                details=batch_details
            )

            for file_path in batch:
                filename = Path(file_path).name
                try:
                    result = process_func(file_path, **kwargs)
                    if result:
                        results['successful'] += 1
                        progress.console.print(f"[green]{filename}: Success[/green]")
                    else:
                        results['failed'] += 1
                        progress.console.print(f"[yellow]{filename}: Failed[/yellow]")
                except Exception as e:
                    results['failed'] += 1
                    results['errors'].append(f"{filename}: {str(e)}")
                    progress.console.print(f"[red]{filename}: Error - {str(e)}[/red]")
                
                results['processed'] += 1
                progress.advance(task)
                
                # Rate limiting
                time.sleep(VT_SCAN_DELAY)

        return results


def create_backup_database(db_conn, backup_path: Path) -> bool:
    """Create a backup of the database"""
    try:
        import sqlite3
        backup_conn = sqlite3.connect(backup_path)
        db_conn.backup(backup_conn)
        backup_conn.close()
        console.print(f"[green]Database backup created: {backup_path}[/green]")
        return True
    except Exception as e:
        console.print(f"[red]Failed to create database backup: {e}[/red]")
        return False


def cleanup_old_files(directory: Path, days_old: int = 30) -> int:
    """Clean up files older than specified days"""
    if not directory.exists():
        console.print(f"[red]Directory not found: {directory}[/red]")
        return 0

    cutoff_time = time.time() - (days_old * 24 * 60 * 60)
    deleted_count = 0

    for file_path in directory.rglob('*'):
        if file_path.is_file() and file_path.stat().st_mtime < cutoff_time:
            try:
                file_path.unlink()
                deleted_count += 1
                console.print(f"[dim]Deleted: {file_path}[/dim]")
            except Exception as e:
                console.print(f"[yellow]Failed to delete {file_path}: {e}[/yellow]")

    console.print(f"[green]Cleaned up {deleted_count} files older than {days_old} days[/green]")
    return deleted_count


def get_system_info() -> Dict[str, str]:
    """Get system information for debugging"""
    import platform
    import sys
    
    return {
        'platform': platform.system(),
        'platform_release': platform.release(),
        'platform_version': platform.version(),
        'architecture': platform.architecture()[0],
        'processor': platform.processor(),
        'python_version': sys.version,
        'python_executable': sys.executable,
        'current_directory': os.getcwd()
    }


def display_system_info():
    """Display system information"""
    info = get_system_info()
    
    console.print(Panel("System Information", style="cyan"))
    for key, value in info.items():
        console.print(f"  [cyan]{key.replace('_', ' ').title()}:[/cyan] {value}")


def check_disk_space(path: str = ".") -> Dict[str, float]:
    """Check disk space for given path"""
    import shutil
    
    try:
        total, used, free = shutil.disk_usage(path)
        return {
            'total_gb': total / (1024**3),
            'used_gb': used / (1024**3),
            'free_gb': free / (1024**3),
            'free_percent': (free / total) * 100
        }
    except Exception as e:
        console.print(f"[red]Error checking disk space: {e}[/red]")
        return {}


def display_disk_space(path: str = "."):
    """Display disk space information"""
    space_info = check_disk_space(path)
    
    if space_info:
        console.print(Panel("Disk Space Information", style="cyan"))
        console.print(f"  [cyan]Total:[/cyan] {space_info['total_gb']:.1f} GB")
        console.print(f"  [cyan]Used:[/cyan] {space_info['used_gb']:.1f} GB")
        console.print(f"  [cyan]Free:[/cyan] {space_info['free_gb']:.1f} GB")
        console.print(f"  [cyan]Free Space:[/cyan] {space_info['free_percent']:.1f}%")
        
        if space_info['free_percent'] < 10:
            console.print("[red]Warning: Low disk space![/red]")
        elif space_info['free_percent'] < 20:
            console.print("[yellow]Warning: Disk space is getting low[/yellow]")


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to be safe for file operations"""
    # Remove or replace problematic characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    # Limit length
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:255 - len(ext)] + ext
    
    return filename


def is_admin() -> bool:
    """Check if the script is running with administrator privileges"""
    try:
        if os.name == 'nt':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            return os.getuid() == 0
    except:
        return False


def check_admin_privileges():
    """Check and display admin privileges status"""
    if is_admin():
        console.print("[green]Running with administrator privileges[/green]")
    else:
        console.print("[yellow]Running without administrator privileges[/yellow]")
        console.print("[dim]Some operations may require elevated permissions[/dim]")