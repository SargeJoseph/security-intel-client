"""
Constants and configuration for VirusTotal Scanner Module.
Centralized location for all static configuration values.
"""

from pathlib import Path
from typing import Optional

# Import _get_env from config to use .env file ONLY
try:
    from config import _get_env
except ImportError:
    # Fallback if config not available
    def _get_env(key: str, default: Optional[str] = None) -> str:
        return default or ''

# Directory configuration
OUTPUT_DIR = Path(_get_env('OUTPUT') or '.')

# Database configuration
DB_PATH = OUTPUT_DIR / "security_intel.db"

# Excluded vendors (auto-updated based on <70% reliability score)
# This list is automatically maintained after each VT scan
# Vendors with reliability_score < 0.70 and >= 10 detections are excluded
# Excluded vendors (auto-updated based on <70% reliability score)
# Excluded vendors (auto-updated based on <70% reliability score)
# Excluded vendors (auto-updated based on <70% reliability score)
# Excluded vendors (auto-updated based on <70% reliability score)
# Excluded vendors (auto-updated based on <70% reliability score)
# Excluded vendors (auto-updated based on <70% reliability score)
EXCLUDED_VENDORS = [
    "APEX",
    "Bkav",
    "ESET-NOD32",
    "Google",
    "Jiangmin",
    "MaxSecure",
    "Tencent",
    "Trapmine",
    "Values",
    "VirIT",
    "Webroot",
    "Zillya",
    "tehtris"
]

# VT CLI configuration
VT_SCAN_DELAY = 0.25  # Rate limiting delay for hash lookups
VT_UPLOAD_DELAY = 15  # Delay between uploads (VT limit: 4/minute)
VT_UPLOAD_DAILY_LIMIT = 500  # Conservative daily upload limit

# Cache duration for VirusTotal scan results (in days)
VT_CACHE_MAX_DAYS = 365

# Vendor reliability tracking
VT_VENDOR_CONSENSUS_THRESHOLD = 10  # Minimum vendors needed to consider a detection valid (not a false positive)
VT_VENDOR_MIN_DETECTIONS = 3  # Minimum detections before tracking vendor reliability
VT_VENDOR_MAX_FP_RATE = 0.30  # Maximum false positive rate (30%) before flagging vendor as unreliable

# File size limits (in bytes)
VT_MAX_FILE_SIZE = 650 * 1024 * 1024  # 650MB VT API limit

# Timeout configurations
VT_SCAN_TIMEOUT = 30  # seconds for hash lookups
VT_UPLOAD_TIMEOUT = 300  # 5 minutes for file uploads
VT_VERSION_TIMEOUT = 10  # seconds for version check

# Database retry configuration
DB_MAX_RETRIES = 3
DB_RETRY_DELAY = 0.5  # seconds

# Display configuration
PAGE_SIZE = 50  # Default page size for paginated results
PROGRESS_DESCRIPTION = "Scanning files"

# File paths for imports
DEFAULT_HASH_DB_PATH = OUTPUT_DIR / "hash_database.json"
DEFAULT_DETECTION_DB_PATH = OUTPUT_DIR / "detection_tracking.json"
