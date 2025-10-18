"""
Configuration settings for Security Intelligence CLI Tool
Contains all constants, paths, and timing configurations
Now includes TOML-based API key management and .env file support
"""

from pathlib import Path
from typing import Optional

# Load .env file ONLY (do not use OS environment variables)
_dotenv_values = {}
try:
    from dotenv import dotenv_values
    # Get the directory where this script is located
    _config_dir = Path(__file__).parent.resolve()
    _env_file = _config_dir / ".env"
    if _env_file.exists():
        _dotenv_values = dotenv_values(_env_file)
except ImportError:
    # python-dotenv not installed, use empty dict
    pass

def _get_env(key: str, default: Optional[str] = None) -> str:
    """Get value from .env file ONLY, not from OS environment variables"""
    return _dotenv_values.get(key, default) or default or ''

# Directory paths - loaded from .env file ONLY
OUTPUT_DIR = Path(_get_env('OUTPUT') or '.')
#MASTER_CSV = OUTPUT_DIR / "MasterNetworkReport.csv"
ARCHIVE_DIR = Path(_get_env('LOGARCHIVES') or (OUTPUT_DIR / "LogArchives"))
DB_PATH = Path(_get_env('DB') or (OUTPUT_DIR / "security_intel.db"))

# VirusTotal CLI path (optional - if not set, will search in system paths)
VT_CLI_PATH = _get_env('VT_CLI_PATH') or None

# Forensic tools paths
FORENSIC_TOOLS_DIR = Path(_get_env('FORENSIC_TOOLS_DIR') or 'C:/tools/net9')
FORENSIC_OUTPUT_DIR = Path(_get_env('FORENSIC_OUTPUT_DIR') or 'C:/users/frapp/desktop/output')

# Configuration file path (matches VT CLI pattern)
CONFIG_FILE = Path.home() / ".security_intel.toml"

# API rate limiting and delays (in seconds)
URLHAUS_DELAY = 0.2
IPAPI_DELAY = 1.4
IPQS_DELAY = 0.5  # IPQualityScore: 2 requests/second = 0.5s delay

# API usage limits
IPAPICO_DAILY_LIMIT = 1000
IPQS_MONTHLY_LIMIT = 5000  # IPQualityScore free tier limit

# Cache expiration periods (in days)
URLHAUS_CACHE_DAYS = 90
GEOIP_CACHE_DAYS = 90
IPQS_CACHE_DAYS = 90  # IPQualityScore cache period


def load_config():
    """
    Load configuration from TOML file

    Returns:
        Dictionary with configuration values, empty dict if file doesn't exist
    """
    if not CONFIG_FILE.exists():
        return {}

    try:
        import tomli as toml
        with open(CONFIG_FILE, "rb") as f:
            return toml.load(f)
    except (ImportError, Exception):
        return {}


def get_urlhaus_api_key():
    """
    Get URLhaus API key from config file

    Returns:
        API key string or None if not configured
    """
    config = load_config()
    return config.get('urlhaus', {}).get('apikey')


def get_virustotal_api_key():
    """
    Get VirusTotal API key from config file
    (Note: VT CLI uses its own .vt.toml file, this is for reference)

    Returns:
        API key string or None if not configured
    """
    config = load_config()
    return config.get('virustotal', {}).get('apikey')
def get_abuseipdb_api_key():
    """Get AbuseIPDB API key from config file"""
    config = load_config()
    return config.get('abuseipdb', {}).get('apikey')


def save_abuseipdb_api_key(api_key: str) -> bool:
    """Save AbuseIPDB API key to config file"""
    try:
        import tomli_w as toml_w
        config = load_config()
        if 'abuseipdb' not in config:
            config['abuseipdb'] = {}
        config['abuseipdb']['apikey'] = api_key
        with open(CONFIG_FILE, 'wb') as f:
            toml_w.dump(config, f)
        return True
    except Exception:
        return False


def get_ipqs_api_key():
    """Get IPQualityScore API key from config file"""
    config = load_config()
    return config.get('ipqualityscore', {}).get('apikey')


def save_ipqs_api_key(api_key: str) -> bool:
    """Save IPQualityScore API key to config file"""
    try:
        import tomli_w as toml_w
        config = load_config()
        if 'ipqualityscore' not in config:
            config['ipqualityscore'] = {}
        config['ipqualityscore']['apikey'] = api_key
        with open(CONFIG_FILE, 'wb') as f:
            toml_w.dump(config, f)
        return True
    except Exception:
        return False



def save_urlhaus_api_key(api_key: str) -> bool:
    """
    Save URLhaus API key to config file

    Args:
        api_key: The API key to save

    Returns:
        True if successful, False otherwise
    """
    try:
        import tomli_w as toml_w
        config = load_config()
        if 'urlhaus' not in config:
            config['urlhaus'] = {}
        config['urlhaus']['apikey'] = api_key

        with open(CONFIG_FILE, 'wb') as f:
            toml_w.dump(config, f)

        return True

    except (ImportError, Exception):
        return False


def check_toml_support() -> bool:
    """
    Check if TOML library is available

    Returns:
        True if TOML can be read/written
    """
    try:
        import tomli
        import tomli_w
        return True
    except ImportError:
        return False
