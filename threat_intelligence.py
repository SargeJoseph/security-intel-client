"""
Threat Intelligence lookups for Security Intelligence CLI Tool
Handles URLhaus, GeoIP, and reverse DNS queries
"""

import json
import socket
from typing import Dict, Optional

import requests
from rich.console import Console

console = Console()


class ThreatIntelligence:
    """Handles threat intelligence lookups"""

    def __init__(self, db):
        """
        Initialize threat intelligence handler

        Args:
            db: Database instance for logging API usage
        """
        self.db = db
        self.urlhaus_key = None
        self.abuseipdb_key = None
        self.ipqs_key = None
        self.urlhaus_api = "https://urlhaus-api.abuse.ch/v1/host/"
        self.abuseipdb_api = "https://api.abuseipdb.com/api/v2/check"
        self.ipqs_api = "https://ipqualityscore.com/api/json/ip"
        self.greynoise_api = "https://api.greynoise.io/v3/community"

    def lookup_greynoise(self, ip: str) -> Dict:
        """
        Query GreyNoise Community API for IP context.

        NOTE: Community API has strict rate limit of 25 requests/week.
        Consider upgrading to paid plan for higher limits.

        Args:
            ip: IP address to check

        Returns:
            Dictionary with GreyNoise intelligence
        """
        headers = {
            'Accept': 'application/json'
        }

        url = f"{self.greynoise_api}/{ip}"

        try:
            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                self.db.log_api_usage('greynoise', True)
                return {
                    'status': 'success',
                    'noise': data.get('noise', False),
                    'riot': data.get('riot', False),
                    'classification': data.get('classification', 'unknown'),
                    'last_seen': data.get('last_seen'),
                    'message': data.get('message') # e.g., "IP not seen in GreyNoise"
                }
            elif response.status_code == 404:
                self.db.log_api_usage('greynoise', True)
                return {'status': 'not_found', 'message': 'IP not found in GreyNoise'}
            elif response.status_code == 429:
                # Rate limit exceeded (25/week for Community API)
                self.db.log_api_usage('greynoise', False)
                return {'status': 'rate_limit', 'message': 'Rate limit exceeded (25/week for Community API)'}
            else:
                self.db.log_api_usage('greynoise', False)
                return {'status': 'error', 'message': f"API returned status {response.status_code}"}

        except Exception as e:
            console.print(f"[yellow]GreyNoise lookup failed for {ip}: {e}[/yellow]")
            self.db.log_api_usage('greynoise', False)
            return {'status': 'error', 'message': str(e)}

    def lookup_urlhaus(self, ip: str, auth_key: Optional[str] = None) -> Dict:
        """
        Query URLhaus API for IP reputation

        Args:
            ip: IP address to check
            auth_key: Optional URLhaus API authentication key

        Returns:
            Dictionary with 'status' and 'details' keys
        """
        headers = {}
        if auth_key:
            headers['Auth-Key'] = auth_key

        try:
            response = requests.post(
                self.urlhaus_api,
                data={'host': ip},
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                self.db.log_api_usage('urlhaus', True)

                status = data.get('query_status', 'unknown')
                if status == 'ok':
                    return {
                        'status': 'malicious',
                        'details': json.dumps(data)
                    }
                elif status == 'no_results':
                    return {'status': 'clean', 'details': None}
                else:
                    return {'status': 'unknown', 'details': None}
            else:
                self.db.log_api_usage('urlhaus', False)
                return {'status': 'error', 'details': None}

        except Exception as e:
            console.print(f"[yellow]URLhaus lookup failed for {ip}: {e}[/yellow]")
            self.db.log_api_usage('urlhaus', False)
            return {'status': 'error', 'details': None}

    def lookup_geoip(self, ip: str) -> Dict:
        """
        Query GeoIP APIs for location and ISP information

        Args:
            ip: IP address to check

        Returns:
            Dictionary with 'country', 'city', and 'isp' keys
        """
        apis = [
            f"https://ipapi.co/{ip}/json/",
            f"http://ip-api.com/json/{ip}"
        ]

        for api_url in apis:
            try:
                response = requests.get(api_url, timeout=5)
                if response.status_code == 200:
                    data = response.json()

                    # Handle different API response formats
                    if 'country_name' in data:
                        return {
                            'country': data.get('country_name'),
                            'city': data.get('city'),
                            'isp': data.get('org')
                        }
                    elif 'country' in data:
                        return {
                            'country': data.get('country'),
                            'city': data.get('city'),
                            'isp': data.get('isp')
                        }

                self.db.log_api_usage('geoip', True)
            except Exception:
                # Try next API if this one fails
                continue

        self.db.log_api_usage('geoip', False)
        return {'country': None, 'city': None, 'isp': None}

    def lookup_abuseipdb(self, ip: str, api_key: Optional[str] = None) -> Dict:
        """Query AbuseIPDB API for IP reputation"""

        if not api_key:
            return {'status': 'error', 'confidence_score': 0, 'categories': [], 'total_reports': 0}

        headers = {
            'Key': api_key,
            'Accept': 'application/json'
        }

        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90,
            'verbose': True
        }

        try:
            response = requests.get(
                self.abuseipdb_api,
                headers=headers,
                params=params,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                self.db.log_api_usage('abuseipdb', True)

                ip_data = data.get('data', {})

                return {
                    'status': 'success',
                    'confidence_score': ip_data.get('abuseConfidenceScore', 0),
                    'categories': ip_data.get('categories', []),
                    'total_reports': ip_data.get('totalReports', 0),
                    'isp': ip_data.get('isp'),
                    'country': ip_data.get('countryCode'),
                    'usage_type': ip_data.get('usageType'),
                    'domain': ip_data.get('domain'),
                    'last_reported': ip_data.get('lastReportedAt')
                }
            else:
                self.db.log_api_usage('abuseipdb', False)
                return {'status': 'error', 'confidence_score': 0, 'categories': [], 'total_reports': 0}

        except Exception as e:
            console.print(f"[yellow]AbuseIPDB lookup failed for {ip}: {e}[/yellow]")
            self.db.log_api_usage('abuseipdb', False)
            return {'status': 'error', 'confidence_score': 0, 'categories': [], 'total_reports': 0}

    def lookup_ipqs(self, ip: str, api_key: Optional[str] = None) -> Dict:
        """
        Query IPQualityScore API for IP reputation, proxy/VPN detection, and fraud scoring

        Args:
            ip: IP address to check
            api_key: IPQualityScore API key

        Returns:
            Dictionary with fraud score, proxy detection, and other intelligence
        """
        if not api_key:
            return {
                'status': 'error',
                'fraud_score': 0,
                'is_proxy': False,
                'is_vpn': False,
                'is_tor': False,
                'is_crawler': False,
                'recent_abuse': False,
                'bot_status': False
            }

        # Build request URL with parameters
        params = {
            'strictness': 1,  # 0=relaxed, 1=standard (recommended), 2=strict
            'allow_public_access_points': 'true',
            'fast': 'false',  # Set to true for faster response but less accuracy
            'mobile': 'true'  # Check for mobile carriers
        }

        # Construct URL: https://ipqualityscore.com/api/json/ip/{API_KEY}/{IP}?strictness=1...
        url = f"{self.ipqs_api}/{api_key}/{ip}"

        try:
            response = requests.get(
                url,
                params=params,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                self.db.log_api_usage('ipqs', True)

                # Check if request was successful
                if not data.get('success', False):
                    error_msg = data.get('message', 'Unknown error')
                    console.print(f"[yellow]IPQS API error for {ip}: {error_msg}[/yellow]")
                    self.db.log_api_usage('ipqs', False)
                    return {'status': 'error', 'fraud_score': 0}

                return {
                    'status': 'success',
                    'fraud_score': data.get('fraud_score', 0),
                    'is_proxy': data.get('proxy', False),
                    'is_vpn': data.get('vpn', False),
                    'is_tor': data.get('tor', False),
                    'is_crawler': data.get('is_crawler', False),
                    'recent_abuse': data.get('recent_abuse', False),
                    'bot_status': data.get('bot_status', False),
                    'connection_type': data.get('connection_type', 'N/A'),
                    'abuse_velocity': data.get('abuse_velocity', 'none'),
                    'country_code': data.get('country_code', 'N/A'),
                    'city': data.get('city', 'N/A'),
                    'region': data.get('region', 'N/A'),
                    'isp': data.get('ISP', 'N/A'),
                    'asn': data.get('ASN', 'N/A'),
                    'organization': data.get('organization', 'N/A'),
                    'latitude': data.get('latitude', 0),
                    'longitude': data.get('longitude', 0),
                    'timezone': data.get('timezone', 'N/A'),
                    'mobile': data.get('mobile', False),
                    'host': data.get('host', 'N/A'),
                    'request_id': data.get('request_id', 'N/A')
                }
            else:
                console.print(f"[yellow]IPQS API returned status {response.status_code} for {ip}[/yellow]")
                self.db.log_api_usage('ipqs', False)
                return {'status': 'error', 'fraud_score': 0}

        except Exception as e:
            console.print(f"[yellow]IPQS lookup failed for {ip}: {e}[/yellow]")
            self.db.log_api_usage('ipqs', False)
            return {'status': 'error', 'fraud_score': 0}


    def get_enhanced_geo_data(self, ip: str, abuseipdb_key: Optional[str] = None) -> Dict:
        """
        Get enhanced geographic data with smart source selection

        Args:
            ip: IP address to check
            abuseipdb_key: Optional AbuseIPDB API key

        Returns:
            Dictionary with geographic data and source metadata
        """
        # Get data from both sources
        geoip_data = self.lookup_geoip(ip)
        abuseipdb_data = self.lookup_abuseipdb(ip, abuseipdb_key)

        # Select primary source based on AbuseIPDB confidence
        primary_source = self._select_primary_source(abuseipdb_data)

        # Merge data based on selected source
        enhanced_data = self._merge_geo_data(geoip_data, abuseipdb_data, primary_source)

        # Add source metadata
        enhanced_data.update({
            'data_source': primary_source,
            'abuseipdb_confidence': abuseipdb_data.get('confidence_score', 0),
            'ip_address': ip
        })

        return enhanced_data

    def _select_primary_source(self, abuseipdb_data: Dict) -> str:
        """
        Select primary data source based on AbuseIPDB confidence score

        Args:
            abuseipdb_data: AbuseIPDB lookup results

        Returns:
            'abuseipdb' if confidence > 50, 'geoip' otherwise
        """
        confidence = abuseipdb_data.get('confidence_score', 0)

        if confidence > 50 and abuseipdb_data.get('status') == 'success':
            return 'abuseipdb'
        else:
            return 'geoip'

    def _merge_geo_data(self, geoip_data: Dict, abuseipdb_data: Dict, primary_source: str) -> Dict:
        """
        Merge geographic data from both sources based on priority

        Args:
            geoip_data: GeoIP lookup results
            abuseipdb_data: AbuseIPDB lookup results
            primary_source: Selected primary source ('abuseipdb' or 'geoip')

        Returns:
            Merged geographic data dictionary
        """
        merged_data = {
            'country': None,
            'city': None,
            'isp': None,
            'usage_type': None,
            'domain': None
        }

        if primary_source == 'abuseipdb':
            # Prioritize AbuseIPDB data, fall back to GeoIP
            merged_data.update({
                'country': abuseipdb_data.get('country') or geoip_data.get('country'),
                'isp': abuseipdb_data.get('isp') or geoip_data.get('isp'),
                'usage_type': abuseipdb_data.get('usage_type'),
                'domain': abuseipdb_data.get('domain'),
                'city': geoip_data.get('city')  # GeoIP has better city data
            })
        else:
            # Prioritize GeoIP data, supplement with AbuseIPDB
            merged_data.update({
                'country': geoip_data.get('country'),
                'city': geoip_data.get('city'),
                'isp': geoip_data.get('isp'),
                'usage_type': abuseipdb_data.get('usage_type'),
                'domain': abuseipdb_data.get('domain')
            })

        return merged_data


    def reverse_dns(self, ip: str) -> str:
        """
        Perform reverse DNS lookup

        Args:
            ip: IP address to resolve

        Returns:
            Hostname string, or "N/A" if lookup fails
        """
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "N/A"
