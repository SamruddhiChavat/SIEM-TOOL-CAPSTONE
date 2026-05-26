import os
import requests
import logging
from functools import lru_cache
import time

logger = logging.getLogger(__name__)

class ThreatIntel:
    def __init__(self):
        self.vt_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.abuse_key = os.getenv("ABUSEIPDB_API_KEY")

    @lru_cache(maxsize=1024)
    def _cached_ip_check(self, ip_address, cache_buster):
        """Internal cached method. Cache buster used to reset cache periodically if needed."""
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.abuse_key, "Accept": "application/json"}
        params = {"ipAddress": ip_address, "maxAgeInDays": "30"}
        
        resp = requests.get(url, headers=headers, params=params, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            score = data["data"]["abuseConfidenceScore"]
            return {"malicious": score > 50, "score": score, "source": "AbuseIPDB"}
        elif resp.status_code == 429:
            logger.warning("AbuseIPDB rate limit reached. Falling back.")
            return {"malicious": False, "score": 0, "source": "RateLimited"}
        else:
            logger.error(f"AbuseIPDB returned {resp.status_code}")
            return {"malicious": False, "score": 0, "source": "APIError"}

    def check_ip(self, ip_address):
        """Check IP against AbuseIPDB and fallback logic"""
        if ip_address.startswith("10.") or \
           ip_address.startswith("192.168.") or \
           ip_address.startswith("172.") or \
           len(ip_address) < 7:
            return {"malicious": False, "score": 0, "source": "internal"}

        if self.abuse_key:
            try:
                # Use hour-based cache buster to refresh cache every hour
                return self._cached_ip_check(ip_address, int(time.time()) // 3600)
            except requests.exceptions.Timeout:
                logger.warning(f"AbuseIPDB timeout for {ip_address}")
            except Exception as e:
                logger.error(f"Threat intel lookup failed: {e}")

        return {"malicious": False, "score": 0, "source": "bypass"}

    @lru_cache(maxsize=1024)
    def _cached_hash_check(self, file_hash, cache_buster):
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": self.vt_key}
        resp = requests.get(url, headers=headers, timeout=5)
        if resp.status_code == 200:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            malicious_count = stats.get("malicious", 0)
            return {"malicious": malicious_count > 3, "score": malicious_count, "source": "VirusTotal"}
        elif resp.status_code == 429:
            logger.warning("VirusTotal rate limit reached.")
            return {"malicious": False, "score": 0, "source": "RateLimited"}
        else:
            return {"malicious": False, "score": 0, "source": "APIError"}

    def check_hash(self, file_hash):
        """Check hash against VirusTotal"""
        if self.vt_key:
            try:
                return self._cached_hash_check(file_hash, int(time.time()) // 3600)
            except requests.exceptions.Timeout:
                logger.warning(f"VT timeout for {file_hash}")
            except Exception as e:
                logger.error(f"VT Hash lookup failed: {e}")
                
        return {"malicious": False, "score": 0, "source": "bypass"}
