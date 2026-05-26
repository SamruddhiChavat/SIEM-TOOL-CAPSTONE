from fastapi import APIRouter
import httpx
import os

router = APIRouter()

VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")

@router.get("/ip/{ip_address}")
async def lookup_ip(ip_address: str):
    if ip_address.startswith("10.") or \
       ip_address.startswith("192.168.") or \
       ip_address.startswith("172.") or \
       len(ip_address) < 7:
        return {"malicious": False, "score": 0, "source": "internal"}

    if not ABUSE_KEY:
        return {"malicious": False, "score": 0, "source": "bypass"}
        
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSE_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip_address, "maxAgeInDays": "30"}
        
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=headers, params=params, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                score = data["data"]["abuseConfidenceScore"]
                return {"malicious": score > 50, "score": score, "source": "AbuseIPDB"}
            elif resp.status_code == 429:
                return {"malicious": False, "score": 0, "source": "RateLimited"}
            return {"malicious": False, "score": 0, "source": "APIError"}
    except Exception as e:
        return {"malicious": False, "score": 0, "source": "APIError", "error": str(e)}

@router.get("/hash/{file_hash}")
async def lookup_hash(file_hash: str):
    if not VT_KEY:
        return {"malicious": False, "score": 0, "source": "bypass"}
        
    try:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VT_KEY}
        
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=headers, timeout=5)
            if resp.status_code == 200:
                stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
                malicious_count = stats.get("malicious", 0)
                return {"malicious": malicious_count > 3, "score": malicious_count, "source": "VirusTotal"}
            elif resp.status_code == 429:
                return {"malicious": False, "score": 0, "source": "RateLimited"}
            return {"malicious": False, "score": 0, "source": "APIError"}
    except Exception as e:
        return {"malicious": False, "score": 0, "source": "APIError", "error": str(e)}
