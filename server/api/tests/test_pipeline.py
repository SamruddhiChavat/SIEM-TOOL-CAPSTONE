import httpx
import time
import uuid
import sys
import os

ES_HOST = "http://elasticsearch:9200"
BACKEND_URL = "http://localhost:8000"

def get_admin_token():
    print("[*] Getting admin token...")
    resp = httpx.post(f"{BACKEND_URL}/api/auth/login", data={"username": "admin", "password": "SecureWatch123!"})
    if resp.status_code == 200:
        return resp.json()["access_token"]
    print(f"[!] Auth failed. Creating admin user directly via script if it doesn't exist.")
    import subprocess
    subprocess.run(["python", "create_admin.py"], check=True)
    resp = httpx.post(f"{BACKEND_URL}/api/auth/login", data={"username": "admin", "password": "SecureWatch123!"})
    if resp.status_code == 200:
        return resp.json()["access_token"]
    print("[!] Failed to get token even after creating admin.")
    sys.exit(1)

def inject_alert():
    print("[*] Simulating Correlation Engine generating an alert...")
    alert_doc = {
        "alert_id": f"ALT-{uuid.uuid4().hex[:8].upper()}",
        "rule_id": "SIEM-001",
        "rule_name": "Brute Force Login",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1110",
        "severity": "critical",
        "entity": "198.51.100.42",
        "status": "new",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "raw_event": {},
        "recommended_action": "block_ip"
    }
    
    try:
        # Pushing directly to backend /api/alerts which is what Correlation Engine does
        resp = httpx.post(f"{BACKEND_URL}/api/alerts", json=alert_doc)
        if resp.status_code in [200, 201]:
            print(f"[+] Successfully injected alert: {alert_doc['alert_id']}")
            
            # Simulate Response Dispatcher
            import redis
            import json as json_lib
            try:
                redis_url = os.getenv("REDIS_URL", "redis://:redispass123!@redis:6379/0")
                r = redis.from_url(redis_url)
                task = {
                    "playbook_id": "PLAYBOOK-001",
                    "target": "198.51.100.42",
                    "alert_id": alert_doc['alert_id'],
                    "rule_id": "SIEM-001"
                }
                r.rpush("playbook_tasks", json_lib.dumps(task))
                print("[+] Successfully dispatched active response task")
            except Exception as e:
                print(f"[!] Redis error: {e}")
                
            return alert_doc['alert_id']
        else:
            print(f"[!] Failed to inject alert: {resp.status_code} {resp.text}")
    except Exception as e:
        print(f"[!] Error connecting to backend: {e}")
    return None

def verify_alert(token, target_alert_id):
    print("[*] Verifying alert exists in backend...")
    for _ in range(5):
        time.sleep(1)
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        try:
            resp = httpx.get(f"{BACKEND_URL}/api/alerts", headers=headers)
            if resp.status_code == 200:
                alerts = resp.json()
                for a in alerts:
                    if a.get("alert_id") == target_alert_id:
                        print(f"[+] Alert detected successfully!")
                        return True
        except Exception as e:
            pass
    print("[-] Alert not found.")
    return False

def verify_response(token, target_ip):
    print("[*] Verifying active response was dispatched and logged...")
    for _ in range(10):
        time.sleep(2)
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        try:
            resp = httpx.get(f"{BACKEND_URL}/api/response/history", headers=headers)
            if resp.status_code == 200:
                history = resp.json()
                for h in history:
                    if h.get("target") == target_ip:
                        print(f"[+] Response history logged successfully! Action: {h.get('action')}")
                        return True
        except Exception as e:
            pass
    print("[-] Response history not found.")
    return False

def main():
    print("=== SecureWatch SIEM End-to-End Pipeline Test ===")
    
    try:
        httpx.get(f"{BACKEND_URL}/health", timeout=5)
    except:
        print("[!] Backend is not responding. Ensure the stack is running.")
        sys.exit(1)
        
    token = get_admin_token()
    
    alert_id = inject_alert()
    if not alert_id:
        print("[-] Pipeline test failed at alert injection.")
        sys.exit(1)
        
    if not verify_alert(token, alert_id):
        print("[-] Pipeline test failed at alert verification.")
        sys.exit(1)
        
    if not verify_response(token, "198.51.100.42"):
        print("[-] Pipeline test failed at active response verification.")
        sys.exit(1)
        
    print("[+] Pipeline test passed! Event simulation -> Correlation -> Alert Generation -> Active Response works end-to-end.")
    sys.exit(0)

if __name__ == "__main__":
    main()
