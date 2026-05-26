import os
import time
import subprocess
import yaml
import logging
import platform

class SecurityConfigurationAssessment:
    def __init__(self, config):
        self.config = config
        self.interval = config.get("interval", 43200) # Default: 12 hours
        self.policies_dir = config.get("policies_dir", "config/policies")
        self.logger = logging.getLogger("SCA")
        self.last_scan = 0
        self.os_type = platform.system()

    def load_policies(self):
        policies = []
        if not os.path.exists(self.policies_dir):
            return policies
            
        for filename in os.listdir(self.policies_dir):
            if filename.endswith(".yml") or filename.endswith(".yaml"):
                # Basic OS filtering
                if self.os_type == "Windows" and "linux" in filename.lower():
                    continue
                if self.os_type == "Linux" and "windows" in filename.lower():
                    continue
                    
                path = os.path.join(self.policies_dir, filename)
                try:
                    with open(path, 'r') as f:
                        policies.append(yaml.safe_load(f))
                except Exception as e:
                    self.logger.error(f"Error loading policy {filename}: {e}")
        return policies

    def run_check(self, check):
        """Execute a single policy check command"""
        cmd = check.get("command")
        if not cmd:
            return "failed", "No command specified"
            
        try:
            # Need to specify shell depending on OS
            if self.os_type == "Windows":
                result = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True, timeout=10)
            else:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                
            output = result.stdout.strip()
            expected = str(check.get("expected", ""))
            
            # Simple evaluation
            if check.get("condition") == "equals":
                passed = output == expected
            elif check.get("condition") == "contains":
                passed = expected in output
            elif check.get("condition") == "not_equals":
                passed = output != expected
            else:
                passed = output == expected # default to equals
                
            return "passed" if passed else "failed", output
            
        except subprocess.TimeoutExpired:
            return "failed", "Command timed out"
        except Exception as e:
            return "failed", f"Execution error: {str(e)}"

    def start(self, event_queue):
        self.event_queue = event_queue
        self.last_scan = 0  # Forces first scan immediately

    def poll(self):
        if not hasattr(self, 'event_queue'):
            return  # Guard: don't poll before start() is called
        now = time.time()
        if now - self.last_scan >= self.interval:
            self.logger.info("Starting Security Configuration Assessment (SCA)...")
            policies = self.load_policies()
            
            for policy in policies:
                policy_id = policy.get("policy_id", "unknown")
                results = []
                
                for check in policy.get("checks", []):
                    status, output = self.run_check(check)
                    results.append({
                        "check_id": check.get("id"),
                        "title": check.get("title"),
                        "status": status,
                        "description": check.get("description", ""),
                        "remediation": check.get("remediation", "")
                    })
                
                # Calculate score
                passed = sum(1 for r in results if r["status"] == "passed")
                total = len(results)
                score = int((passed / total) * 100) if total > 0 else 0
                
                self.event_queue.append({
                    "module": "sca",
                    "event_type": "sca_scan_result",
                    "policy_id": policy_id,
                    "policy_name": policy.get("name"),
                    "score": score,
                    "total_checks": total,
                    "passed_checks": passed,
                    "results": results
                })
                
            self.logger.info(f"SCA scan completed for {len(policies)} policies.")
            self.last_scan = now
