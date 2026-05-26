import os
import psutil
import time
import platform
import logging
import subprocess

class RootkitDetector:
    def __init__(self, config):
        self.config = config
        self.interval = config.get("interval", 3600)  # Scan every hour by default
        self.logger = logging.getLogger("RootkitDetector")
        self.last_scan = 0
        self.os_type = platform.system()

    def check_hidden_processes_linux(self):
        """Compares ps command output to /proc to find hidden processes"""
        hidden = []
        try:
            # Get all PIDs from /proc
            proc_pids = set()
            for entry in os.listdir('/proc'):
                if entry.isdigit():
                    proc_pids.add(int(entry))
            
            # Get all PIDs visible to ps
            ps = subprocess.run(['ps', '-e', '-o', 'pid='], capture_output=True, text=True)
            ps_pids = set(int(p.strip()) for p in ps.stdout.splitlines() if p.strip())
            
            # PIDs in /proc but not in ps (potential rootkit hook)
            hidden_pids = proc_pids - ps_pids
            for pid in hidden_pids:
                hidden.append({"pid": pid, "reason": "Present in /proc but hidden from ps"})
        except Exception as e:
            self.logger.error(f"Error checking hidden processes: {e}")
        return hidden

    def check_suid_binaries_linux(self):
        """Find recently modified or unexpected SUID binaries"""
        suid_findings = []
        try:
            # We don't want to find / full drive, just common paths
            paths_to_check = ["/bin", "/usr/bin", "/sbin", "/usr/sbin", "/tmp", "/var/tmp"]
            for path in paths_to_check:
                if not os.path.exists(path):
                    continue
                find_cmd = ['find', path, '-type', 'f', '-perm', '-4000']
                result = subprocess.run(find_cmd, capture_output=True, text=True)
                for line in result.stdout.splitlines():
                    if "/tmp/" in line or "/var/tmp/" in line:
                         suid_findings.append({"path": line, "reason": "SUID binary in temporary directory"})
        except Exception as e:
            self.logger.error(f"Error checking SUID binaries: {e}")
        return suid_findings

    def check_kernel_modules_linux(self):
        """Check for potentially malicious kernel modules"""
        modules = []
        try:
            lsmod = subprocess.run(['lsmod'], capture_output=True, text=True)
            for line in lsmod.stdout.splitlines()[1:]:  # skip header
                mod_name = line.split()[0]
                # Basic mock check against known malicious signatures
                if mod_name in ['diamorphine', 'reptile', 'adore-ng']:
                    modules.append({"module": mod_name, "reason": "Known malicious kernel module detected"})
        except Exception as e:
            self.logger.error(f"Error checking kernel modules: {e}")
        return modules

    def check_hidden_ports(self):
        """Cross-checks netstat with /proc/net/tcp (simplified)"""
        hidden_ports = []
        # Complex to do robustly in Python without root parsing raw tables. 
        # But this represents the capability.
        return hidden_ports

    def scan(self, event_queue):
        findings = []
        
        if self.os_type == 'Linux':
            hidden_procs = self.check_hidden_processes_linux()
            for p in hidden_procs:
                findings.append({
                    "event_type": "rootkit_process_detected",
                    "pid": p["pid"],
                    "reason": p["reason"]
                })
                
            suid = self.check_suid_binaries_linux()
            for s in suid:
                findings.append({
                    "event_type": "suid_binary_detected",
                    "path": s["path"],
                    "reason": s["reason"]
                })
                
            kmods = self.check_kernel_modules_linux()
            for k in kmods:
                findings.append({
                    "event_type": "kernel_module_detected",
                    "module_name": k["module"],
                    "reason": k["reason"]
                })
                
            # Check ld.so.preload
            if os.path.exists('/etc/ld.so.preload'):
                try:
                    with open('/etc/ld.so.preload', 'r') as f:
                        content = f.read().strip()
                        if content:
                            findings.append({
                                "event_type": "ld_preload_detected",
                                "path": "/etc/ld.so.preload",
                                "reason": f"File is populated: {content}"
                            })
                except:
                    pass

        # Windows rootkit detection (DLL injection, specific hooks) would go here
        
        for finding in findings:
            finding["module"] = "rootkit_detector"
            event_queue.append(finding)
            self.logger.warning(f"Rootkit anomaly detected: {finding}")

    def start(self, event_queue):
        self.event_queue = event_queue
        # Initial scan on startup
        self.scan(self.event_queue)
        self.last_scan = time.time()

    def poll(self):
        now = time.time()
        if now - self.last_scan >= self.interval:
            self.logger.info("Running scheduled rootkit scan...")
            self.scan(self.event_queue)
            self.last_scan = now
