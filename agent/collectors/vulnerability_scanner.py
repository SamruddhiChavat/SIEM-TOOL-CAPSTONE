import os
import subprocess
import logging
import platform
import json
import time

class VulnScanner:
    def __init__(self, config):
        self.config = config
        self.interval = config.get("interval", 86400) # Default: once a day (seconds)
        self.logger = logging.getLogger("VulnScanner")
        self.last_scan = 0
        
    def get_linux_inventory(self):
        inventory = []
        try:
            # Detect package manager
            if os.path.exists("/usr/bin/dpkg"):
                # Debian/Ubuntu
                result = subprocess.run(["dpkg-query", "-W", "-f=${Package}||${Version}||${Architecture}\n"], 
                                      capture_output=True, text=True)
                for line in result.stdout.splitlines():
                    if '||' in line:
                        pkg, ver, arch = line.split("||", 2)
                        inventory.append({"package": pkg, "version": ver, "arch": arch, "os": "debian-based"})
            elif os.path.exists("/usr/bin/rpm"):
                # RHEL/CentOS
                result = subprocess.run(["rpm", "-qa", "--qf", "%{NAME}||%{VERSION}||%{ARCH}\n"], 
                                      capture_output=True, text=True)
                for line in result.stdout.splitlines():
                    if '||' in line:
                        pkg, ver, arch = line.split("||", 2)
                        inventory.append({"package": pkg, "version": ver, "arch": arch, "os": "rhel-based"})
                        
            # Get pip packages if python3 is available
            try:
                result = subprocess.run(["pip3", "list", "--format=json"], capture_output=True, text=True)
                if result.returncode == 0:
                    pip_pkgs = json.loads(result.stdout)
                    for p in pip_pkgs:
                        inventory.append({"package": p["name"], "version": p["version"], "type": "python-pip"})
            except FileNotFoundError:
                pass
                
        except Exception as e:
            self.logger.error(f"Error gathering Linux inventory: {e}")
        return inventory

    def get_windows_inventory(self):
        inventory = []
        try:
            # Get from WMI
            cmd = 'Get-WmiObject -Class Win32_Product | Select-Object -Property Name, Version, Vendor | ConvertTo-Json'
            result = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)
            if result.stdout.strip():
                try:
                    pkgs = json.loads(result.stdout)
                    if isinstance(pkgs, dict):
                        pkgs = [pkgs]
                    for p in pkgs:
                        if p.get("Name") and p.get("Version"):
                            inventory.append({
                                "package": p["Name"], 
                                "version": p["Version"], 
                                "vendor": p.get("Vendor", ""),
                                "os": "windows"
                            })
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            self.logger.error(f"Error gathering Windows inventory: {e}")
        return inventory

    def collect_inventory(self):
        if platform.system() == "Windows":
            return self.get_windows_inventory()
        else:
            return self.get_linux_inventory()

    def start(self, event_queue):
        self.event_queue = event_queue
        # We don't block startup, we'll collect it in the first poll

    def poll(self):
        now = time.time()
        if now - self.last_scan >= self.interval:
            self.logger.info("Starting software inventory scan for vulnerability detection...")
            inventory = self.collect_inventory()
            
            if inventory:
                self.event_queue.append({
                    "module": "vuln_scanner",
                    "event_type": "software_inventory",
                    "inventory": inventory
                })
                self.logger.info(f"Inventory collected: {len(inventory)} packages.")
            
            self.last_scan = now
