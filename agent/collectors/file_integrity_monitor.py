import os
import time
import hashlib
import stat
import logging
import pwd
import platform

class FileIntegrityMonitor:
    def __init__(self, config):
        self.config = config
        self.interval = config.get("interval", 60)
        self.directories = config.get("directories", [])
        self.logger = logging.getLogger("FIM")
        self.state = {} # filepath -> {hash, size, mtime, owner, permissions}
        
    def hash_file(self, filepath):
        hasher = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (IOError, OSError) as e:
            return None

    def get_file_metadata(self, filepath):
        try:
            st = os.stat(filepath)
            
            # Try to get owner name (Linux specific, fallback to UID on Windows/Failures)
            owner = str(st.st_uid)
            if platform.system() != 'Windows':
                try:
                    owner = pwd.getpwuid(st.st_uid).pw_name
                except KeyError:
                    pass

            return {
                "size": st.st_size,
                "mtime": st.st_mtime,
                "permissions": oct(stat.S_IMODE(st.st_mode)),
                "owner": owner
            }
        except OSError:
            return None

    def scan_directory(self, directory):
        current_files = set()
        
        if not os.path.exists(directory):
            return current_files

        for root, _, files in os.walk(directory):
            for filename in files:
                filepath = os.path.join(root, filename)
                current_files.add(filepath)
                
                meta = self.get_file_metadata(filepath)
                if not meta:
                    continue
                
                # Check if new file
                if filepath not in self.state:
                    file_hash = self.hash_file(filepath)
                    self.state[filepath] = {
                        "hash": file_hash,
                        **meta
                    }
                    self.event_queue.append({
                        "module": "fim",
                        "event_type": "file_created",
                        "file_path": filepath,
                        "new_hash": file_hash,
                        "file_size": meta["size"],
                        "owner": meta["owner"],
                        "permissions": meta["permissions"]
                    })
                    continue
                
                # Check for modifications
                old_state = self.state[filepath]
                changed = False
                change_type = []
                
                if old_state["mtime"] != meta["mtime"] or old_state["size"] != meta["size"]:
                    new_hash = self.hash_file(filepath)
                    if new_hash != old_state["hash"]:
                        changed = True
                        change_type.append("content_modified")
                        old_hash = old_state["hash"]
                        old_state["hash"] = new_hash
                    old_state["mtime"] = meta["mtime"]
                    old_state["size"] = meta["size"]
                else:
                    new_hash = old_state["hash"]
                    old_hash = new_hash
                    
                if old_state["permissions"] != meta["permissions"]:
                    changed = True
                    change_type.append("permissions_changed")
                    old_state["permissions"] = meta["permissions"]
                    
                if old_state["owner"] != meta["owner"]:
                    changed = True
                    change_type.append("owner_changed")
                    old_state["owner"] = meta["owner"]
                    
                if changed:
                    self.event_queue.append({
                        "module": "fim",
                        "event_type": "file_modified",
                        "change_details": change_type,
                        "file_path": filepath,
                        "old_hash": old_hash,
                        "new_hash": new_hash,
                        "file_size": meta["size"],
                        "owner": meta["owner"],
                        "permissions": meta["permissions"]
                    })
                    
        return current_files

    def start(self, event_queue):
        self.event_queue = event_queue
        self.logger.info("Initializing FIM baseline scan...")
        for directory in self.directories:
            self.scan_directory(directory)
        self.logger.info(f"FIM baseline complete. Monitored files: {len(self.state)}")
        # Clear creation events from baseline so we don't spam the SIEM on startup
        self.event_queue.clear()
        
    def poll(self):
        current_all_files = set()
        
        # Scan for modifications and creations
        for directory in self.directories:
            files_in_dir = self.scan_directory(directory)
            current_all_files.update(files_in_dir)
            
        # Scan for deletions
        deleted_files = set(self.state.keys()) - current_all_files
        for filepath in list(deleted_files):
            old_meta = self.state.pop(filepath)
            self.event_queue.append({
                "module": "fim",
                "event_type": "file_deleted",
                "file_path": filepath,
                "old_hash": old_meta.get("hash"),
                "file_size": old_meta.get("size")
            })
