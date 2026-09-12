import os
import time
import hashlib
import json
import urllib.request
import shutil
import winsound
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Locate your Windows Downloads folder automatically
DOWNLOADS_DIR = os.path.join(os.path.expanduser("~"), "Downloads")
QUARANTINE_DIR = "C:\\Antivirus_Quarantine"
DATABASE_URL = "https://githubusercontent.com"

def fetch_signatures():
    try:
        with urllib.request.urlopen(DATABASE_URL, timeout=5) as response:
            data = json.loads(response.read().decode())
            return data.get("signatures", {})
    except Exception:
        print("⚠️ Running in offline defense mode. Using local signatures...")
        return {"5d41402abc4b2a76b9719d911017c592": "Trojan.Generic.Hello"}

class FileGuardHandler(FileSystemEventHandler):
    def __init__(self):
        self.virus_db = fetch_signatures()
        self.dangerous_exts = [".exe", ".bat", ".cmd", ".dll", ".ps1", ".vbs", ".js"]
        print(f"👀 Watchman Active! Shielding folder: {DOWNLOADS_DIR}")
        print(f"Loaded {len(self.virus_db)} cloud threat signatures. Standing guard...\n")

    def on_created(self, event):
        # Ignore new folders, only check files
        if event.is_directory:
            return
            
        file_path = event.src_path
        filename = os.path.basename(file_path)
        _, ext = os.path.splitext(filename.lower())
        
        # Fast Filter: Only check high-risk files
        if ext not in self.dangerous_exts:
            return
            
        print(f"⚡ File Event Detected: {filename} just landed in Downloads!")
        
        # Give the browser a brief moment to finish writing the file to disk
        time.sleep(1)
        
        try:
            with open(file_path, "rb") as f:
                file_hash = hashlib.md5(f.read()).hexdigest()
                
            if file_hash in self.virus_db:
                virus_name = self.virus_db[file_hash]
                print(f"\033[91m❌ ALERT: Intercepted known threat [{virus_name}] inside {filename}!\033[0m")
                
                # Sound the alarm!
                winsound.Beep(1200, 600)
                
                # Isolate immediately
                if not os.path.exists(QUARANTINE_DIR): 
                    os.makedirs(QUARANTINE_DIR)
                shutil.move(file_path, os.path.join(QUARANTINE_DIR, f"Watchman_Intercepted_{virus_name}_{filename}.locked"))
                print(f"🔒 ISOLATION COMPLETE: File quarantined securely to {QUARANTINE_DIR}\n")
            else:
                print(f"✅ Safe Check: {filename} fingerprint passed security review.\n")
        except Exception as e:
            print(f"⚠️ Could not complete scanning on {filename}: {e}\n")

if __name__ == "__main__":
    event_handler = FileGuardHandler()
    observer = Observer()
    observer.schedule(event_handler, path=DOWNLOADS_DIR, recursive=False)
    observer.start()
    
    try:
        while True:
            time.sleep(1)  # Keep the script running quietly in the background
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
