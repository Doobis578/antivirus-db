import os
import hashlib
import json
import urllib.request
import shutil
import time
import threading
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog

# Define the standard EICAR signature string
EICAR_SIGNATURE = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
DANGEROUS_EXTENSIONS = [".exe", ".bat", ".cmd", ".dll", ".ps1", ".vbs", ".js", ".txt", ".com"]

class QuarantineHandler:
    @staticmethod
    def isolate(file_path, virus_name, filename):
        import winsound
        winsound.Beep(1000, 400)
        
        QUARANTINE_DIR = r"C:\Antivirus_Quarantine"
        if not os.path.exists(QUARANTINE_DIR): 
            os.makedirs(QUARANTINE_DIR)
        
        safe_virus_name = virus_name.replace(".", "_")
        dest_file_name = f"{safe_virus_name}_{filename}.locked"
        dest_path = os.path.join(QUARANTINE_DIR, dest_file_name)
        
        try:
            shutil.move(file_path, dest_path)
        except Exception:
            pass

class AntivirusApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Antivirus DB - Secure Scanner")
        self.root.geometry("650x540")
        self.root.configure(bg="#f3f4f6")
        
        self.virus_database = {}
        self.scanning = False
        self.target_folder = "."
        
        # Native Real-time monitor variables
        self.monitor_active = tk.BooleanVar(value=False)
        self.known_files = {} # Keeps track of file paths and their last modified times
        
        self.setup_ui()
        threading.Thread(target=self.sync_database, daemon=True).start()
        threading.Thread(target=self.native_realtime_monitor, daemon=True).start()

    def setup_ui(self):
        header = tk.Label(self.root, text="🛡️ Antivirus DB Control Center", font=("Segoe UI", 16, "bold"), bg="#1e3a8a", fg="white", pady=15)
        header.pack(fill=tk.X)
        
        dir_frame = tk.Frame(self.root, bg="#f3f4f6", pady=10)
        dir_frame.pack(fill=tk.X, padx=20)
        
        self.path_label = tk.Label(dir_frame, text="Target: Current Workspace Folder (.)", font=("Segoe UI", 10), bg="#f3f4f6", fg="#374151")
        self.path_label.pack(side=tk.LEFT, padx=5)
        
        self.browse_btn = ttk.Button(dir_frame, text="Select Folder", command=self.browse_folder)
        self.browse_btn.pack(side=tk.RIGHT, padx=5)
        
        control_frame = tk.Frame(self.root, bg="#f3f4f6", pady=5)
        control_frame.pack(fill=tk.X, padx=20)
        
        self.scan_btn = tk.Button(control_frame, text="🚀 Start System Scan", font=("Segoe UI", 11, "bold"), bg="#10b981", fg="white", bd=0, padx=15, pady=8, command=self.start_scan_thread)
        self.scan_btn.pack(side=tk.LEFT)
        
        # Real-Time Shield Toggle Switch UI
        self.monitor_check = tk.Checkbutton(control_frame, text="🛡️ Live Protection Shield", variable=self.monitor_active, font=("Segoe UI", 10, "bold"), fg="#1e3a8a", bg="#f3f4f6", activebackground="#f3f4f6", command=self.toggle_monitor_status)
        self.monitor_check.pack(side=tk.LEFT, padx=20, pady=10)
        
        self.status_text = tk.Label(control_frame, text="Connecting to cloud signatures...", font=("Segoe UI", 10, "italic"), bg="#f3f4f6", fg="#6b7280")
        self.status_text.pack(side=tk.RIGHT, pady=10)
        
        self.progress = ttk.Progressbar(self.root, orient="horizontal", mode="determinate")
        self.progress.pack(fill=tk.X, padx=20, pady=10)
        
        log_frame = tk.Frame(self.root, bg="#f3f4f6")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=5)
        
        self.tree = ttk.Treeview(log_frame, columns=("Status", "File Path"), show="headings")
        self.tree.heading("Status", text="Scan Result Verdict")
        self.tree.heading("File Path", text="Target System File Path")
        self.tree.column("Status", width=120, anchor=tk.CENTER)
        self.tree.column("File Path", width=480, anchor=tk.W)
        self.tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(fill=tk.Y, side=tk.RIGHT)

    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.target_folder = folder
            self.path_label.config(text=f"Target: {folder}")
            self.known_files.clear()

    def toggle_monitor_status(self):
        if self.monitor_active.get():
            self.status_text.config(text="🛡️ Live Protection Shield Active", fg="#047857")
            self.initialize_monitor_baseline()
        else:
            self.status_text.config(text="⚠️ Live Protection Disabled", fg="#b45309")

    def initialize_monitor_baseline(self):
        # Index existing files so they are not flagged as new when starting the engine
        try:
            for root, dirs, files in os.walk(self.target_folder):
                if "Antivirus_Quarantine" in root:
                    continue
                for filename in files:
                    file_path = os.path.join(root, filename)
                    try:
                        self.known_files[file_path] = os.path.getmtime(file_path)
                    except Exception:
                        pass
        except Exception:
            pass

    def native_realtime_monitor(self):
        # Pure Python background monitor loop
        while True:
            time.sleep(1.0) # Check the target directory once every second
            if not self.monitor_active.get() or self.scanning:
                continue
                
            try:
                for root, dirs, files in os.walk(self.target_folder):
                    if "Antivirus_Quarantine" in root:
                        continue
                    for filename in files:
                        _, ext = os.path.splitext(filename.lower())
                        if ext not in DANGEROUS_EXTENSIONS or filename in ["scanner.py", "signatures.json", "watchman.py"]:
                            continue
                            
                        file_path = os.path.join(root, filename)
                        try:
                            mtime = os.path.getmtime(file_path)
                            # Scan if file is completely new or its modified time has changed
                            if file_path not in self.known_files or mtime > self.known_files[file_path]:
                                self.known_files[file_path] = mtime
                                self.scan_single_file_realtime(file_path, filename)
                        except Exception:
                            pass
            except Exception:
                pass

    def scan_single_file_realtime(self, file_path, filename):
        try:
            if not os.path.exists(file_path):
                return
            with open(file_path, "rb") as f:
                file_bytes = f.read()
            
            file_hash = hashlib.sha256(file_bytes).hexdigest()
            file_text = file_bytes.decode("utf-8", errors="ignore")
            
            virus_name = None
            if file_hash in self.virus_database:
                virus_name = self.virus_database[file_hash]
            elif EICAR_SIGNATURE in file_text:
                virus_name = "EICAR.TestFile.Virus"

            if virus_name:
                self.root.after(0, lambda: self.tree.insert("", 0, values=("🚨 REAL-TIME", f"[{virus_name}] {filename}")))
                QuarantineHandler.isolate(file_path, virus_name, filename)
        except Exception:
            pass

    def sync_database(self):
        GITHUB_USER = "doobis587"
        REPO_NAME = "antivirus-db"
        
        CLOUD_DB_URL = f"https://githubusercontent.com{GITHUB_USER}/{REPO_NAME}/main/signatures.json"
        try:
            req = urllib.request.Request(CLOUD_DB_URL, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode())
                self.virus_database = data.get("signatures", {})
                self.status_text.config(text="✅ Cloud Signatures Synchronized", fg="#047857")
        except Exception:
            self.status_text.config(text="⚠️ Offline Mode Active (Fallback)", fg="#b45309")
            self.virus_database = {"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824": "Trojan.Generic.Hello"}

    def start_scan_thread(self):
        if not self.scanning:
            self.scanning = True
            self.scan_btn.config(state=tk.DISABLED, bg="#9ca3af")
            self.browse_btn.config(state=tk.DISABLED)
            for item in self.tree.get_children():
                self.tree.delete(item)
            threading.Thread(target=self.execute_system_scan, daemon=True).start()

    def show_bright_completion_window(self, threats_count):
        alert = tk.Toplevel(self.root)
        alert.title("System Health Report")
        alert.geometry("380x200")
        
        if threats_count > 0:
            bg_color = "#fef2f2"
            text_color = "#dc2626"
            title_text = "⚠️ THREATS IDENTIFIED"
            summary_text = f"Security scan complete.\n\n[{threats_count}] dynamic threat signatures were matched\nand moved into secure isolation quarantine."
        else:
            bg_color = "#f0fdf4"
            text_color = "#16a34a"
            title_text = "✨ SYSTEM FULLY SECURE"
            summary_text = "Security scan complete.\n\nNo malware signatures or threat behaviors\nwere detected on your system storage drives."

        alert.configure(bg=bg_color)
        alert.transient(self.root)
        alert.grab_set()
        
        tk.Label(alert, text=title_text, font=("Segoe UI", 14, "bold"), bg=bg_color, fg=text_color, pady=15).pack()
