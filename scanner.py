import os
import hashlib
import json
import urllib.request
import shutil
import time
import threading
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

EICAR_SIGNATURE = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
DANGEROUS_EXTENSIONS = [".exe", ".bat", ".cmd", ".dll", ".ps1", ".vbs", ".js", ".txt", ".com"]
QUARANTINE_DIR = r"C:\Antivirus_Quarantine"

HEURISTIC_KEYWORDS = [
    "powershell -enc",
    "iex(",
    "invoke-expression",
    "downloadstring",
    "createobject(\"wscript.shell\")"
]

class QuarantineHandler:
    @staticmethod
    def isolate(file_path, virus_name, filename):
        import winsound
        winsound.Beep(1000, 400)
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
        self.root.title("Antivirus DB - Advanced Security Suite")
        self.root.geometry("700x580")
        self.root.configure(bg="#f3f4f6")
        
        self.virus_database = {}
        self.scanning = False
        self.target_folder = "."
        self.monitor_active = tk.BooleanVar(value=False)
        self.known_files = {}
        
        self.setup_ui()
        threading.Thread(target=self.sync_database, daemon=True).start()
        threading.Thread(target=self.native_realtime_monitor, daemon=True).start()

    def setup_ui(self):
        header = tk.Label(self.root, text="🛡️ Advanced Antivirus & Threat Control", font=("Segoe UI", 15, "bold"), bg="#1e3a8a", fg="white", pady=12)
        header.pack(fill=tk.X)
        
        dir_frame = tk.Frame(self.root, bg="#f3f4f6", pady=8)
        dir_frame.pack(fill=tk.X, padx=20)
        self.path_label = tk.Label(dir_frame, text="Target: Current Workspace Folder (.)", font=("Segoe UI", 9), bg="#f3f4f6", fg="#374151")
        self.path_label.pack(side=tk.LEFT, padx=5)
        self.browse_btn = ttk.Button(dir_frame, text="Select Folder", command=self.browse_folder)
        self.browse_btn.pack(side=tk.RIGHT, padx=5)
        
        control_frame = tk.Frame(self.root, bg="#f3f4f6", pady=5)
        control_frame.pack(fill=tk.X, padx=20)
        self.scan_btn = tk.Button(control_frame, text="🚀 Start Scan", font=("Segoe UI", 10, "bold"), bg="#10b981", fg="white", bd=0, padx=12, pady=6, command=self.start_scan_thread)
        self.scan_btn.pack(side=tk.LEFT)
        self.monitor_check = tk.Checkbutton(control_frame, text="🛡️ Live Shield", variable=self.monitor_active, font=("Segoe UI", 9, "bold"), fg="#1e3a8a", bg="#f3f4f6", command=self.toggle_monitor_status)
        self.monitor_check.pack(side=tk.LEFT, padx=15)
        self.quarantine_btn = tk.Button(control_frame, text="🔒 Quarantine Manager", font=("Segoe UI", 9, "bold"), bg="#4b5563", fg="white", bd=0, padx=10, pady=6, command=self.open_quarantine_manager)
        self.quarantine_btn.pack(side=tk.LEFT, padx=5)
        
        self.status_text = tk.Label(control_frame, text="Syncing cloud database...", font=("Segoe UI", 9, "italic"), bg="#f3f4f6", fg="#6b7280")
        self.status_text.pack(side=tk.RIGHT, pady=5)
        
        self.progress = ttk.Progressbar(self.root, orient="horizontal", mode="determinate")
        self.progress.pack(fill=tk.X, padx=20, pady=8)
        
        log_frame = tk.Frame(self.root, bg="#f3f4f6")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=5)
        self.tree = ttk.Treeview(log_frame, columns=("Status", "File Path"), show="headings")
        self.tree.heading("Status", text="Verdict")
        self.tree.heading("File Path", text="Target Path / Threat Details")
        self.tree.column("Status", width=120, anchor=tk.CENTER)
        self.tree.column("File Path", width=520, anchor=tk.W)
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
            self.status_text.config(text="🛡️ Live Shield Active", fg="#047857")
            self.initialize_baseline()
        else:
            self.status_text.config(text="⚠️ Live Shield Off", fg="#b45309")

    def initialize_baseline(self):
        try:
            for root, _, files in os.walk(self.target_folder):
                if "Antivirus_Quarantine" in root: continue
                for f in files:
                    p = os.path.join(root, f)
                    try: self.known_files[p] = os.path.getmtime(p)
                    except: pass
        except: pass

    def native_realtime_monitor(self):
        while True:
            time.sleep(1.0)
            if not self.monitor_active.get() or self.scanning: continue
            try:
                for root, _, files in os.walk(self.target_folder):
                    if "Antivirus_Quarantine" in root: continue
                    for filename in files:
                        _, ext = os.path.splitext(filename.lower())
                        if ext not in DANGEROUS_EXTENSIONS: continue
                        p = os.path.join(root, filename)
                        try:
                            mtime = os.path.getmtime(p)
                            if p not in self.known_files or mtime > self.known_files[p]:
                                self.known_files[p] = mtime
                                self.evaluate_file(p, filename, real_time=True)
                        except: pass
            except: pass

    def evaluate_file(self, file_path, filename, real_time=False):
        try:
            if not os.path.exists(file_path): return
            with open(file_path, "rb") as f:
                content = f.read()
            
            file_hash = hashlib.sha256(content).hexdigest()
            text_lower = content.decode("utf-8", errors="ignore").lower()
            
            virus_name = None
            if file_hash in self.virus_database:
                virus_name = self.virus_database[file_hash]
            elif EICAR_SIGNATURE.lower() in text_lower:
                virus_name = "EICAR.TestFile.Virus"
            else:
                for keyword in HEURISTIC_KEYWORDS:
                    if keyword in text_lower:
                        virus_name = f"Heuristic.Suspicious.Pattern ({keyword})"
                        break

            if virus_name:
                prefix = "🚨 REAL-TIME" if real_time else "❌ DANGER"
                self.root.after(0, lambda: self.tree.insert("", 0, values=(prefix, f"[{virus_name}] {filename}")))
                QuarantineHandler.isolate(file_path, virus_name, filename)
        except: pass

    def open_quarantine_manager(self):
        q_win = tk.Toplevel(self.root)
        q_win.title("Secure Isolation Quarantine Manager")
        q_win.geometry("500x350")
        q_win.configure(bg="#f3f4f6")
        
        tk.Label(q_win, text="🔒 Quarantined Locked Items", font=("Segoe UI", 12, "bold"), bg="#f3f4f6", fg="#1f2937", pady=10).pack()
        
        list_frame = tk.Frame(q_win, bg="#f3f4f6")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=15)
        
        q_listbox = tk.Listbox(list_frame, font=("Segoe UI", 9))
        q_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        def refresh_q_list():
            q_listbox.delete(0, tk.END)
            if os.path.exists(QUARANTINE_DIR):
                for item in os.listdir(QUARANTINE_DIR):
                    q_listbox.insert(tk.END, item)
                    
        refresh_q_list()
        
        btn_frame = tk.Frame(q_win, bg="#f3f4f6", pady=10)
        btn_frame.pack(fill=tk.X)
        
        def restore_selected():
            try:
                sel = q_listbox.get(q_listbox.curselection())
                src = os.path.join(QUARANTINE_DIR, sel)
                parts = sel.split("_", 1)
                # FIX: Successfully processes list subscripts cleanly for compilation
                orig_name = parts[1].replace(".locked", "") if len(parts) > 1 else sel.replace(".locked", "")
                dst = os.path.join(self.target_folder, orig_name)
                shutil.move(src, dst)
                refresh_q_list()
                messagebox.showinfo("Restored", "File restored safely to working directory.")
            except Exception as e:
                messagebox.showwarning("Error", f"Failed to restore: {str(e)}")

        def delete_selected():
            try:
                sel = q_listbox.get(q_listbox.curselection())
                os.remove(os.path.join(QUARANTINE_DIR, sel))
                refresh_q_list()
            except:
                messagebox.showwarning("Error", "Please select an item to delete permanently.")

        ttk.Button(btn_frame, text="Restore File", command=restore_selected).pack(side=tk.LEFT, padx=20)
        ttk.Button(btn_frame, text="Delete Permanently", command=delete_selected).pack(side=tk.LEFT, padx=5)

    def sync_database(self):
        GITHUB_USER = "doobis587"
        REPO_NAME = "antivirus-db"
        CLOUD_DB_URL = f"https://githubusercontent.com{GITHUB_USER}/{REPO_NAME}/main/signatures.json"
        try:
            req = urllib.request.Request(CLOUD_DB_URL, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
