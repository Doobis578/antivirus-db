import os
import hashlib
import json

def load_virus_database():
    try:
        with open("signatures.json", "r") as db_file:
            data = json.load(db_file)
            # This loads our hashes mapped to their specific names
            return data.get("signatures", {})
    except Exception as e:
        print(f"Error loading signatures.json: {e}")
        return {}

def scan_entire_folder(folder_path):
    virus_database = load_virus_database()
    print(f"--- Starting Full System Scan on Folder: {folder_path} ---")
    print(f"Loaded {len(virus_database)} virus signatures.\n")
    
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        
        if os.path.isdir(file_path) or filename in ["scanner.py", "signatures.json", ".gitignore"]:
            continue
            
        print(f"Scanning: {filename}...")
        
        try:
            with open(file_path, "rb") as file:
                file_bytes = file.read()
                file_hash = hashlib.md5(file_bytes).hexdigest()
                
            print(f"-> Fingerprint: {file_hash}")
            
            # Check if the hash matches a key in our database dictionary
            if file_hash in virus_database:
                virus_name = virus_database[file_hash]
                print(f"❌ WARNING: DETECTED [{virus_name}] IN {filename}!\n")
            else:
                print(f"✅ {filename} is safe.\n")
                
        except Exception as e:
            print(f"Could not scan {filename}: {e}\n")

scan_entire_folder(".")
