import os
import json
import requests
from datetime import datetime

BAZAAR_URL = "https://abuse.ch"
FILE_PATH = "definitions.json"

def fetch_bazaar_hashes():
    data = {"query": "get_recent", "selector": "100"}
    try:
        response = requests.post(BAZAAR_URL, data=data, timeout=15)
        if response.status_code == 200:
            result = response.json()
            if result.get("query_status") == "ok":
                return [item["sha256_hash"] for item in result.get("data", [])]
    except Exception as e:
        print(f"Error connecting to API: {e}")
    return []

def update_database():
    existing_hashes = set()
    
    if os.path.exists(FILE_PATH) and os.path.getsize(FILE_PATH) > 0:
        try:
            with open(FILE_PATH, "r") as f:
                current_data = json.load(f)
                if isinstance(current_data, dict):
                    existing_hashes = set(current_data.get("hashes", []))
        except Exception as e:
            print(f"Warning reading existing file: {e}")

    new_hashes = fetch_bazaar_hashes()
    for h in new_hashes:
        existing_hashes.add(h)

    if not existing_hashes:
        existing_hashes.add("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")

    output = {
        "version": int(datetime.utcnow().strftime("%Y%m%d%H")),
        "hashes": list(existing_hashes)
    }

    with open(FILE_PATH, "w") as f:
        json.dump(output, f, indent=2)
    print(f"Database updated. Total hashes tracked: {len(existing_hashes)}")

if __name__ == "__main__":
    update_database()
