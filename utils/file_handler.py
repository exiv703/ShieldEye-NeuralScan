import json
import os
import logging
from datetime import datetime

DATA_DIR = 'data'
HISTORY_FILE = os.path.join(DATA_DIR, 'scan_history.json')
LEGACY_FILE = 'scan_history.json'
HISTORY_VERSION = 1

def load_scan_history():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return []
    if os.path.exists(LEGACY_FILE):
        try:
            with open(LEGACY_FILE, 'r') as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError):
            return []
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(HISTORY_FILE, 'w') as nf:
                json.dump(data, nf, indent=4)
        except (OSError, ValueError) as e:
            logging.warning("Failed to migrate legacy scan history to '%s': %s", HISTORY_FILE, e)
        return data
    return []

def save_scan_history(file_path, threat_count, security_score=0):
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
    except OSError as e:
        logging.error("Failed to create data directory '%s' for scan history: %s", DATA_DIR, e)
    history = load_scan_history()
    # Why: full path is required for rescan; security_score comes from scanner, not derived here
    new_entry = {
        'file': os.path.basename(file_path) if file_path else '',
        'file_path': os.path.abspath(file_path) if file_path else '',
        'date': datetime.now().strftime('%Y-%m-%d'),
        'threats': int(threat_count) if isinstance(threat_count, (int, float, str)) else 0,
        'security_score': int(security_score) if isinstance(security_score, (int, float, str)) else 0,
        # Why: schema_version allows future migrations to detect and upgrade old entries
        'schema_version': HISTORY_VERSION
    }
    history.append(new_entry)
    history = history[-30:]
    try:
        with open(HISTORY_FILE, 'w') as f:
            json.dump(history, f, indent=4)
    except IOError as e:
        logging.warning("Error saving scan history: %s", e)
