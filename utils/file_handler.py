import json
import os
from datetime import datetime

DATA_DIR = 'data'
HISTORY_FILE = os.path.join(DATA_DIR, 'scan_history.json')
LEGACY_FILE = 'scan_history.json'

def load_scan_history():
    """Load scan history from new location, with legacy fallback and migration."""
    # Prefer new path
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return []
    # Fallback to legacy path and migrate
    if os.path.exists(LEGACY_FILE):
        try:
            with open(LEGACY_FILE, 'r') as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError):
            return []
        # Try to persist to new location for future reads
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(HISTORY_FILE, 'w') as nf:
                json.dump(data, nf, indent=4)
        except Exception:
            pass
        return data
    return []

def save_scan_history(file_path, threat_count):
    """Append a new scan history entry and persist to the new path."""
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
    except Exception:
        pass
    history = load_scan_history()
    new_entry = {
        'file': os.path.basename(file_path) if file_path else '',
        'date': datetime.now().strftime('%Y-%m-%d'),
        'threats': int(threat_count) if isinstance(threat_count, (int, float, str)) else 0
    }
    history.append(new_entry)
    history = history[-30:]
    try:
        with open(HISTORY_FILE, 'w') as f:
            json.dump(history, f, indent=4)
    except IOError as e:
        print(f"Error saving scan history: {e}")
