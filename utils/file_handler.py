import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

DATA_DIR = Path('data')
HISTORY_FILE = DATA_DIR / 'scan_history.json'
LEGACY_FILE = Path('scan_history.json')
HISTORY_VERSION = 1


def load_scan_history() -> List[Dict[str, Any]]:
    if HISTORY_FILE.exists():
        try:
            with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return []

    # Migrate the old top-level history file into data/ the first time we see it.
    if LEGACY_FILE.exists():
        try:
            with open(LEGACY_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return []
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            with open(HISTORY_FILE, 'w', encoding='utf-8') as nf:
                json.dump(data, nf, indent=4)
        except (OSError, ValueError) as e:
            logging.warning("Failed to migrate legacy scan history to '%s': %s", HISTORY_FILE, e)
        return data
    return []


def save_scan_history(file_path: str, threat_count: int, security_score: int = 0) -> None:
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logging.error("Failed to create data directory '%s' for scan history: %s", DATA_DIR, e)

    history = load_scan_history()
    new_entry = {
        'file': Path(file_path).name if file_path else '',
        'file_path': str(Path(file_path).resolve()) if file_path else '',
        'date': datetime.now().strftime('%Y-%m-%d'),
        'threats': int(threat_count) if isinstance(threat_count, (int, float, str)) else 0,
        'security_score': int(security_score) if isinstance(security_score, (int, float, str)) else 0,
        'schema_version': HISTORY_VERSION,
    }
    history.append(new_entry)
    history = history[-30:]
    try:
        with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
            json.dump(history, f, indent=4)
    except OSError as e:
        logging.warning("Error saving scan history: %s", e)
