# Why: file_handler is the persistence layer — these tests catch schema regressions

from pathlib import Path

from utils import file_handler


def test_save_and_load_roundtrip(tmp_path):
    original_data_dir = file_handler.DATA_DIR
    original_history_file = file_handler.HISTORY_FILE
    original_legacy_file = file_handler.LEGACY_FILE

    file_handler.DATA_DIR = str(tmp_path / "data")
    file_handler.HISTORY_FILE = str(Path(file_handler.DATA_DIR) / "scan_history.json")
    file_handler.LEGACY_FILE = str(tmp_path / "scan_history.json")

    try:
        target_file = tmp_path / "target.py"
        target_file.write_text("print('ok')\n", encoding="utf-8")

        file_handler.save_scan_history(str(target_file), threat_count=2, security_score=80)
        history = file_handler.load_scan_history()

        assert history
        last_entry = history[-1]
        assert "file_path" in last_entry
        assert "security_score" in last_entry
    finally:
        file_handler.DATA_DIR = original_data_dir
        file_handler.HISTORY_FILE = original_history_file
        file_handler.LEGACY_FILE = original_legacy_file


def test_schema_version_present(tmp_path):
    original_data_dir = file_handler.DATA_DIR
    original_history_file = file_handler.HISTORY_FILE
    original_legacy_file = file_handler.LEGACY_FILE

    file_handler.DATA_DIR = str(tmp_path / "data")
    file_handler.HISTORY_FILE = str(Path(file_handler.DATA_DIR) / "scan_history.json")
    file_handler.LEGACY_FILE = str(tmp_path / "scan_history.json")

    try:
        target_file = tmp_path / "target_schema.py"
        target_file.write_text("print('schema')\n", encoding="utf-8")

        file_handler.save_scan_history(str(target_file), threat_count=1, security_score=95)
        history = file_handler.load_scan_history()

        assert history
        assert history[-1].get("schema_version") == 1
    finally:
        file_handler.DATA_DIR = original_data_dir
        file_handler.HISTORY_FILE = original_history_file
        file_handler.LEGACY_FILE = original_legacy_file


def test_missing_file_returns_empty(tmp_path):
    original_data_dir = file_handler.DATA_DIR
    original_history_file = file_handler.HISTORY_FILE
    original_legacy_file = file_handler.LEGACY_FILE

    file_handler.DATA_DIR = str(tmp_path / "data")
    file_handler.HISTORY_FILE = str(Path(file_handler.DATA_DIR) / "scan_history.json")
    file_handler.LEGACY_FILE = str(tmp_path / "scan_history.json")

    try:
        history_path = Path(file_handler.HISTORY_FILE)
        if history_path.exists():
            history_path.unlink()

        result = file_handler.load_scan_history()

        assert result == []
    finally:
        file_handler.DATA_DIR = original_data_dir
        file_handler.HISTORY_FILE = original_history_file
        file_handler.LEGACY_FILE = original_legacy_file
