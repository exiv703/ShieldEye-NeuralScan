# Why: these tests verify scanner contracts, not implementation details — inputs and outputs only

from pathlib import Path

from backend.scanner import SecurityScanner


def _scanner_heuristic_only() -> SecurityScanner:
    scanner = SecurityScanner()
    scanner.settings["ai_enabled"] = False
    scanner.settings["use_trivy"] = False
    return scanner


def test_sql_injection_detected():
    scanner = _scanner_heuristic_only()
    sample_file = Path(__file__).parent / "samples" / "sql_injection_test.py"

    result = scanner.scan_file_for_malware(str(sample_file))

    assert "error" not in result
    assert len(result["findings"]) >= 3


def test_empty_file_score(tmp_path):
    scanner = _scanner_heuristic_only()
    empty_file = tmp_path / "empty.py"
    empty_file.write_text("", encoding="utf-8")

    result = scanner.scan_file_for_malware(str(empty_file))

    assert "error" not in result
    assert result["security_score"] == 100


def test_error_on_missing_file():
    scanner = _scanner_heuristic_only()

    result = scanner.scan_file_for_malware("nonexistent.py")

    assert "error" in result


def test_suppressed_not_in_findings(tmp_path):
    scanner = _scanner_heuristic_only()
    test_file = tmp_path / "suppressed.py"
    test_file.write_text("import os\nos.system('ls') # nosec\n", encoding="utf-8")

    result = scanner.scan_file_for_malware(str(test_file))

    assert "error" not in result
    assert all(not finding.get("suppressed", False) for finding in result["findings"])


def test_suppressed_count(tmp_path):
    scanner = _scanner_heuristic_only()
    test_file = tmp_path / "suppressed_count.py"
    test_file.write_text("import os\nos.system('ls') # nosec\n", encoding="utf-8")

    result = scanner.scan_file_for_malware(str(test_file))

    assert "error" not in result
    assert result["suppressed_count"] >= 1
