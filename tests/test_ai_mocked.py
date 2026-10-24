"""AI explanation path with the model mocked out. Nothing is downloaded or loaded."""

from unittest.mock import MagicMock

from backend.scanner import SecurityScanner


def test_ai_explanation_used_when_model_ready(tmp_path):
    scanner = SecurityScanner()
    scanner.settings["ai_enabled"] = True
    scanner.settings["use_trivy"] = False
    scanner.settings["save_history"] = False

    explanation = "Mocked model output: user input reaches os.system unescaped, so it can run arbitrary commands."
    fake_analyzer = MagicMock()
    fake_analyzer.model = object()
    fake_analyzer.explain_snippet.return_value = explanation
    scanner.ai_analyzer = fake_analyzer
    scanner.ai_ready.set()

    sample = tmp_path / "cmd.py"
    sample.write_text("import os\nos.system('ping ' + host)\n", encoding="utf-8")

    result = scanner.scan_file_for_malware(str(sample))

    assert "error" not in result
    assert result["findings"]
    assert all(f["source"] == "AI Analyzer" for f in result["findings"])
    assert all(f["explanation"] == explanation for f in result["findings"])
    fake_analyzer.explain_snippet.assert_called()
