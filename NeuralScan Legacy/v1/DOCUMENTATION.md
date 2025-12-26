# NeuralScan – Technical Documentation

NeuralScan is a desktop application for analyzing source files and configuration files for security risks. It combines regex-based heuristics with an elegant, modern UI, and offers optional AI explanations (per flagged snippet) and optional Trivy integration.

- UI: CustomTkinter with tabs – Dashboard, Scan, Results, Settings.
- Analysis: built-in heuristics; optional AI explanations (per finding).
- Trivy (optional): Docker-based scan of vulnerabilities and secrets.

---

## Table of Contents
- [System Requirements](#system-requirements)
- [Installation](#installation)
- [Running the App](#running-the-app)
- [Capabilities](#capabilities)
- [Architecture](#architecture)
- [Settings](#settings)
- [Dependencies](#dependencies)
- [Scan History](#scan-history)
- [Extensibility & Integrations](#extensibility--integrations)
- [Distribution & Portability](#distribution--portability)
- [Development & Contributing](#development--contributing)
- [License](#license)

---

## System Requirements
- Python 3.9+ (recommended: 3.10/3.11)
- Desktop environment with Tk available
- Optional: Docker (for Trivy)

---

## Installation
Use a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install --upgrade pip
```
Install all dependencies:
```bash
pip install -r requirements.txt
```
Note on PyTorch (for AI explanations): install `torch` for your platform separately. Torch wheels are platform/GPU specific. Follow https://pytorch.org/get-started/. Example CPU-only:
```bash
pip install torch --index-url https://download.pytorch.org/whl/cpu
```

---

## Running the App
```bash
python run.py
```
The app launches a window titled "NeuralScan".

---

## Capabilities
- Dashboard: summaries, charts, risk categories, security score.
- Scan: choose a file (.py, .js, .sh, Dockerfile).
- Results: findings with line numbers, code snippets, concise explanations. Każde znalezisko ma pole „Source”: AI Analyzer | Heuristic/Fallback | Trivy.
- History: last ~30 scans persisted to `data/scan_history.json`.
- Optional: AI explanations (per finding); Trivy findings merged with heuristics.

---

## Architecture
- `run.py` – entry point for the GUI application.
- `scanner.py` – scanning logic:
  - `SecurityScanner` – core engine (regex heuristics + integration with AI/Trivy). AI domyślnie wyjaśnia tylko fragmenty wykryte przez heurystyki; nie wykonuje pełno-plikowej analizy.
  - `AICodeAnalyzer` – ładuje model HF i generuje wyjaśnienia fragmentów (opcjonalnie).
- `gui/main.py` – UI (`App`):
  - view composition (dashboard, scan, results, settings),
  - background processing queue (`process_queue`),
  - results presentation (`display_scan_results`) and automatic tab switch to Results.
- `gui/theme.py` – theme and color system.
- `utils/file_handler.py` – history persistence (read/write JSON).
- `assets/` – icons and images (PNG/SVG).

Flow:
1. User selects a file in the Scan tab.
2. `SecurityScanner` analyzes it (heuristics; AI wyjaśnia wykryte fragmenty; opcjonalnie Trivy).
3. Results are pushed to a queue and rendered by the UI in Results.
4. The app switches to the Results tab automatically after the scan.

---

## Settings
In `gui/main.py` (Settings tab):
- AI Model – wybór modelu dla `AICodeAnalyzer` (jeśli AI dostępne; w razie braku używany jest fallback deterministyczny).
- Use Trivy – włącza skanowanie przez Docker (pobiera `aquasec/trivy:latest` przy pierwszym użyciu).
- Minimum scan time (ms) – pace UX.
- AI explanation detail – short | standard | deep.
- Save scan history – zapisuje historię do `data/scan_history.json`.

Defaults in `SecurityScanner`:
- `use_trivy=False`, `save_history=True`, `ai_detail='standard'`, `desired_model_name='bigcode/starcoder2-3b'`.

---

## Dependencies
- Core: `customtkinter`, `Pillow`, `matplotlib` (see `requirements.txt`).
- AI (optional): `transformers`, `accelerate`, platform-specific `torch` (install per PyTorch docs).
- Extras (optional): `docker` SDK, `cairosvg` (for SVG icons).

Note: torch installation depends on CPU/GPU and CUDA/ROCm support.

---

## Scan History
- File: `data/scan_history.json`.
- Format: list of the last ~30 entries – `{ file, date, threats }`.
- Module: `utils/file_handler.py` (`save_scan_history()`, `load_scan_history()`).

---

## Extensibility & Integrations
- AI: `AICodeAnalyzer` generuje wyjaśnienia dla wykrytych fragmentów (HF model). Jeśli AI niedostępne, używany jest fallback deterministyczny.
- Trivy: uruchamia `aquasec/trivy:latest` w Dockerze. Wynik parsowany i dołączany do raportu.
- SVG icons: jeśli używasz `.svg`, zainstaluj `cairosvg`; `.png` nie wymaga dodatkowych zależności.

---

## Heuristics (current rule set)
Regex-based detectors applied line-by-line:
- Command execution: `subprocess(..., shell=True)`, `os.system(...)`
- Dynamic code: `eval(...)`, `exec(...)`
- Unsafe deserialization: `pickle.load(...)`, `yaml.load(...)` (bez SafeLoader)
- Weak crypto: `hashlib.md5`, `hashlib.sha1`, `DES`
- Filesystem: `os.remove`, `os.unlink`, `shutil.rmtree`, `open(...,'w'|'a')`
- Secrets: wzorce `api key/secret/password/token`, klucze AWS `AKIA...`
- Network: `requests.*(http[s]://...)`, `socket.socket(...)`

Uwaga: kategorie ryzyka w Dashboardzie powstają przez grupowanie po słowach-kluczach (post-hoc) i nie są dodatkowymi regułami.

---

## Distribution & Portability
- No hardcoded local paths in the UI; packaged for public use.
- For GitHub distribution: include `README.md`, `DOCUMENTATION.md`, `requirements.txt`, `.gitignore`.
- (Optional) Packaging with PyInstaller:
  ```bash
  pyinstaller --noconfirm --onefile --name NeuralScan run.py
  ```
  For AI/matplotlib heavy builds, consider non-onefile and bundling assets.

---

## Development & Contributing
- Standard GitHub flow: fork, branch, PR.
- Code style: readable, with clear error logging. Tests welcome for key changes.
- Issues: please include logs and environment details.

---

## License
Specify a license (e.g., MIT/Apache-2.0) and include a `LICENSE` file in the repository.
