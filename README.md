<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9%2B-6f42c1?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/CustomTkinter-UI-6f42c1?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-6f42c1" />
  <img src="https://img.shields.io/badge/License-MIT-6f42c1" />
</p>

# <img src="assets/brand-banner.svg" alt="NeuralScan" width="100%" />

# 🛡️ NeuralScan

> See the threats before they see you.

NeuralScan is a lightweight desktop app that scans source files and configs for security risks. It ships with a clean CustomTkinter UI (Dashboard, Scan, Results), optional AI explanations for flagged snippets, and optional Trivy integration.

---

## ✨ Features

- Modern GUI: clean CustomTkinter interface with Dashboard, Scan, Results
- Heuristic scanning (regex-based):
  - Command execution: `subprocess(..., shell=True)`, `os.system(...)`
  - Dynamic code: `eval(...)`, `exec(...)`
  - Unsafe deserialization: `pickle.load(...)`, `yaml.load(...)` (without SafeLoader)
  - Weak crypto: `hashlib.md5`, `hashlib.sha1`, `DES`
  - Filesystem risks: destructive ops (`os.remove`, `os.unlink`, `shutil.rmtree`), writes via `open(..., 'w'|'a')`
  - Secrets: hardcoded `api key/secret/password/token`, AWS AKIA keys
  - Network indicators: `requests.*(http[s]://...)`, raw `socket`
- AI explanations (optional): per-finding explanation by a local HF model (if available)
- Trivy integration (optional): vulnerabilities and secrets via Docker container
- Dashboard: security score, risk categories, and recent history

---

## 🖼️ Screenshots


<p align="center">
   <img src="assets/screenshots/dashboard.png" width="90%" alt="Dashboard"/> 
   <img src="assets/screenshots/scan.png" width="90%" alt="Scan"/> 
   <img src="assets/screenshots/results.png" width="90%" alt="Results"/> 
</p>

## 📋 System Requirements

- Python 3.9+
- Desktop environment with Tk available
- Optional: Docker (for Trivy integration)

---

## 🚀 Tech Stack

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9%2B-6f42c1?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/CustomTkinter-UI-6f42c1?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/matplotlib-3.x-6f42c1?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Pillow-10%2B-6f42c1?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/transformers-4.x-6f42c1?logo=huggingface&logoColor=white" />
  <img src="https://img.shields.io/badge/accelerate-0.3x-6f42c1?logo=huggingface&logoColor=white" />
  <img src="https://img.shields.io/badge/docker-SDK-6f42c1?logo=docker&logoColor=white" />
</p>

---

## 🛠️ Installation

Recommended virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install --upgrade pip
```

Install core dependencies:
```bash
pip install -r requirements.txt
```
> Note on PyTorch: if you plan to use AI explanations, install `torch` per your platform. Torch wheels are platform/GPU-specific. Follow https://pytorch.org/get-started/ to pick the right wheel. Example CPU-only:
> ```bash
> pip install torch --index-url https://download.pytorch.org/whl/cpu
> ```

---

## ⚡ Quick Start

1. Ensure Python 3.9+ is installed.
2. (Optional) Install Docker and start the Docker daemon (for Trivy integration).
3. Create and activate a virtualenv.
4. Install requirements: `pip install -r requirements.txt`.
5. (Optional) Install `torch` for AI explanations (see note above).
6. Run: `python run.py`.

---

## ▶️ Usage

Run the app:
```bash
python run.py
```

Workflow:
1. Go to Scan and select a file (.py, .js, .sh, Dockerfile).
2. Results auto-open with findings, code snippets, and explanations. Each finding shows its source: AI Analyzer | Heuristic/Fallback | Trivy.
3. Dashboard shows score, risk categories, and recent scans.

---

## 🧭 Table of Contents

- [Features](#-features)
- [Screenshots](#️-screenshots)
- [System Requirements](#-system-requirements)
- [Tech Stack](#-tech-stack)
- [Installation](#️-installation)
- [Quick Start](#-quick-start)
- [Usage](#️-usage)
- [Documentation](#-documentation)
- [Settings](#-settings)
- [Architecture](#-architecture)
- [Roadmap](#-roadmap)
- [FAQ](#-faq)
- [Contributing](#-contributing)
- [License](#-license)

---

## 📚 Documentation
For full technical documentation, see [DOCUMENTATION.md](./DOCUMENTATION.md).

---

## ⚙️ Settings
- AI Model: choose the model for explanations (e.g., `bigcode/starcoder2-3b`). Falls back to deterministic text if AI is unavailable.
- Use Trivy: enable container-based vulnerability/secret scan (requires Docker and `docker` SDK). The `aquasec/trivy:latest` image is pulled on first use.
- Minimum scan time (ms): ensures realistic UX pacing.
- AI explanation detail: short, standard, deep.
- Save scan history: stores last ~30 scans in `data/scan_history.json`.

---

## 🏗️ Architecture

- `gui/` — CustomTkinter UI
  - `gui/main.py` — main application (`App`), views, results rendering
  - `gui/theme.py` — theme and color tokens
- `scanner.py` — scanning logic (heuristics, optional AI/Trivy). AI explains only snippets wykryte przez heurystyki; nie wykonuje domyślnie pełno-plikowej analizy.
- `utils/file_handler.py` — scan history I/O (`data/scan_history.json`)
- `run.py` — entry point
- `assets/` — icons, banner, optional screenshots

---

## 🧩 Project Structure
- `run.py` – app entry point (GUI)
- `scanner.py` – scanning logic (heuristics, optional AI/Trivy)
- `gui/main.py` – UI (`App`), views, results rendering
- `gui/theme.py` – visual theme
- `utils/file_handler.py` – scan history I/O
- `assets/` – icons and visual assets (PNG/SVG)

---

## ❗ Troubleshooting
- AI missing: app works without AI; explanations fall back to deterministic text. “AI Ready” oznacza gotowość modelu, ale źródło każdego znaleziska jest pokazane w karcie (AI/Heuristic/Trivy).
- Torch install: for CPU-only, for example:
  ```bash
  pip install torch --index-url https://download.pytorch.org/whl/cpu
  ```
- Docker/Trivy: ensure Docker daemon is running (`docker info`). First run may pull `aquasec/trivy:latest`.
- Icons: make sure `gui/assets/` contains required `.png` or `.svg` files.

---

## 🗺️ Roadmap

- Better accessibility (keyboard focus order, aria-like hints)
- Theming presets (compact/comfortable density)
- Optional animations for view transitions
- Pluggable rule packs for language-specific checks

---

## ❓ FAQ

- Q: Do I need Torch?  
  A: Only for AI explanations. The scanner works without it.
- Q: Do I need Docker?  
  A: Only if you enable Trivy integration.
- Q: Does it support Windows/macOS?  
  A: Yes, if `tkinter` is available and dependencies install. On Linux ensure `python3-tk`.

---

## 🤝 Contributing
1. Fork the repository
2. Create a feature branch
3. Make changes and test
4. Open a pull request

---

## 📜 License
MIT License. See [License](./LICENSE)
