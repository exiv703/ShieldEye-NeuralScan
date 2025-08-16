<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9%2B-6f42c1?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/CustomTkinter-UI-6f42c1?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-6f42c1" />
  <img src="https://img.shields.io/badge/License-MIT-6f42c1" />
</p>

<p align="center">
  <img src="assets/brand-banner.svg" alt="NeuralScan" width="100%" />
</p>

<h1 align="center">🛡️ NeuralScan</h1>

<p align="center">
  <b>Find security pitfalls fast:</b> heuristics + local AI (StarCoder2‑3B). Optional Trivy. Local‑first, MIT.
</p>

<p align="center">
  If you like it, please ⭐ the repo — it helps a lot!
</p>

---

## 📚 Table of Contents

- [Highlights](#highlights)
- [Screenshots](#screenshots)
- [System Requirements](#system-requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Settings](#settings)
- [Privacy](#privacy)
- [Architecture](#architecture)
- [Roadmap](#roadmap)
- [FAQ](#faq)
- [Contributing](#contributing)
- [License](#license)

---

## 🔥 Highlights

- 💻 Clean desktop GUI (CustomTkinter): Dashboard, Scan, Results
- 🧠 Heuristic scanning (regex-based):
  - Command exec: `subprocess(..., shell=True)`, `os.system(...)`
  - Dynamic code: `eval(...)`, `exec(...)`
  - Unsafe deserialization: `pickle.load(...)`, `yaml.load(...)` (without SafeLoader)
  - Weak crypto: `hashlib.md5`, `hashlib.sha1`, `DES`
  - Filesystem risks: `os.remove`, `os.unlink`, `shutil.rmtree`, writes via `open(..., w|a)`
  - Secrets (API key/secret/password/token), AWS AKIA
  - Network IOCs: `requests.*(http[s]://...)`, raw `socket`
- 🤖 Optional AI explanations (local): `bigcode/starcoder2-3b` via HF Transformers  
  Falls back to deterministic text if AI is unavailable.
- 🐳 Optional Trivy (Docker) for dependency vulnerabilities & secrets
- 📊 Dashboard: security score (severity-weighted), top risk categories, recent history (local)
- ✅ Cross-platform: Linux / Windows / macOS, Python 3.9+
- 🔓 MIT license

---

## 🖼️ Screenshots

<p align="center">
  <img src="assets/screenshots/dashboard.png" width="90%" alt="Dashboard"/> 
  <img src="assets/screenshots/scan.png" width="90%" alt="Scan"/> 
  <img src="assets/screenshots/results.png" width="90%" alt="Results"/> 
</p>

---

## �� System Requirements

- Python 3.9+
- A desktop environment with Tk available
- Optional: Docker (for Trivy integration)

Tip:
- Ubuntu/Debian: `sudo apt-get install -y python3-tk`
- macOS (Homebrew): `brew install tcl-tk` (uruchamiaj Pythona ze wskazaniem na ten Tk)
- Windows: Tk zwykle wbudowany w instalator Pythona

---

## 🧰 Installation

Clone the repository:
```bash
git clone https://github.com/exiv703/neuralscan.git
cd neuralscan
```

Create and activate a virtual environment:
```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows
.venv\\Scripts\\activate
```

Upgrade pip and install dependencies:
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

Optional — AI (PyTorch):
```bash
# Example CPU-only wheel
pip install torch --index-url https://download.pytorch.org/whl/cpu
```

---

## ⚡ Quick Start

```bash
python run.py
```

- Optional: start Docker daemon for Trivy integration (`docker info`)
- First AI/Trivy use may download a model/image (one-time)

---

## ▶️ Usage

1. Open the app (`python run.py`).
2. Go to “Scan” and select a file (.py, .js, .sh, Dockerfile).
3. Results open automatically: findings, code snippets, explanations.  
   Each finding shows its source: AI Analyzer | Heuristic/Fallback | Trivy.
4. Dashboard → security score, top risk categories, recent history.

---

## 🔧 Settings

- AI Model: e.g., `bigcode/starcoder2-3b` (local AI explanations)
- Use Trivy: enable Docker-based dependency scanning
- Minimum scan time (ms): smoother UX pacing
- AI explanation detail: short | standard | deep
- Save scan history: keeps ~30 recent scans in `data/scan_history.json`

---

## 🔒 Privacy

- Local-first: analysis runs on your machine.
- Network is used only to fetch the AI model or Trivy image on first use.
- Scan history is stored locally (`data/scan_history.json`) and is git‑ignored.

---

## 🏗️ Architecture

- `gui/` — CustomTkinter UI  
  - `gui/main.py` — main application (`App`), views, results rendering  
  - `gui/theme.py` — theme and color tokens
- `scanner.py` — scanning logic (heuristics, optional AI/Trivy)  
  AI explains only snippets flagged by heuristics; no full‑file LLM pass by default.
- `utils/file_handler.py` — scan history I/O (`data/scan_history.json`, legacy migration)
- `run.py` — entry point
- `assets/` — icons, banner, screenshots

---

## 🗺️ Roadmap

- Better accessibility (focus order, hints)
- Theming presets (compact/comfortable)
- Lightweight animations for transitions
- Pluggable rule packs per language

Ideas or PRs welcome!

---

## ❓ FAQ

- Do I need Torch?  
  Only for AI explanations. Scanner works without it (deterministic fallback).
- Do I need Docker?  
  Only for Trivy integration. Without Docker, the rest of the app still works.
- Windows/macOS support?  
  Yes, if `tkinter` is available and deps install. On Linux ensure `python3-tk`.

---

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch
3. Make changes and test
4. Open a pull request

---

## 📜 License

MIT — see [LICENSE](./LICENSE).

