import os
import json
import logging
import re
import threading
from typing import Dict, Any, List, Optional

from .ai_analyzer import AICodeAnalyzer
from .rules import SECURITY_RULES
from .scoring import calculate_security_score, summarize_risk_categories
from .trivy import TrivyScanner

try:
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM
    AI_LIBS_AVAILABLE = True
except ImportError:
    AI_LIBS_AVAILABLE = False

CONFIG_FILE = os.path.join('data', 'config.json')

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SecurityScanner:
    def __init__(self, settings: Optional[Dict[str, Any]] = None):
        self.settings = settings or {}
        self._load_config()
        
        self.settings.setdefault('use_trivy', False)
        self.settings.setdefault('save_history', True)
        self.settings.setdefault('ai_detail', 'standard')
        self.desired_model_name: str = self.settings.get('ai_model', "bigcode/starcoder2-3b")
        # Why: system_prompt was never passed to AICodeAnalyzer — explain_snippet() builds its own prompt internally
        self.ai_analyzer: Optional[AICodeAnalyzer] = None
        self.ai_ready = threading.Event()
        self.progress_message: str = ""
        self.trivy_scanner = TrivyScanner()
        self.init_thread: Optional[threading.Thread] = None

    def _load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    saved_settings = json.load(f)
                    self.settings.update(saved_settings)
            except Exception as e:
                logging.error(f"Failed to load config: {e}")

    def reload_config(self):
        self._load_config()
        self.desired_model_name = self.settings.get('ai_model', "bigcode/starcoder2-3b")

    def prepare_ai_analyzer(self, model_name: Optional[str] = None):
        if not self.init_thread or not self.init_thread.is_alive():
            logging.info("AI analyzer preparation requested. Starting initialization.")
            if model_name:
                self.desired_model_name = model_name
            self.init_thread = threading.Thread(target=self._initialize_ai_analyzer, daemon=True)
            self.init_thread.start()
        else:
            logging.info("AI analyzer initialization already in progress or completed.")

    def _initialize_ai_analyzer(self):
        logging.info("Initializing AI Code Analyzer in background...")
        self.ai_analyzer = AICodeAnalyzer(model_name=self.desired_model_name, settings=self.settings)
        if self.ai_analyzer and self.ai_analyzer.model:
            self.ai_ready.set()
            logging.info("AI Code Analyzer is ready.")
        else:
            logging.error("AI Code Analyzer failed to initialize.")

    def _basic_static_analysis(self, code: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        lines = code.splitlines()
        rules: List[Dict[str, Any]] = SECURITY_RULES

        seen = set()
        for i, line in enumerate(lines):
            for details in rules:
                try:
                    if re.search(details["pattern"], line):
                        key = (i + 1, details["description"])
                        if key in seen:
                            continue
                        seen.add(key)
                        
                        finding: Dict[str, Any] = {
                            "line": i + 1,
                            "code_snippet": line.strip(),
                            "description": details["description"],
                            "explanation": details["explanation"],
                            "severity": details.get("severity", "High"),
                            "source": "Heuristic Detector",
                        }
                        
                        for meta_key in ("category", "cwe", "owasp", "remediation", "confidence", "pci_dss", "nist", "gdpr"):
                            if meta_key in details:
                                finding[meta_key] = details[meta_key]
                        
                        finding = self._adjust_severity_by_context(finding, lines, i)
                        
                        findings.append(finding)
                except re.error as e:
                    # Why: silent regex failures mask detection gaps — must surface to logs
                    logging.warning(f"Regex rule failed [{details.get('description', 'Unknown rule')}]: {e}")
        return findings
    
    def _adjust_severity_by_context(self, finding: Dict[str, Any], lines: List[str], line_idx: int) -> Dict[str, Any]:
        start = max(0, line_idx - 3)
        end = min(len(lines), line_idx + 4)
        context = "\n".join(lines[start:end]).lower()
        finding_line = lines[line_idx].lower() if 0 <= line_idx < len(lines) else ""
        
        severity = finding["severity"]
        confidence = finding.get("confidence", "Medium")
        
        # Why: context-wide suppression is too broad — a # nosec on line N must not silence a finding on line N+2
        if any(marker in finding_line for marker in ["# nosec", "# noqa", "# nosonar", "# skipcq"]):
            finding["suppressed"] = True
            finding["suppression_reason"] = "Suppression comment found"
            return finding
        
        user_input_patterns = [
            "input(", "request.args", "request.form", "request.json",
            "sys.argv", "os.environ", "flask.request", "django.request",
            "raw_input(", "stdin.read"
        ]
        if any(pattern in context for pattern in user_input_patterns):
            if severity == "Medium":
                finding["severity"] = "High"
                finding["severity_reason"] = "User input detected in context"
            elif severity == "High":
                finding["severity"] = "Critical"
                finding["severity_reason"] = "User input detected in context"
            
            if confidence == "Low":
                finding["confidence"] = "Medium"
            elif confidence == "Medium":
                finding["confidence"] = "High"
        
        if "try:" in context and "except" in context:
            finding["context_note"] = "Error handling present"
        
        validation_patterns = ["validate", "sanitize", "escape", "whitelist", "allowlist"]
        if any(pattern in context for pattern in validation_patterns):
            finding["context_note"] = "Validation detected - verify if sufficient"
            if confidence == "High":
                finding["confidence"] = "Medium"
        
        return finding

    def _fallback_explanation(self, description: str, code_snippet: str, category: str = None) -> str:
        desc = (description or "").lower()
        cat = (category or "").lower()
        
        if "command injection" in cat or "command" in desc:
            return (
                "**Impact:** Remote code execution with full system privileges. Attackers can execute arbitrary "
                "commands, exfiltrate data, install backdoors, or pivot to other systems. "
                "**Likelihood:** High if user input reaches the command without validation. "
                "**Fix:** Use subprocess with argument lists (no shell=True), validate all inputs against strict "
                "allowlists, or use higher-level APIs that don't invoke shells."
            )
        
        if "sql injection" in cat or "sql" in desc:
            return (
                "**Impact:** Database compromise including data theft, modification, or deletion. Attackers can "
                "bypass authentication, escalate privileges, or execute OS commands via database features. "
                "**Likelihood:** High if queries are built with string concatenation/formatting. "
                "**Fix:** Always use parameterized queries/prepared statements. Never interpolate user input "
                "directly into SQL strings."
            )
        
        if "eval" in desc or "exec" in desc or "dynamic code" in cat:
            return (
                "**Impact:** Arbitrary code execution in the application context. Complete application compromise. "
                "**Likelihood:** Critical if any user-controlled data reaches eval/exec. "
                "**Fix:** Refactor to avoid eval/exec entirely. Use ast.literal_eval for safe literal parsing, "
                "or implement plugin systems with explicit function mappings."
            )
        
        if "deserial" in desc or "pickle" in code_snippet.lower() or "yaml" in desc:
            return (
                "**Impact:** Remote code execution during deserialization. Object injection can trigger gadget "
                "chains leading to arbitrary code execution. "
                "**Likelihood:** High if deserializing untrusted data sources. "
                "**Fix:** Never deserialize untrusted data with pickle/unsafe YAML. Use JSON with strict schema "
                "validation and type checking."
            )
        
        if "crypto" in cat or "weak" in desc:
            return (
                "**Impact:** Cryptographic compromise allowing data decryption, integrity bypass, or authentication "
                "forgery. Broken algorithms enable practical attacks. "
                "**Likelihood:** Medium to High depending on data sensitivity. "
                "**Fix:** Migrate to modern cryptographic primitives (SHA-256+, AES-GCM, ChaCha20-Poly1305). "
                "Use established libraries and follow current best practices."
            )
        
        if "secret" in cat or "hardcoded" in desc or "key" in desc:
            return (
                "**Impact:** Credential compromise leading to unauthorized access, data breaches, or service abuse. "
                "Secrets in code are easily discovered via repository scanning. "
                "**Likelihood:** High - automated scanners constantly search for exposed credentials. "
                "**Fix:** Remove all hardcoded secrets. Use environment variables, secrets managers (Vault, AWS "
                "Secrets Manager), or secure configuration systems."
            )
        
        if "path traversal" in cat or "filesystem" in cat or "../" in code_snippet:
            return (
                "**Impact:** Unauthorized file access, data exfiltration, or arbitrary file write/delete. Can lead "
                "to code execution via config file overwrites. "
                "**Likelihood:** High if file paths are constructed from user input. "
                "**Fix:** Validate and normalize all paths, use safe path joining functions, restrict operations "
                "to specific directories, and never trust user-supplied path components."
            )
        
        if "network" in cat or "http" in desc or "tls" in desc:
            return (
                "**Impact:** Data interception, man-in-the-middle attacks, or data exfiltration. Sensitive data "
                "transmitted over insecure channels can be captured. "
                "**Likelihood:** Medium - depends on network environment and data sensitivity. "
                "**Fix:** Use HTTPS for all sensitive communications, enable certificate validation, and restrict "
                "outbound connections to approved endpoints."
            )
        
        return (
            "**Impact:** Varies by context - potential for data compromise, privilege escalation, or service disruption. "
            "**Likelihood:** Depends on input sources and validation controls. "
            "**Fix:** Apply defense-in-depth: validate all inputs, use least-privilege execution, implement proper "
            "error handling, and prefer safer APIs where available."
        )

    def scan_file_for_malware(self, file_path: str, custom_prompt: Optional[str] = None, detail: Optional[str] = None) -> Dict[str, Any]:
        if not os.path.exists(file_path):
            return {"error": f"File {file_path} does not exist"}

        # Security: Check file size to prevent memory exhaustion (max 10MB)
        MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
        try:
            file_size = os.path.getsize(file_path)
            if file_size > MAX_FILE_SIZE:
                return {"error": f"File too large ({file_size} bytes). Maximum allowed: {MAX_FILE_SIZE} bytes (10MB)"}
        except OSError as e:
            return {"error": f"Could not check file size: {e}"}

        if self.settings.get('use_trivy'):
            # Why: Docker init belongs at scan time, not app startup — avoids blocking UI and unexpected daemon calls
            trivy_error = self.trivy_scanner._ensure_trivy_ready()
            if trivy_error:
                return {"error": trivy_error}

        ai_enabled = self.settings.get('ai_enabled', True)
        # Why: ai_enabled=False lets users run heuristic-only scans on slow hardware without waiting for model load
        if ai_enabled and not (self.ai_analyzer and self.ai_ready.is_set()):
            try:
                self.prepare_ai_analyzer()
            except Exception as e:
                # Why: silent AI init failure hides misconfiguration — log so user knows why AI is unavailable
                logging.warning("AI analyzer initialization failed during scan for '%s': %s", file_path, e)

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code_content = f.read()
        except Exception as e:
            return {"error": f"Could not read file: {e}"}

        result = {
            "file_path": file_path,
            "findings": [],
            "security_score": 100
        }

        try:
            # Why: progress message must match what scanner actually emits — fake progress is misleading
            self.progress_message = "Running static analysis..."
            detected = self._basic_static_analysis(code_content)
            total = len(detected)

            # Effective detail level: per-call override > global setting
            effective_detail = (detail or self.settings.get('ai_detail') or 'standard').lower()

            findings: List[Dict[str, Any]] = []
            suppressed_count = 0
            for idx, d in enumerate(detected, start=1):
                                                                                                 
                use_ai = bool(ai_enabled and self.ai_analyzer and self.ai_ready.is_set() and getattr(self.ai_analyzer, 'model', None))
                mode_msg = "with AI" if use_ai else "(fallback)"
                self.progress_message = f"Analyzing snippet {idx}/{total} (line {d['line']}) {mode_msg}..."
                logging.info(f"Explaining snippet at line {d['line']} {mode_msg}...")
                ctx = None
                try:
                    lines = code_content.splitlines()
                    idx = max(0, int(d['line']) - 1)
                    ctx_lines = lines[max(0, idx-1): min(len(lines), idx+2)]
                    ctx = "\n".join(ctx_lines)
                except Exception:
                    ctx = None

                if effective_detail == 'short' or effective_detail == 'quick':
                    detail_prompt = "Provide a concise 1-2 sentence security rationale and risk summary."
                elif effective_detail == 'deep':
                    detail_prompt = "Provide an in-depth explanation including root cause, exploit scenario, impact, and concrete remediation steps with code suggestions."
                else:
                    detail_prompt = "Provide a clear explanation of the issue, why it's risky, and a brief remediation tip."
                merged_prompt = f"{custom_prompt + ' ' if custom_prompt else ''}{detail_prompt}".strip()
                if use_ai:
                    explanation = self.ai_analyzer.explain_snippet(d["code_snippet"], ctx, merged_prompt)
                else:
                    explanation = self._fallback_explanation(d.get("description", ""), d.get("code_snippet", ""), d.get("category"))
                
                try:
                    preview = (explanation or "").replace("\n", " ")[:200]
                    import re
                    preview = re.sub(r'(password|secret|token|key)\s*[=:]\s*["\'][^"\']{3,}["\']', r'\1=***REDACTED***', preview, flags=re.IGNORECASE)
                    preview = re.sub(r'AKIA[0-9A-Z]{16}', 'AKIA***REDACTED***', preview)
                    logging.info(f"AI explanation (len={len(explanation or '')}) for line {d['line']}: {preview}")
                except Exception:
                    pass
                norm = (explanation or "").strip()
                if (not norm) or len(norm) < 40 or norm.lower().startswith("potential risk present") or norm.startswith("An error occurred"):
                    explanation = self._fallback_explanation(d.get("description", ""), d.get("code_snippet", ""), d.get("category"))
                final_finding = {
                    # Why: full metadata is preserved here — downstream views and exports rely on it, re-derivation is lossy
                    "line": d["line"],
                    "code_snippet": d["code_snippet"],
                    "description": d["description"],
                    "explanation": explanation,
                    "severity": d.get("severity", "Medium"),
                    "category": d.get("category", ""),
                    "cwe": d.get("cwe", ""),
                    "owasp": d.get("owasp", ""),
                    "remediation": d.get("remediation", ""),
                    "confidence": d.get("confidence", ""),
                    "pci_dss": d.get("pci_dss", ""),
                    "nist": d.get("nist", ""),
                    "suppressed": d.get("suppressed", False),
                    "suppression_reason": d.get("suppression_reason", ""),
                    "source": "AI Analyzer" if use_ai else "Heuristic/Fallback"
                }
                if final_finding.get("suppressed") is True:
                    suppressed_count += 1
                    # Why: suppressed findings are intentionally excluded by developer — including them defeats the purpose of # nosec markers
                    continue
                findings.append(final_finding)
            self.progress_message = "Aggregating results..."

            if self.settings.get('use_trivy') and self.trivy_scanner.docker_client:
                logging.info("Starting Trivy scan (optional)...")
                trivy_results_str = self.trivy_scanner._scan_with_trivy(file_path)
                if "No vulnerabilities or secrets found" not in trivy_results_str and "unavailable" not in trivy_results_str:
                    findings.append({
                        "line": "N/A",
                        "code_snippet": "See explanation",
                        "description": "Dependency Vulnerability",
                        "explanation": trivy_results_str,
                        "severity": "High",
                        "source": "Trivy"
                    })
                logging.info("Trivy scan completed.")

            result["suppressed_count"] = suppressed_count
            result["findings"] = findings
            result["security_score"] = calculate_security_score(findings, policy=effective_detail)
            result["risk_categories"] = summarize_risk_categories(findings)

        except Exception as e:
            logging.error(f"An unexpected error occurred during scan: {e}", exc_info=True)
            result["error"] = f"An unexpected error occurred: {e}"

        finally:
            if AI_LIBS_AVAILABLE and torch.cuda.is_available():
                try:
                    torch.cuda.empty_cache()
                    logging.debug("GPU memory cache cleared")
                except Exception:
                    pass
        
        self.progress_message = ""
        return result
    
