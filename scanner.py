import os
import json
import subprocess
import logging
import re
import threading
from typing import Dict, Any, List, Optional

                                                            
try:
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM
    AI_LIBS_AVAILABLE = True
except ImportError:
    AI_LIBS_AVAILABLE = False

class DockerConnectionError(Exception):
                                                        
    pass

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class AICodeAnalyzer:
    def __init__(self, model_name="bigcode/starcoder2-3b"):
        if not AI_LIBS_AVAILABLE:
            logging.warning("AI libraries not available. AI analysis is disabled.")
            self.model = None
            self.tokenizer = None
            return

        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        logging.info(f"AI Analyzer is using device: {self.device}")

        try:
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.model = AutoModelForCausalLM.from_pretrained(
                model_name,
                torch_dtype=torch.bfloat16 if self.device == "cuda" else torch.float32,
                use_safetensors=True
            ).to(self.device)
            if getattr(self.tokenizer, "pad_token", None) is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token
            logging.info(f"Model {model_name} loaded successfully.")
        except Exception as e:
            logging.error(f"Could not load AI model '{model_name}'. AI analysis will be unavailable. Error: {e}")
            self.model = None
            self.tokenizer = None

    def analyze_code(self, code: str, system_prompt: str, custom_prompt: Optional[str] = None) -> List[str]:
        if not self.model or not self.tokenizer:
            return ["AI Analyzer is not available."]

        final_prompt = system_prompt
        if custom_prompt:
            final_prompt += f"\n\nAdditionally, consider the following instruction: {custom_prompt}"

        prompt = f"""{final_prompt}

        Code:
        ```python
        {code}
        ```
        
        Analysis:"""
        
        try:
            with torch.no_grad():
                inputs = self.tokenizer(prompt, return_tensors="pt", padding=True).to(self.device)
                generated_ids = self.model.generate(
                    inputs.input_ids,
                    attention_mask=inputs.attention_mask,
                    max_new_tokens=180,
                    do_sample=False,
                    temperature=0.2,
                    top_p=0.9,
                    pad_token_id=self.tokenizer.eos_token_id,
                    max_time=12.0
                )
            result = self.tokenizer.batch_decode(generated_ids, skip_special_tokens=True)[0]
            analysis_part = result.split("Analysis:")[-1].strip()
            return [analysis_part] if analysis_part else ["No specific issues found by AI."]
        except Exception as e:
            logging.error(f"Error during AI code analysis: {e}")
            return [f"An error occurred during AI analysis: {e}"]

    def explain_snippet(self, snippet: str, surrounding: Optional[str], custom_prompt: Optional[str] = None) -> str:
                                                                                               
        if not self.model or not self.tokenizer:
            return "AI Analyzer is not available."

        base = (
            "You are a security expert. Explain succinctly why the following code may be dangerous,"
            " referencing concrete risks (CWE/OWASP where relevant) and potential impact."
            " Provide remediation advice in 1–2 sentences."
        )
        if custom_prompt:
            base += f"\nAdditional instruction: {custom_prompt}"

        ctx = f"\nContext (optional):\n```python\n{surrounding}\n```\n" if surrounding else "\n"
        prompt = f"{base}{ctx}\nSnippet:\n```python\n{snippet}\n```\n\nExplanation:"
        try:
            max_new = 100 if (custom_prompt and "concise" in custom_prompt.lower()) else 180
            with torch.no_grad():
                inputs = self.tokenizer(prompt, return_tensors="pt", padding=True).to(self.device)
                generated_ids = self.model.generate(
                    inputs.input_ids,
                    attention_mask=inputs.attention_mask,
                    max_new_tokens=max_new,
                    do_sample=False,
                    pad_token_id=self.tokenizer.eos_token_id,
                    max_time=12.0
                )
            full = generated_ids[0]
            prompt_len = inputs.input_ids.shape[1]
            new_tokens = full[prompt_len:]
            result_text = self.tokenizer.decode(new_tokens, skip_special_tokens=True).strip()
            for marker in ("Explanation:", "Explanation -", "Analysis:", "Reasoning:"):
                if result_text.lower().startswith(marker.lower()):
                    result_text = result_text[len(marker):].strip()
                    break
            if not result_text or len(result_text) < 40 or result_text.startswith("Potential risk"):
                alt_base = (
                    "You are a security expert. Clearly explain why the following Python code is risky,"
                    " include: root cause, how it can be exploited, impact, and a short remediation tip."
                )
                alt_ctx = f"\nContext:\n```python\n{surrounding}\n```\n" if surrounding else "\n"
                alt_prompt = f"{alt_base}{alt_ctx}\nCode:\n```python\n{snippet}\n```\n"
                with torch.no_grad():
                    alt_inputs = self.tokenizer(alt_prompt, return_tensors="pt", padding=True).to(self.device)
                    alt_ids = self.model.generate(
                        alt_inputs.input_ids,
                        attention_mask=alt_inputs.attention_mask,
                        max_new_tokens=220,
                        do_sample=True,
                        temperature=0.8,
                        top_p=0.95,
                        pad_token_id=self.tokenizer.eos_token_id,
                        max_time=20.0
                    )
                alt_full = alt_ids[0]
                alt_new = alt_full[alt_inputs.input_ids.shape[1]:]
                alt_text = self.tokenizer.decode(alt_new, skip_special_tokens=True).strip()
                if alt_text.lower().startswith("explanation:"):
                    alt_text = alt_text[len("explanation:"):].strip()
                result_text = alt_text or result_text
            if not result_text:
                result_text = ""
            result_text = result_text.replace("```", "").strip()
            return result_text
        except Exception as e:
            logging.error(f"Error during AI snippet explanation: {e}")
            return f"An error occurred during AI analysis: {e}"

class SecurityScanner:
    def __init__(self, settings: Optional[Dict[str, Any]] = None):
        self.settings = settings or {}
        self.settings.setdefault('use_trivy', False)
        self.settings.setdefault('save_history', True)
        self.settings.setdefault('ai_detail', 'standard')
        self.desired_model_name: str = "bigcode/starcoder2-3b"
        self.system_prompt = """Role & Context:
You are an advanced, autonomous source code security analysis module operating under the highest industry standards (OWASP, NIST, ISO/IEC 27001). Your sole purpose is to detect and report all known or potential security threats in the provided file.

Analysis Objectives:

    Detect malicious software (malware) – including keyloggers, spyware, backdoors, trojans, and rootkits.

    Identify suspicious behaviors – e.g., unauthorized data collection, hidden network connections, system registry or file system manipulation.

    Detect security vulnerabilities – including exploits, code injection, unsafe function calls, and lack of input validation.

    Highlight non-compliance with security best practices – legacy code, outdated libraries, missing encryption, insecure configurations.

Methodology:
– Analyze the entire file in context, considering structure, dependencies, and potential attack vectors.
– Pinpoint threats with precise location references (line numbers, code snippets, function/method names).
– Describe the mechanism of the threat and its potential impact.
– Provide specific remediation recommendations for each issue.
– If no threats are detected, clearly state: “No threats detected.”
Critical Rules:
– Do not modify the code.
– Do not omit any suspicious fragments, even if the likelihood of risk is low.
– Do not include information unrelated to code security.
– Prioritize accuracy, completeness, and compliance with industry security standards."""
        self.ai_analyzer: Optional[AICodeAnalyzer] = None
        self.ai_ready = threading.Event()
        self.progress_message: str = ""
        self.docker_client = self._initialize_docker_client()
        self.init_thread: Optional[threading.Thread] = None
        
        if self.docker_client:
            self._pull_trivy_image()

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
        self.ai_analyzer = AICodeAnalyzer(model_name=self.desired_model_name)
        if self.ai_analyzer and self.ai_analyzer.model:
            self.ai_ready.set()
            logging.info("AI Code Analyzer is ready.")
        else:
            logging.error("AI Code Analyzer failed to initialize.")

    def _initialize_docker_client(self) -> Optional[Any]:
                                                                                 
        try:
            import docker
            from docker.errors import DockerException
        except Exception:
            logging.info("Docker SDK not installed. Trivy scan will be unavailable.")
            return None
        try:
            client = docker.from_env()
            client.ping()
            logging.info("Docker connection established.")
            return client
        except DockerException:
            logging.warning("Docker is not running or not installed. Trivy scan will be unavailable.")
            return None

    def _pull_trivy_image(self):
        if not self.docker_client:
            return
        try:
            import docker
            self.docker_client.images.get("aquasec/trivy:latest")
            logging.info("Trivy image already exists.")
        except Exception as e:
            try:
                                                                           
                logging.info("Pulling Trivy image, this may take a moment...")
                self.docker_client.images.pull("aquasec/trivy", "latest")
                logging.info("Trivy image pulled successfully.")
            except Exception as e2:
                logging.error(f"Failed to pull trivy image: {e2}")

    def _summarize_risk_categories(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
           
        buckets: Dict[str, Dict[str, Any]] = {}
        def add(cat: str, sev: str):
            if not cat:
                return
            b = buckets.setdefault(cat, {"category": cat, "count": 0, "max_severity": "Low"})
            b["count"] += 1
            order = ["Low", "Medium", "High", "Critical"]
            if order.index(sev if sev in order else "Medium") > order.index(b["max_severity"]):
                b["max_severity"] = sev if sev in order else "Medium"

        for f in findings:
            desc = (f.get("description") or "").lower()
            code = (f.get("code_snippet") or "").lower()
            sev = f.get("severity", "Medium")
            cat = None
            text = desc + "\n" + code
            if any(k in text for k in ["subprocess", "shell=true", "os.system", "popen"]):
                cat = "Command Execution"
            elif "eval" in text or "exec(" in text:
                cat = "Dynamic Code"
            elif any(k in text for k in ["requests.", "http://", "https://", "socket."]):
                cat = "Network/Exfiltration"
            elif any(k in text for k in ["secret", "password", "apikey", "token"]):
                cat = "Secrets/Hardcoded"
            elif any(k in text for k in ["pickle.load", "yaml.load("]):
                cat = "Unsafe Deserialization"
            elif any(k in text for k in ["md5(", "sha1(", "des("]):
                cat = "Weak Crypto"
            elif any(k in text for k in ["open(", "write(", "remove(", "unlink("]):
                cat = "Filesystem Access"
            else:
                cat = "General Risk"
            add(cat, sev)

                                          
        severity_rank = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}
        ranked = sorted(buckets.values(), key=lambda x: (x["count"], severity_rank.get(x["max_severity"], 1)), reverse=True)
        return ranked[:5]

    def _scan_with_trivy(self, file_path: str) -> str:
        if not self.docker_client:
            return "Trivy scan is unavailable because Docker is not running."
        try:
            import docker
            command = [
                'fs',
                '--scanners', 'vuln,secret',
                '--format', 'json',
                '--quiet',
                '--no-progress',
                f'/scan/{os.path.basename(file_path)}'
            ]

            container = self.docker_client.containers.run(
                'aquasec/trivy:latest',
                command,
                volumes={os.path.dirname(os.path.abspath(file_path)): {'bind': '/scan', 'mode': 'ro'}},
                remove=True,
                stderr=True,
                stdout=True
            )
            
            output = container.decode('utf-8')
            return self._parse_trivy_json(output)
        except Exception as e:
                                                                      
            error_msg = getattr(e, 'stderr', b'').decode('utf-8') if hasattr(e, 'stderr') and e.stderr else str(e)
            logging.error(f"Trivy scan failed: {error_msg}")
            return f"Trivy scan failed: {error_msg}"

    def _parse_trivy_json(self, json_string: str) -> str:
                                                                       
        try:
            data = json.loads(json_string)
        except json.JSONDecodeError:
            return "Could not parse Trivy output. It might not be valid JSON."

        if not data or 'Results' not in data or not data['Results']:
            return "No vulnerabilities or secrets found by Trivy."

        summary = []
        for result in data['Results']:
            target = result.get('Target', 'Unknown Target')
            summary.append(f"Target: {target}")

            if 'Vulnerabilities' in result and result['Vulnerabilities']:
                summary.append("  Vulnerabilities:")
                for vuln in result['Vulnerabilities']:
                    line = f"    - {vuln['VulnerabilityID']} ({vuln['Severity']}): {vuln['Title']}"
                    summary.append(line)
            
            if 'Secrets' in result and result['Secrets']:
                summary.append("  Secrets Found:")
                for secret in result['Secrets']:
                    line = f"    - {secret['Title']} (Severity: {secret['Severity']}) at line {secret['StartLine']}"
                    summary.append(line)

        return "\n".join(summary) if summary else "No issues found by Trivy."

    def _basic_static_analysis(self, code: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        lines = code.splitlines()
        # Per-rule severities to better reflect risk and avoid all-High findings
        rules: List[Dict[str, str]] = [
            {
                "pattern": r'subprocess\.run\(.*shell=True.*\)',
                "description": "Command Injection Risk",
                "explanation": "Using shell=True invokes a real shell. If any part of the command is user-controlled, attackers can inject additional shell syntax to execute arbitrary commands.",
                "severity": "Critical",
            },
            {
                "pattern": r'os\.system\s*\(',
                "description": "Command Execution Risk",
                "explanation": "os.system executes through a shell. If the command contains untrusted data, it can lead to command injection. Prefer subprocess with a list of args and without shell=True.",
                "severity": "High",
            },
            {
                "pattern": r'eval\s*\(',
                "description": "Use of eval",
                "explanation": "eval() executes arbitrary expressions. If tainted input reaches eval, it enables arbitrary code execution. Use safe parsers or explicit whitelists.",
                "severity": "High",
            },
            {
                "pattern": r'exec\s*\(',
                "description": "Use of exec",
                "explanation": "exec() executes arbitrary Python code. If untrusted input reaches exec, it enables arbitrary code execution. Avoid exec; refactor to safer alternatives.",
                "severity": "High",
            },
            {
                "pattern": r'pickle\.load',
                "description": "Unsafe Deserialization",
                "explanation": "Untrusted pickle data can execute code during loading. Use safer formats (e.g., JSON) for untrusted inputs.",
                "severity": "High",
            },
            {
                "pattern": r'yaml\.load\s*\(',
                "description": "Unsafe YAML load",
                "explanation": "yaml.load without SafeLoader can construct arbitrary objects. Use yaml.safe_load or specify SafeLoader.",
                "severity": "High",
            },
            {
                "pattern": r'hashlib\.(md5|sha1)\s*\(',
                "description": "Weak Cryptography",
                "explanation": "MD5/SHA-1 are considered broken for security-sensitive contexts. Use SHA-256 or stronger (and HMAC/AEAD where appropriate).",
                "severity": "Medium",
            },
            {
                "pattern": r'(?:Crypto\.Cipher\.DES\b|DES\.new\s*\()',
                "description": "Weak Cipher (DES)",
                "explanation": "DES is obsolete and insecure due to short key length. Use AES-GCM/ChaCha20-Poly1305.",
                "severity": "Medium",
            },
            {
                "pattern": r'(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*[\'\"][^\'\"]{6,}[\'\"]',
                "description": "Hardcoded Secret",
                "explanation": "Hardcoding credentials risks accidental leakage and compromise. Move secrets to a secure vault or environment variables.",
                "severity": "High",
            },
            {
                "pattern": r'AKIA[0-9A-Z]{16}',
                "description": "Potential AWS Access Key",
                "explanation": "String matches AWS access key pattern. Treat as secret and rotate if exposed.",
                "severity": "High",
            },
            {
                "pattern": r'(os\.remove|os\.unlink|shutil\.rmtree)\s*\(',
                "description": "Destructive Filesystem Operation",
                "explanation": "Deleting files/directories based on untrusted paths can enable path traversal or data loss. Validate and constrain paths.",
                "severity": "Medium",
            },
            {
                "pattern": r'open\s*\(.*?,\s*[\'\"][wa][\'\"]',
                "description": "File Write Operation",
                "explanation": "Writing to files using unvalidated user-controlled paths can lead to overwrites or injection. Validate paths and use secure directories.",
                "severity": "Medium",
            },
            {
                "pattern": r'requests\.(get|post|put|delete)\s*\(.*http[s]?://',
                "description": "Network Call (Hardcoded URL)",
                "explanation": "Hardcoded outbound HTTP requests may exfiltrate data or contact untrusted services. Ensure TLS, validation, and allowlists.",
                "severity": "Low",
            },
            {
                "pattern": r'socket\.socket\s*\(',
                "description": "Raw Socket Usage",
                "explanation": "Low-level sockets can bypass higher-level security checks. Audit inputs, destinations, and protocols.",
                "severity": "Low",
            },
        ]

        seen = set()  # (line_no, description)
        for i, line in enumerate(lines):
            for details in rules:
                try:
                    if re.search(details["pattern"], line):
                        key = (i + 1, details["description"])
                        if key in seen:
                            continue
                        seen.add(key)
                        findings.append({
                            "line": i + 1,
                            "code_snippet": line.strip(),
                            "description": details["description"],
                            "explanation": details["explanation"],
                            "severity": details.get("severity", "High"),
                            "source": "Heuristic Detector",
                        })
                except re.error:
                    # Skip invalid regex patterns gracefully
                    continue
        return findings

    def _calculate_security_score(self, findings: List[Dict[str, Any]]) -> int:
        score = 100
        severity_weights = {"Low": 5, "Medium": 10, "High": 20, "Critical": 30}
        for finding in findings:
            score -= severity_weights.get(finding.get("severity", "Medium"), 10)
        return max(0, score)

    def _fallback_explanation(self, description: str, code_snippet: str) -> str:
                                                                            
        desc = (description or "").lower()
        if "command" in desc or "shell" in code_snippet.lower():
            return (
                "The code executes a shell command (shell=True). If any part of the command is derived from"
                " external input, an attacker can inject additional shell syntax to execute arbitrary commands."
                " Impact: full system compromise under the user's privileges. Mitigation: avoid shell=True,"
                " pass a list of arguments, validate/escape inputs, or use shlex.split when appropriate."
            )
        if "eval" in desc or "eval(" in code_snippet:
            return (
                "The eval() function evaluates arbitrary Python expressions. If user-controlled data reaches"
                " eval(), it can execute arbitrary code. Impact: arbitrary code execution. Mitigation: avoid"
                " eval; use safe parsers (ast.literal_eval for literals) or explicit whitelists of operations."
            )
        if "deserial" in desc or "pickle" in code_snippet.lower():
            return (
                "Untrusted deserialization with pickle allows object gadgets to run code during loading."
                " If the data source can be influenced by an attacker, this can lead to RCE. Mitigation:"
                " do not use pickle for untrusted data; use safe formats like JSON and validate schema."
            )
                          
        return (
            "This pattern can be dangerous depending on input sources and context. Ensure strict validation,"
            " least-privilege execution, and prefer safer APIs. Add input sanitization and error handling."
        )

    def scan_file_for_malware(self, file_path: str, custom_prompt: Optional[str] = None) -> Dict[str, Any]:
                                                                                                                         
        if not os.path.exists(file_path):
            return {"error": f"File {file_path} does not exist"}

                                                                              
        if not (self.ai_analyzer and self.ai_ready.is_set()):
            try:
                self.prepare_ai_analyzer()
            except Exception:
                pass

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
                                                                                            
            detected = self._basic_static_analysis(code_content)
            total = len(detected)

                                                                                               
            findings: List[Dict[str, Any]] = []
            for idx, d in enumerate(detected, start=1):
                                                                                                 
                use_ai = bool(self.ai_analyzer and self.ai_ready.is_set() and getattr(self.ai_analyzer, 'model', None))
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
                                                           
                detail = (self.settings.get('ai_detail') or 'standard').lower()
                if detail == 'short':
                    detail_prompt = "Provide a concise 1-2 sentence security rationale and risk summary."
                elif detail == 'deep':
                    detail_prompt = "Provide an in-depth explanation including root cause, exploit scenario, impact, and concrete remediation steps with code suggestions."
                else:
                    detail_prompt = "Provide a clear explanation of the issue, why it's risky, and a brief remediation tip."
                merged_prompt = f"{custom_prompt + ' ' if custom_prompt else ''}{detail_prompt}".strip()
                if use_ai:
                    explanation = self.ai_analyzer.explain_snippet(d["code_snippet"], ctx, merged_prompt)
                else:
                    explanation = self._fallback_explanation(d.get("description", ""), d.get("code_snippet", ""))
                                                    
                try:
                    preview = (explanation or "").replace("\n", " ")[:200]
                    logging.info(f"AI explanation (len={len(explanation or '')}) for line {d['line']}: {preview}")
                except Exception:
                    pass
                norm = (explanation or "").strip()
                if (not norm) or len(norm) < 40 or norm.lower().startswith("potential risk present") or norm.startswith("An error occurred"):
                    explanation = self._fallback_explanation(d.get("description", ""), d.get("code_snippet", ""))
                findings.append({
                    "line": d["line"],
                    "code_snippet": d["code_snippet"],
                    "description": d["description"],
                    "explanation": explanation,
                    "severity": d.get("severity", "Medium"),
                    "source": "AI Analyzer" if use_ai else "Heuristic/Fallback"
                })
            self.progress_message = "Aggregating results..."

                                                                                            
            if self.settings.get('use_trivy') and self.docker_client:
                logging.info("Starting Trivy scan (optional)...")
                trivy_results_str = self._scan_with_trivy(file_path)
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

            result["findings"] = findings
            result["security_score"] = self._calculate_security_score(findings)
            result["risk_categories"] = self._summarize_risk_categories(findings)

        except Exception as e:
            logging.error(f"An unexpected error occurred during scan: {e}", exc_info=True)
            result["error"] = f"An unexpected error occurred: {e}"

                                  
        self.progress_message = ""
        return result
