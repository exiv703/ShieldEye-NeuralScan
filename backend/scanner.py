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

CONFIG_FILE = os.path.join('data', 'config.json')

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
        
        # Security: Set resource limits for AI inference
        self.max_inference_time = 30.0  # seconds
        self.max_tokens = 512  # input token limit

        try:
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            
            load_kwargs = {
                "use_safetensors": True,
                "low_cpu_mem_usage": True,
            }
            
            if self.device == "cuda":
                try:
                    load_kwargs["load_in_8bit"] = True
                    load_kwargs["device_map"] = "auto"
                    logging.info("Loading model with 8-bit quantization")
                except:
                    load_kwargs["torch_dtype"] = torch.bfloat16
            else:
                load_kwargs["torch_dtype"] = torch.float32
            
            self.model = AutoModelForCausalLM.from_pretrained(model_name, **load_kwargs)
            
            if "device_map" not in load_kwargs:
                self.model = self.model.to(self.device)
            
            if getattr(self.tokenizer, "pad_token", None) is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token
            logging.info(f"Model {model_name} loaded successfully.")
        except Exception as e:
            logging.error(f"Could not load AI model '{model_name}'. AI analysis will be unavailable. Error: {e}")
            logging.info("Scanner will continue using fallback heuristic analysis.")
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
                inputs = self.tokenizer(prompt, return_tensors="pt", padding=True, truncation=True, max_length=self.max_tokens)
                
                if not hasattr(self.model, 'hf_device_map'):
                    inputs = {k: v.to(self.device) for k, v in inputs.items()}
                
                generated_ids = self.model.generate(
                    **inputs,
                    max_new_tokens=180,
                    do_sample=False,
                    temperature=0.2,
                    top_p=0.9,
                    pad_token_id=self.tokenizer.eos_token_id,
                    max_time=min(12.0, self.max_inference_time)
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
                inputs = self.tokenizer(prompt, return_tensors="pt", padding=True, truncation=True, max_length=self.max_tokens).to(self.device)
                generated_ids = self.model.generate(
                    inputs.input_ids,
                    attention_mask=inputs.attention_mask,
                    max_new_tokens=max_new,
                    do_sample=False,
                    pad_token_id=self.tokenizer.eos_token_id,
                    max_time=min(12.0, self.max_inference_time)
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
                    alt_inputs = self.tokenizer(alt_prompt, return_tensors="pt", padding=True, truncation=True, max_length=self.max_tokens).to(self.device)
                    alt_ids = self.model.generate(
                        alt_inputs.input_ids,
                        attention_mask=alt_inputs.attention_mask,
                        max_new_tokens=220,
                        do_sample=True,
                        temperature=0.8,
                        top_p=0.95,
                        pad_token_id=self.tokenizer.eos_token_id,
                        max_time=min(20.0, self.max_inference_time)
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
        self._load_config()
        
        self.settings.setdefault('use_trivy', False)
        self.settings.setdefault('save_history', True)
        self.settings.setdefault('ai_detail', 'standard')
        self.desired_model_name: str = self.settings.get('ai_model', "bigcode/starcoder2-3b")
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

    def _load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    saved_settings = json.load(f)
                    self.settings.update(saved_settings)
            except Exception as e:
                logging.error(f"Failed to load config: {e}")

    def save_config(self):
        try:
            os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.settings, f, indent=4)
            logging.info("Configuration saved.")
        except Exception as e:
            logging.error(f"Failed to save config: {e}")

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
        except ImportError as e:
            logging.info(f"Docker SDK not installed: {e}. Trivy scan will be unavailable.")
            return None
        except Exception as e:
            logging.warning(f"Unexpected error importing Docker SDK: {e}")
            return None
        
        try:
            client = docker.from_env()
            client.ping()
            logging.info("Docker connection established.")
            return client
        except DockerException as e:
            logging.warning(f"Docker error: {e}. Docker is not running or not accessible. Trivy scan will be unavailable.")
            return None
        except Exception as e:
            logging.error(f"Unexpected error connecting to Docker: {e}")
            return None

    def _pull_trivy_image(self):
        if not self.docker_client:
            return
        try:
            import docker
            from docker.errors import ImageNotFound, APIError
            
            self.docker_client.images.get("aquasec/trivy:latest")
            logging.info("Trivy image already exists.")
        except ImageNotFound:
            try:
                logging.info("Pulling Trivy image, this may take a moment...")
                self.docker_client.images.pull("aquasec/trivy", "latest")
                logging.info("Trivy image pulled successfully.")
            except APIError as e:
                logging.error(f"Docker API error while pulling Trivy image: {e}")
            except Exception as e:
                logging.error(f"Failed to pull Trivy image: {e}")
        except APIError as e:
            logging.error(f"Docker API error checking for Trivy image: {e}")
        except Exception as e:
            logging.error(f"Unexpected error checking Trivy image: {e}")

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
            sev = f.get("severity", "Medium")
            cat = f.get("category")

            if not cat:
                desc = (f.get("description") or "").lower()
                code = (f.get("code_snippet") or "").lower()
                text = desc + "\n" + code
                if "sql injection" in desc or "select" in text and " where " in text:
                    cat = "SQL Injection"
                elif any(k in text for k in ["subprocess", "shell=true", "os.system", "popen"]):
                    cat = "Command Injection"
                elif "eval" in text or "exec(" in text:
                    cat = "Dynamic Code Execution"
                elif any(k in text for k in ["pickle.load", "yaml.load("]):
                    cat = "Deserialization"
                elif any(k in text for k in ["md5(", "sha1(", "des(", "arc4("]):
                    cat = "Weak Cryptography"
                elif any(k in text for k in ["secret", "password", "apikey", "token", "aws_access_key_id"]):
                    cat = "Secrets & Keys"
                elif any(k in text for k in ["../", "open(", "remove(", "unlink(", "shutil.rmtree"]):
                    cat = "Filesystem / Path Traversal"
                elif any(k in text for k in ["requests.", "http://", "https://", "socket."]):
                    cat = "Network / Exfiltration"
                else:
                    cat = "General Risk"

            add(cat, sev)

        severity_rank = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}
        ranked = sorted(
            buckets.values(),
            key=lambda x: (x["count"], severity_rank.get(x["max_severity"], 1)),
            reverse=True,
        )
        return ranked[:5]

    def _scan_with_trivy(self, file_path: str) -> str:
        if not self.docker_client:
            return "Trivy scan is unavailable because Docker is not running."
        try:
            import docker
            from docker.errors import ContainerError, ImageNotFound, APIError
            
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
        except ImageNotFound as e:
            logging.error(f"Trivy image not found: {e}")
            return "Trivy scan failed: Trivy Docker image not found. Run installation to pull the image."
        except ContainerError as e:
            logging.error(f"Trivy container error: {e}")
            return f"Trivy scan failed: Container execution error - {e}"
        except APIError as e:
            logging.error(f"Docker API error during Trivy scan: {e}")
            return f"Trivy scan failed: Docker API error - {e}"
        except Exception as e:
            error_msg = getattr(e, 'stderr', b'').decode('utf-8') if hasattr(e, 'stderr') and e.stderr else str(e)
            logging.error(f"Unexpected error during Trivy scan: {error_msg}")
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
        rules: List[Dict[str, Any]] = [
            {
                "pattern": r'subprocess\.(?:run|call|Popen|check_output)\(.*shell=True.*\)',
                "description": "Command Injection Risk (shell=True)",
                "explanation": "Using shell=True invokes a real shell. If any part of the command is user-controlled, attackers can inject additional shell syntax to execute arbitrary commands.",
                "severity": "Critical",
                "category": "Command Injection",
                "cwe": "CWE-78",
                "owasp": "A03:2021-Injection",
                "remediation": "Avoid shell=True with untrusted input. Pass arguments as a list, validate/escape inputs, or use high-level APIs instead of spawning shells.",
                "confidence": "High",
                "pci_dss": "6.5.1",
                "nist": "SI-10",
            },
            {
                "pattern": r'os\.system\s*\(',
                "description": "Command Execution via os.system",
                "explanation": "os.system executes commands through a shell. If the command contains untrusted data, it can lead to command injection. Prefer subprocess with a list of args and without shell=True.",
                "severity": "High",
                "category": "Command Injection",
                "cwe": "CWE-78",
                "owasp": "A03:2021-Injection",
                "remediation": "Replace os.system with subprocess.run([...]) without shell=True and ensure all inputs are validated or hard-coded.",
                "confidence": "High",
                "pci_dss": "6.5.1",
                "nist": "SI-10",
            },
            {
                "pattern": r'os\.popen\s*\(',
                "description": "Command Execution via os.popen",
                "explanation": "os.popen runs a shell command and captures output. If any part of the command is user-controlled, this can lead to command injection.",
                "severity": "High",
                "category": "Command Injection",
                "cwe": "CWE-78",
                "owasp": "A03:2021-Injection",
                "remediation": "Avoid os.popen for executing commands. Use subprocess APIs with argument lists and remove direct concatenation of user input into commands.",
                "confidence": "High",
                "pci_dss": "6.5.1",
                "nist": "SI-10",
            },
            {
                "pattern": r"\.execute\([^\)]*(?i)(select|insert|update|delete)[^\)]*\+\s*",
                "description": "Possible SQL Injection (string concatenation)",
                "explanation": "Building SQL queries via string concatenation allows attackers to inject arbitrary SQL when untrusted input is concatenated into the query. Use parameterized queries instead.",
                "severity": "High",
                "category": "SQL Injection",
                "cwe": "CWE-89",
                "owasp": "A03:2021-Injection",
                "remediation": "Use parameterized queries / prepared statements. Never concatenate untrusted input directly into SQL strings.",
                "confidence": "High",
                "pci_dss": "6.5.1",
                "nist": "SI-10",
            },
            {
                "pattern": r"\.execute\([^\)]*%s[^\)]*%[^\)]*\)",
                "description": "Possible SQL Injection (percent formatting)",
                "explanation": "Using %s-style string formatting to build SQL queries can allow injection if untrusted data is interpolated. Use parameterized queries provided by the DB driver.",
                "severity": "High",
                "category": "SQL Injection",
                "cwe": "CWE-89",
                "owasp": "A03:2021-Injection",
                "remediation": "Avoid %-style string formatting for SQL. Use placeholders supported by the DB driver and pass parameters separately.",
                "confidence": "High",
                "pci_dss": "6.5.1",
                "nist": "SI-10",
            },
            {
                "pattern": r"\.execute\(\s*f['\"](?i)(select|insert|update|delete).*{[^}]+}.*['\"]\s*\)",
                "description": "Possible SQL Injection (f-string)",
                "explanation": "Using f-strings to interpolate variables directly into SQL statements can lead to SQL injection. Use bind parameters / placeholders instead.",
                "severity": "High",
                "category": "SQL Injection",
                "cwe": "CWE-89",
                "owasp": "A03:2021-Injection",
                "remediation": "Do not format SQL using f-strings. Switch to parameterized queries and bind variables instead of interpolating them.",
                "confidence": "High",
                "pci_dss": "6.5.1",
                "nist": "SI-10",
            },
            {
                "pattern": r"\.execute\(\s*['\"].*(?i)(select|insert|update|delete).*['\"]\s*\.format\(",
                "description": "Possible SQL Injection (.format)",
                "explanation": "Using .format() on SQL strings can allow injection when untrusted values are formatted into the query. Prefer parameterized queries.",
                "severity": "High",
                "category": "SQL Injection",
                "cwe": "CWE-89",
                "owasp": "A03:2021-Injection",
                "remediation": "Avoid using .format() to build SQL. Use placeholders (e.g. ? or %s) and pass user input as separate parameters.",
                "confidence": "High",
                "pci_dss": "6.5.1",
                "nist": "SI-10",
            },
            {
                "pattern": r'eval\s*\(',
                "description": "Use of eval",
                "explanation": "eval() executes arbitrary expressions. If tainted input reaches eval, it enables arbitrary code execution. Use safe parsers or explicit whitelists.",
                "severity": "High",
                "category": "Dynamic Code Execution",
                "cwe": "CWE-94",
                "owasp": "A03:2021-Injection",
                "remediation": "Avoid eval on dynamic input. Use safe parsers (e.g. ast.literal_eval) or explicit allowlists of operations.",
                "confidence": "High",
                "pci_dss": "6.5.1",
                "nist": "SI-10",
            },
            {
                "pattern": r'exec\s*\(',
                "description": "Use of exec",
                "explanation": "exec() executes arbitrary Python code. If untrusted input reaches exec, it enables arbitrary code execution. Avoid exec; refactor to safer alternatives.",
                "severity": "High",
                "category": "Dynamic Code Execution",
                "cwe": "CWE-94",
                "owasp": "A03:2021-Injection",
                "remediation": "Refactor code to avoid exec. Use functions, mappings or plugins instead of executing constructed code strings.",
                "confidence": "High",
                "pci_dss": "6.5.1",
                "nist": "SI-10",
            },
            {
                "pattern": r'pickle\.load',
                "description": "Unsafe Deserialization (pickle.load)",
                "explanation": "Untrusted pickle data can execute code during loading. Use safer formats (e.g., JSON) for untrusted inputs.",
                "severity": "High",
                "category": "Deserialization",
                "cwe": "CWE-502",
                "owasp": "A08:2021-Software and Data Integrity Failures",
                "remediation": "Do not use pickle for untrusted data. Prefer JSON/MsgPack with strict schema validation and type checks.",
                "confidence": "High",
                "pci_dss": "6.5.6",
                "nist": "SI-10",
            },
            {
                "pattern": r'yaml\.load\s*\(',
                "description": "Unsafe YAML load",
                "explanation": "yaml.load without SafeLoader can construct arbitrary objects. Use yaml.safe_load or specify SafeLoader.",
                "severity": "High",
                "category": "Deserialization",
                "cwe": "CWE-502",
                "owasp": "A08:2021-Software and Data Integrity Failures",
                "remediation": "Use yaml.safe_load with SafeLoader (or FullLoader with caution) when parsing untrusted YAML content.",
                "confidence": "Medium",
                "pci_dss": "6.5.6",
                "nist": "SI-10",
            },
            {
                "pattern": r'hashlib\.(md5|sha1)\s*\(',
                "description": "Weak Cryptography (MD5/SHA1)",
                "explanation": "MD5/SHA-1 are considered broken for security-sensitive contexts. Use SHA-256 or stronger (and HMAC/AEAD where appropriate).",
                "severity": "Medium",
                "category": "Weak Cryptography",
                "cwe": "CWE-327",
                "owasp": "A02:2021-Cryptographic Failures",
                "remediation": "Replace MD5/SHA-1 with modern hashes like SHA-256 and use HMAC/AEAD modes where appropriate.",
                "confidence": "High",
                "pci_dss": "4.1",
                "nist": "SC-13",
            },
            {
                "pattern": r'(?:Crypto\.Cipher\.DES\b|DES\.new\s*\()',
                "description": "Weak Cipher (DES)",
                "explanation": "DES is obsolete and insecure due to short key length. Use AES-GCM/ChaCha20-Poly1305.",
                "severity": "Medium",
                "category": "Weak Cryptography",
                "cwe": "CWE-327",
                "owasp": "A02:2021-Cryptographic Failures",
                "remediation": "Migrate from DES to a modern cipher such as AES-GCM or ChaCha20-Poly1305 with strong keys.",
                "confidence": "High",
                "pci_dss": "4.1",
                "nist": "SC-13",
            },
            {
                "pattern": r'(?:Crypto\.Cipher\.ARC4\b|ARC4\.new\s*\()',
                "description": "Weak Cipher (RC4/ARC4)",
                "explanation": "RC4/ARC4 are considered insecure due to multiple cryptographic weaknesses. Avoid RC4 and use modern AEAD ciphers instead.",
                "severity": "Medium",
                "category": "Weak Cryptography",
                "cwe": "CWE-327",
                "owasp": "A02:2021-Cryptographic Failures",
                "remediation": "Avoid RC4/ARC4 and use modern AEAD ciphers (AES-GCM, ChaCha20-Poly1305) provided by well-maintained libraries.",
                "confidence": "High",
                "pci_dss": "4.1",
                "nist": "SC-13",
            },
            {
                "pattern": r'(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*["\"][^"\"]{6,}["\"]',
                "description": "Hardcoded Secret",
                "explanation": "Hardcoding credentials risks accidental leakage and compromise. Move secrets to a secure vault or environment variables.",
                "severity": "High",
                "category": "Secrets & Keys",
                "cwe": "CWE-798",
                "owasp": "A02:2021-Cryptographic Failures",
                "remediation": "Remove hardcoded secrets from source code. Load them from a secure secrets manager or environment variables.",
                "confidence": "Medium",
                "pci_dss": "8.2.1",
                "nist": "IA-5",
                "gdpr": "Article 32",
            },
            {
                "pattern": r'AKIA[0-9A-Z]{16}',
                "description": "Potential AWS Access Key",
                "explanation": "String matches AWS access key pattern. Treat as secret and rotate if exposed.",
                "severity": "High",
                "category": "Secrets & Keys",
                "cwe": "CWE-798",
                "owasp": "A02:2021-Cryptographic Failures",
                "remediation": "Rotate the exposed AWS access key immediately and move credentials to a dedicated secrets management system.",
                "confidence": "Medium",
                "pci_dss": "8.2.1",
                "nist": "IA-5",
                "gdpr": "Article 32",
            },
            {
                "pattern": r'-----BEGIN RSA PRIVATE KEY-----',
                "description": "Hardcoded Private Key",
                "explanation": "Embedding private keys directly in source code risks key leakage and long-term compromise. Use secure key management instead.",
                "severity": "Critical",
                "category": "Secrets & Keys",
                "cwe": "CWE-522",
                "owasp": "A02:2021-Cryptographic Failures",
                "remediation": "Remove private keys from the repository. Store them in a secure key vault and reference them via configuration only.",
                "confidence": "High",
                "pci_dss": "3.5",
                "nist": "SC-12",
                "gdpr": "Article 32",
            },
            {
                "pattern": r'(os\.remove|os\.unlink|shutil\.rmtree)\s*\(',
                "description": "Destructive Filesystem Operation",
                "explanation": "Deleting files/directories based on untrusted paths can enable path traversal or data loss. Validate and constrain paths.",
                "severity": "Medium",
                "category": "Filesystem Access",
                "cwe": "CWE-22",
                "owasp": "A01:2021-Broken Access Control",
                "remediation": "Validate and normalize filesystem paths, restrict deletions to allowed directories, and avoid using untrusted input directly in file APIs.",
                "confidence": "Medium",
                "pci_dss": "6.5.8",
                "nist": "AC-3",
            },
            {
                "pattern": r'open\s*\(.*?,\s*["\"][wa]["\"]',
                "description": "File Write Operation",
                "explanation": "Writing to files using unvalidated user-controlled paths can lead to overwrites or injection. Validate paths and use secure directories.",
                "severity": "Medium",
                "category": "Filesystem Access",
                "cwe": "CWE-22",
                "owasp": "A01:2021-Broken Access Control",
                "remediation": "Ensure file paths are validated, constrained to specific directories, and not constructed directly from untrusted user input.",
                "confidence": "Low",
                "pci_dss": "6.5.8",
                "nist": "AC-3",
            },
            {
                "pattern": r'"\.\./',
                "description": "Potential Path Traversal (relative path)",
                "explanation": "Using ../ in paths can indicate directory traversal. When combined with untrusted input, this can allow access outside intended directories.",
                "severity": "Medium",
                "category": "Path Traversal",
                "cwe": "CWE-22",
                "owasp": "A01:2021-Broken Access Control",
                "remediation": "Normalize and validate paths, strip ../ sequences, and use safe join functions to prevent escaping the intended directory.",
                "confidence": "Low",
                "pci_dss": "6.5.8",
                "nist": "AC-3",
            },
            {
                "pattern": r'zipfile\.ZipFile\s*\(',
                "description": "Zip Processing (check for Zip Slip)",
                "explanation": "Extracting archives without validating file paths can lead to Zip Slip, where files are written outside the intended directory.",
                "severity": "Medium",
                "category": "Filesystem Access",
                "cwe": "CWE-22",
                "owasp": "A01:2021-Broken Access Control",
                "remediation": "Validate each member path in archives before extraction and prevent files from writing outside the target directory.",
                "confidence": "Low",
                "pci_dss": "6.5.8",
                "nist": "AC-3",
            },
            {
                "pattern": r'requests\.(get|post|put|delete)\s*\(.*http://',
                "description": "HTTP Request without TLS",
                "explanation": "Using plain HTTP instead of HTTPS can expose sensitive data to interception and tampering. Prefer HTTPS endpoints whenever possible.",
                "severity": "Medium",
                "category": "Network / Exfiltration",
                "cwe": "CWE-319",
                "owasp": "A02:2021-Cryptographic Failures",
                "remediation": "Use HTTPS for all sensitive traffic and update endpoints to enforce TLS with strong cipher suites.",
                "confidence": "High",
                "pci_dss": "4.1",
                "nist": "SC-8",
            },
            {
                "pattern": r'requests\.(get|post|put|delete)\s*\([^\)]*verify\s*=\s*False',
                "description": "TLS Verification Disabled",
                "explanation": "Disabling TLS certificate verification exposes connections to man-in-the-middle attacks. Only disable verification for controlled debugging scenarios.",
                "severity": "High",
                "category": "Network / Exfiltration",
                "cwe": "CWE-295",
                "owasp": "A02:2021-Cryptographic Failures",
                "remediation": "Do not set verify=False in production. Configure proper CA bundles and validate certificates for all outbound HTTPS requests.",
                "confidence": "High",
                "pci_dss": "4.1",
                "nist": "SC-8",
            },
            {
                "pattern": r'requests\.(get|post|put|delete)\s*\(.*https?://',
                "description": "Outbound HTTP Request",
                "explanation": "Outbound HTTP requests may exfiltrate data or contact untrusted services. Ensure endpoints are trusted and inputs are validated.",
                "severity": "Low",
                "category": "Network / Exfiltration",
                "cwe": "CWE-200",
                "owasp": "A01:2021-Broken Access Control",
                "remediation": "Restrict outbound HTTP calls to approved domains and validate all request parameters before sending.",
                "confidence": "Low",
                "pci_dss": "1.3",
                "nist": "SC-7",
            },
            {
                "pattern": r'socket\.socket\s*\(',
                "description": "Raw Socket Usage",
                "explanation": "Low-level socket usage can bypass higher-level security controls. Carefully validate destinations, ports, and data.",
                "severity": "Low",
                "category": "Network / Exfiltration",
                "cwe": "CWE-200",
                "owasp": "A05:2021-Security Misconfiguration",
                "remediation": "Wrap raw socket usage with validation logic, restrict remote endpoints, and consider higher-level protocols with built-in security.",
                "confidence": "Low",
                "pci_dss": "1.3",
                "nist": "SC-7",
            },
        ]

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
                except re.error:
                    continue
        return findings
    
    def _adjust_severity_by_context(self, finding: Dict[str, Any], lines: List[str], line_idx: int) -> Dict[str, Any]:
        start = max(0, line_idx - 3)
        end = min(len(lines), line_idx + 4)
        context = "\n".join(lines[start:end]).lower()
        
        severity = finding["severity"]
        confidence = finding.get("confidence", "Medium")
        
        if any(marker in context for marker in ["# nosec", "# noqa", "# nosonar", "# skipcq"]):
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

    def _calculate_security_score(self, findings: List[Dict[str, Any]], policy: str = 'standard') -> int:
        score = 100
        policy = (policy or 'standard').lower()
        
        if policy in ['quick', 'short']:
            severity_weights = {"Low": 0, "Medium": 5, "High": 15, "Critical": 25}
            category_cap = 40
        elif policy == 'deep':
            severity_weights = {"Low": 10, "Medium": 20, "High": 30, "Critical": 45}
            category_cap = 80
        else:
            severity_weights = {"Low": 5, "Medium": 10, "High": 20, "Critical": 30}
            category_cap = 60

        penalties_by_category: Dict[str, int] = {}

        for finding in findings:
            sev = finding.get("severity", "Medium")
            if policy == 'quick' and sev == 'Low':
                continue
                
            weight = severity_weights.get(sev, 10)
            cat = finding.get("category") or "General"
            current = penalties_by_category.get(cat, 0)
            
            penalties_by_category[cat] = min(current + weight, category_cap)

        total_penalty = sum(penalties_by_category.values())
        score -= total_penalty
        return max(0, score)

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

            # Effective detail level: per-call override > global setting
            effective_detail = (detail or self.settings.get('ai_detail') or 'standard').lower()

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
            result["security_score"] = self._calculate_security_score(findings, policy=effective_detail)
            result["risk_categories"] = self._summarize_risk_categories(findings)

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
    
    def export_report(self, scan_result: Dict[str, Any], format: str = 'json', output_path: str = None) -> str:
        if format == 'json':
            report = self._export_json(scan_result)
        elif format == 'markdown':
            report = self._export_markdown(scan_result)
        elif format == 'html':
            report = self._export_html(scan_result)
        else:
            raise ValueError(f"Unsupported format: {format}. Use 'json', 'markdown', or 'html'.")
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report)
            logging.info(f"Report exported to {output_path}")
        
        return report
    
    def _export_json(self, scan_result: Dict[str, Any]) -> str:
        import json
        return json.dumps(scan_result, indent=2, ensure_ascii=False)
    
    def _export_markdown(self, scan_result: Dict[str, Any]) -> str:
        lines = []
        lines.append("# Security Scan Report\n")
        lines.append(f"**File:** `{scan_result.get('file_path', 'Unknown')}`\n")
        lines.append(f"**Security Score:** {scan_result.get('security_score', 0)}/100\n")
        lines.append(f"**Total Findings:** {len(scan_result.get('findings', []))}\n")
        
        risk_cats = scan_result.get('risk_categories', [])
        if risk_cats:
            lines.append("\n## Risk Categories\n")
            for cat in risk_cats:
                lines.append(f"- **{cat['category']}**: {cat['count']} issues (Max Severity: {cat['max_severity']})")
        
        findings = scan_result.get('findings', [])
        if findings:
            lines.append("\n## Findings\n")
            for i, finding in enumerate(findings, 1):
                lines.append(f"\n### {i}. {finding.get('description', 'Unknown Issue')}\n")
                lines.append(f"- **Line:** {finding.get('line', 'N/A')}")
                lines.append(f"- **Severity:** {finding.get('severity', 'Unknown')}")
                if 'confidence' in finding:
                    lines.append(f"- **Confidence:** {finding['confidence']}")
                if 'category' in finding:
                    lines.append(f"- **Category:** {finding['category']}")
                if 'cwe' in finding:
                    lines.append(f"- **CWE:** {finding['cwe']}")
                if 'owasp' in finding:
                    lines.append(f"- **OWASP:** {finding['owasp']}")
                if 'pci_dss' in finding:
                    lines.append(f"- **PCI-DSS:** {finding['pci_dss']}")
                if 'nist' in finding:
                    lines.append(f"- **NIST:** {finding['nist']}")
                
                lines.append(f"\n**Code:**\n```python\n{finding.get('code_snippet', '')}\n```\n")
                lines.append(f"**Explanation:** {finding.get('explanation', '')}\n")
                
                if 'remediation' in finding:
                    lines.append(f"**Remediation:** {finding['remediation']}\n")
        
        return "\n".join(lines)
    
    def _export_html(self, scan_result: Dict[str, Any]) -> str:
        import html
        findings = scan_result.get('findings', [])
        score = scan_result.get('security_score', 0)
        
        if score >= 80:
            score_color = "#28a745"
        elif score >= 60:
            score_color = "#ffc107"
        else:
            score_color = "#dc3545"
        
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Scan Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        .score {{ font-size: 48px; font-weight: bold; color: {score_color}; }}
        .finding {{ border-left: 4px solid #007bff; padding: 15px; margin: 20px 0; background: #f8f9fa; }}
        .critical {{ border-left-color: #dc3545; }}
        .high {{ border-left-color: #fd7e14; }}
        .medium {{ border-left-color: #ffc107; }}
        .low {{ border-left-color: #28a745; }}
        .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; margin: 2px; }}
        .badge-critical {{ background: #dc3545; color: white; }}
        .badge-high {{ background: #fd7e14; color: white; }}
        .badge-medium {{ background: #ffc107; color: black; }}
        .badge-low {{ background: #28a745; color: white; }}
        code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; }}
        pre {{ background: #282c34; color: #abb2bf; padding: 15px; border-radius: 5px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Security Scan Report</h1>
        <p><strong>File:</strong> <code>{html.escape(scan_result.get('file_path', 'Unknown'))}</code></p>
        <p><strong>Security Score:</strong> <span class="score">{score}/100</span></p>
        <p><strong>Total Findings:</strong> {len(findings)}</p>
        
        <h2>Findings</h2>
"""
        
        for i, finding in enumerate(findings, 1):
            severity = finding.get('severity', 'Medium').lower()
            severity_badge = f"badge-{severity}"
            
            html_content += f"""
        <div class="finding {severity}">
            <h3>{i}. {html.escape(finding.get('description', 'Unknown Issue'))}</h3>
            <p>
                <span class="badge {severity_badge}">{html.escape(finding.get('severity', 'Unknown'))}</span>
"""
            if 'confidence' in finding:
                html_content += f"""                <span class="badge" style="background: #6c757d; color: white;">Confidence: {html.escape(str(finding['confidence']))}</span>\n"""
            if 'cwe' in finding:
                html_content += f"""                <span class="badge" style="background: #17a2b8; color: white;">{html.escape(str(finding['cwe']))}</span>\n"""
            if 'owasp' in finding:
                html_content += f"""                <span class="badge" style="background: #6610f2; color: white;">{html.escape(str(finding['owasp']))}</span>\n"""
            
            html_content += f"""            </p>
            <p><strong>Line:</strong> {html.escape(str(finding.get('line', 'N/A')))}</p>
            <pre><code>{html.escape(finding.get('code_snippet', ''))}</code></pre>
            <p>{html.escape(finding.get('explanation', ''))}</p>
"""
            if 'remediation' in finding:
                html_content += f"""            <p><strong>🔧 Remediation:</strong> {html.escape(finding['remediation'])}</p>\n"""
            
            html_content += """        </div>\n"""
        
        html_content += """    </div>
</body>
</html>"""
        
        return html_content
