"""AI code analyzer. Owns the model lifecycle, separate from scan orchestration."""
import logging
from typing import Dict, Any, Optional

try:
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM
    AI_LIBS_AVAILABLE = True
except ImportError:
    AI_LIBS_AVAILABLE = False


class AICodeAnalyzer:
    def __init__(self, model_name="bigcode/starcoder2-3b", settings: Optional[Dict[str, Any]] = None):
        self.settings = settings or {}
        if not AI_LIBS_AVAILABLE:
            logging.warning("AI libraries not available. AI analysis is disabled.")
            self.model = None
            self.tokenizer = None
            return

        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        logging.info(f"AI Analyzer is using device: {self.device}")

        # Security: Set resource limits for AI inference
        timeout_ms = self.settings.get('scan_timeout', 2500)
        try:
            timeout_seconds = float(timeout_ms) / 1000.0
        except (TypeError, ValueError):
            timeout_seconds = 2.5
        self.max_inference_time = min(30.0, timeout_seconds) if timeout_seconds > 0 else 30.0  # seconds
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
                except Exception as e:
                    logging.warning("8-bit quantization setup failed; falling back to bfloat16. Error: %s", e)
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

    def explain_snippet(self, snippet: str, surrounding: Optional[str], custom_prompt: Optional[str] = None) -> str:
        if not self.model or not self.tokenizer:
            return "AI Analyzer is not available."

        base = (
            "You are a security expert. Explain succinctly why the following code may be dangerous,"
            " referencing concrete risks (CWE/OWASP where relevant) and potential impact."
            " Provide remediation advice in 1-2 sentences."
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
