# Why: scoring logic is testable in isolation without instantiating a full scanner
from typing import Dict, Any, List


def summarize_risk_categories(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
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


def calculate_security_score(findings: List[Dict[str, Any]], policy: str = 'standard') -> int:
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
        if finding.get("suppressed") is True:
            continue

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
