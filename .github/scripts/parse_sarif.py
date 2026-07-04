import json
from dataclasses import dataclass

@dataclass
class EvaluationResult:
    gate_failed: bool
    gate_warn: bool
    
def evaluate(sarif_paths):
    if isinstance(sarif_paths, str):
        sarif_paths = [sarif_paths]

    max_score = 0.0
    for path in sarif_paths:
        with open(path) as f:
            sarif = json.load(f, strict=False)

        for run in sarif.get("runs", []):
            rules = run["tool"]["driver"].get("rules", [])
            severities = {r["id"]: r.get("properties", {}).get("security-severity") for r in rules}
                        
            for result in run.get("results", []):
                score = severities.get(result["ruleId"])
                if score is not None:
                    max_score = max(max_score, float(score))
                    
    return EvaluationResult(
            gate_failed=max_score >= 8,
            gate_warn=5 <= max_score < 8,
        )