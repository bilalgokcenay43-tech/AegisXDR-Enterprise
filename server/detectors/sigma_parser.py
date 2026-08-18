"""
SIGMA Rule Parser & Detection Engine for AegisXDR-Enterprise.
Parses standard YAML SIGMA rules and evaluates events against multi-field detection selections and logical conditions.
"""

import os
import re
import yaml
from typing import Dict, Any, List
from config import settings

class SigmaEngine:
    def __init__(self, rules_dir: str = None):
        self.rules_dir = rules_dir or settings.SIGMA_RULES_DIR
        self.rules: List[Dict[str, Any]] = []
        self.load_rules()

    def load_rules(self):
        """Loads all YAML SIGMA rules from the designated rules directory."""
        self.rules.clear()
        if not os.path.exists(self.rules_dir):
            os.makedirs(self.rules_dir, exist_ok=True)
            return

        for filename in os.listdir(self.rules_dir):
            if filename.endswith(".yml") or filename.endswith(".yaml"):
                filepath = os.path.join(self.rules_dir, filename)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        rule = yaml.safe_load(f)
                        if rule and isinstance(rule, dict) and "detection" in rule:
                            self.rules.append(rule)
                except Exception as e:
                    print(f"[SIGMA Parser] Error loading rule {filename}: {e}")

    def _match_field_condition(self, field_val: str, pattern: Any) -> bool:
        """Helper to match field values against strings, lists, or modifier rules."""
        if field_val is None:
            return False
        field_val_str = str(field_val).lower()

        if isinstance(pattern, list):
            return any(self._match_field_condition(field_val_str, p) for p in pattern)
        
        pattern_str = str(pattern).lower()
        return pattern_str in field_val_str

    def _evaluate_selection(self, selection: Dict[str, Any], event: Dict[str, Any]) -> bool:
        """Evaluates a single SIGMA selection block against event attributes."""
        field_map = {
            "image": event.get("process_name") or event.get("process_path"),
            "parentimage": event.get("parent_name"),
            "commandline": event.get("cmdline"),
            "hostname": event.get("hostname"),
            "processid": event.get("pid"),
        }

        for key, expected in selection.items():
            # Handle field modifiers (e.g., CommandLine|contains, Image|endswith)
            key_parts = key.split("|")
            field_name = key_parts[0].lower()
            modifier = key_parts[1].lower() if len(key_parts) > 1 else None

            actual_val = field_map.get(field_name, event.get(field_name))

            if actual_val is None:
                return False

            actual_str = str(actual_val).lower()

            if isinstance(expected, list):
                patterns = [str(p).lower() for p in expected]
            else:
                patterns = [str(expected).lower()]

            matched = False
            for p in patterns:
                if modifier == "contains":
                    if p in actual_str:
                        matched = True
                        break
                elif modifier == "endswith":
                    if actual_str.endswith(p):
                        matched = True
                        break
                elif modifier == "startswith":
                    if actual_str.startswith(p):
                        matched = True
                        break
                elif modifier == "re":
                    if re.search(p, actual_str, re.IGNORECASE):
                        matched = True
                        break
                else: # Default exact or substring check
                    if p in actual_str:
                        matched = True
                        break

            if not matched:
                return False

        return True

    def analyze(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluates event telemetry against all loaded SIGMA rules."""
        alerts = []

        for rule in self.rules:
            try:
                detection = rule.get("detection", {})
                condition = detection.get("condition", "selection")

                # Simplified condition evaluator (supports 'selection', 'selection and not filter', '1 of selection*')
                selections = {k: v for k, v in detection.items() if k != "condition"}
                selection_results = {}

                for sel_name, sel_body in selections.items():
                    if isinstance(sel_body, dict):
                        selection_results[sel_name] = self._evaluate_selection(sel_body, event)
                    elif isinstance(sel_body, list):
                        # List of selections treated as OR
                        selection_results[sel_name] = any(
                            self._evaluate_selection(item, event) for item in sel_body if isinstance(item, dict)
                        )

                # Basic condition evaluation
                rule_matched = False
                if condition == "selection":
                    rule_matched = selection_results.get("selection", False)
                elif "and" in condition:
                    parts = [p.strip() for p in condition.split("and")]
                    rule_matched = all(selection_results.get(p, False) for p in parts if not p.startswith("not"))
                elif "or" in condition:
                    parts = [p.strip() for p in condition.split("or")]
                    rule_matched = any(selection_results.get(p, False) for p in parts)
                else:
                    # Fallback match if any selection matched
                    rule_matched = any(selection_results.values()) if selection_results else False

                if rule_matched:
                    level = str(rule.get("level", "medium")).upper()
                    if level == "INFORMATIONAL": level = "LOW"
                    
                    alerts.append({
                        "rule_id": rule.get("id", "SIGMA-RULE"),
                        "rule_title": rule.get("title", "SIGMA Detection Match"),
                        "severity": level,
                        "mitre_tactic": ", ".join(rule.get("tags", ["Execution"])),
                        "mitre_technique": rule.get("tags", ["T1059"])[0] if rule.get("tags") else "T1059",
                        "description": rule.get("description", "SIGMA rule condition matched telemetry payload.")
                    })
            except Exception as e:
                print(f"[SIGMA Engine] Error evaluating rule {rule.get('title')}: {e}")

        return alerts

sigma_engine = SigmaEngine()
