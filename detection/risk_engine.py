"""
Dynamic Risk Scoring Engine for AegisXDR-Enterprise.
Calculates threat scores based on Rule Base Score, Asset Criticality multiplier, and Threat Intel IOC matches.
Categorizes risk into actionable SOC Tiers (LOW, MEDIUM, HIGH, CRITICAL).
"""

import logging
from typing import Dict, Any, Tuple

logger = logging.getLogger("RiskScoringEngine")

class RiskScoringEngine:
    """
    Computes dynamic risk score using the formula:
    Risk Score = (Rule Base Score * Asset Criticality) + Threat Intel Boost
    """
    def __init__(self):
        # Asset Criticality Mapping by Hostname / Role
        self.asset_criticality_map = {
            "DC-01": 1.3,             # Domain Controller
            "DOMAIN-CONTROLLER": 1.3,
            "FINANCE-WORKSTATION": 1.2,
            "SEC-OPS-01": 1.2,
            "WORKSTATION": 1.0,       # Standard Workstation
            "TEST-LAB": 0.7           # Non-production Lab
        }

    def calculate_score(
        self,
        base_score: float,
        hostname: str = "WORKSTATION",
        threat_intel_matched: bool = False,
        threat_intel_boost: float = 20.0
    ) -> Dict[str, Any]:
        """
        Calculates final risk score and assigns SOC action tier.
        Score Ranges:
          0-39: LOW (Log only)
          40-69: MEDIUM (Create Alert)
          70-89: HIGH (Require Analyst Approval)
          90-100+: CRITICAL (Automated SOAR Execution)
        """
        # Determine Asset Criticality Multiplier
        crit_multiplier = 1.0
        host_upper = hostname.upper()
        for key, mult in self.asset_criticality_map.items():
            if key in host_upper:
                crit_multiplier = mult
                break

        # Calculate Raw Risk Score
        ti_score = threat_intel_boost if threat_intel_matched else 0.0
        final_score = (base_score * crit_multiplier) + ti_score
        
        # Cap score between 0 and 100
        final_score = max(0.0, min(100.0, round(final_score, 1)))

        # Categorize Tier & Action Policy
        if final_score >= 90.0:
            severity = "CRITICAL"
            action = "AUTO_SOAR"
        elif final_score >= 70.0:
            severity = "HIGH"
            action = "REQUIRE_APPROVAL"
        elif final_score >= 40.0:
            severity = "MEDIUM"
            action = "CREATE_ALERT"
        else:
            severity = "LOW"
            action = "LOG_ONLY"

        result = {
            "risk_score": final_score,
            "severity": severity,
            "recommended_action": action,
            "base_score": base_score,
            "asset_criticality": crit_multiplier,
            "threat_intel_boost": ti_score
        }

        logger.info(
            f"[Risk Engine] Host: {hostname} | Base: {base_score} * Crit: {crit_multiplier} + TI: {ti_score} "
            f"=> Final Score: {final_score} ({severity} -> {action})"
        )

        return result

risk_engine = RiskScoringEngine()
