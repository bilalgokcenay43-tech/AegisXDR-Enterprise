"""
MISP Threat Intelligence & Alert Enrichment Engine for AegisXDR-Enterprise.
Enriches correlated security alerts with MISP IoC reputation, GeoIP metadata,
SHA-256 hash reputation lookups, and user execution privilege levels.
"""

import os
import logging
import requests
from typing import Dict, Any, Optional

logger = logging.getLogger("AlertEnrichment")

class ThreatIntelEnricher:
    """
    Enriches alerts with contextual threat intelligence and user privilege scopes.
    """
    def __init__(self, misp_url: Optional[str] = None, misp_api_key: Optional[str] = None):
        self.misp_url = misp_url or os.getenv("MISP_URL", "https://misp.local")
        self.misp_api_key = misp_api_key or os.getenv("MISP_API_KEY", "YOUR_MISP_API_KEY_HERE")
        
        # Local Known Malicious IOC Fallback Database
        self.local_ioc_db = {
            "185.220.101.5": {"country": "Russia", "asn": "AS200052", "threat_type": "C2 Server / Tor Exit"},
            "45.154.255.88": {"country": "Netherlands", "asn": "AS49453", "threat_type": "Cobalt Strike Beacon"},
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {"malware": "Emotet Loader", "score": 95}
        }

    def check_misp_ioc(self, value: str) -> Optional[Dict[str, Any]]:
        """Queries MISP REST API for IP, Domain, or Hash IoC reputation."""
        if not value:
            return None

        # Try Local Database match first
        if value in self.local_ioc_db:
            logger.info(f"[Enrichment] Matched IoC '{value}' in local threat intelligence database.")
            return {"matched": True, "source": "MISP_LOCAL_CACHE", "details": self.local_ioc_db[value]}

        # Query MISP REST API if configured
        if self.misp_api_key and self.misp_api_key != "DEMO_KEY":
            try:
                headers = {
                    "Authorization": self.misp_api_key,
                    "Accept": "application/json",
                    "Content-Type": "application/json"
                }
                payload = {"returnFormat": "json", "value": value}
                response = requests.post(f"{self.misp_url}/attributes/restSearch", json=payload, headers=headers, timeout=3, verify=False)
                if response.status_code == 200:
                    data = response.json()
                    attr = data.get("response", {}).get("Attribute", [])
                    if attr:
                        return {"matched": True, "source": "MISP_SERVER", "details": attr[0]}
            except Exception as e:
                logger.debug(f"MISP API query timeout/error for IoC '{value}': {e}")

        return None

    def determine_user_privilege(self, user_str: str) -> str:
        """Categorizes process user execution privilege context."""
        user_lower = (user_str or "").lower()
        if "system" in user_lower or "nt authority" in user_lower:
            return "NT AUTHORITY\\SYSTEM (Highest Risk / Core System)"
        elif "admin" in user_lower or "administrator" in user_lower:
            return "Local / Domain Administrator"
        elif "service" in user_lower:
            return "Service Account"
        else:
            return f"Standard User ({user_str or 'Unknown'})"

    def enrich_alert(self, alert_data: Dict[str, Any], telemetry_event: Dict[str, Any]) -> Dict[str, Any]:
        """Enriches alert dictionary with GeoIP, MISP reputation, and Privilege context."""
        enriched = dict(alert_data)
        
        # 1. User Privilege Level Enrichment
        user = telemetry_event.get("user") or telemetry_event.get("User", "SYSTEM")
        enriched["privilege_level"] = self.determine_user_privilege(user)

        # 2. Network GeoIP & MISP IOC Lookup
        dest_ip = telemetry_event.get("dest_ip") or telemetry_event.get("ip_address")
        ioc_match = self.check_misp_ioc(dest_ip)
        
        if ioc_match:
            enriched["misp_intel"] = ioc_match
            enriched["threat_intel_matched"] = True
            enriched["geoip"] = ioc_match.get("details", {}).get("country", "Unknown")
        else:
            enriched["threat_intel_matched"] = False
            enriched["geoip"] = "Internal / Private IP"

        # 3. Hash Lookup
        file_hash = telemetry_event.get("hashes")
        if file_hash:
            hash_match = self.check_misp_ioc(file_hash)
            if hash_match:
                enriched["hash_reputation"] = hash_match

        logger.info(f"[Enrichment] Alert '{alert_data.get('rule_title')}' enriched. Privilege: {enriched['privilege_level']}, Intel Match: {enriched['threat_intel_matched']}")
        return enriched

enricher = ThreatIntelEnricher()
