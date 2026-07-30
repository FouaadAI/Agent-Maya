"""
Takedown Vektoren Module - Generiert Multi-Channel-Takedown-Reports
"""
import json
from typing import Dict, Any, List
from datetime import datetime


class TakedownVektoren:
    """
    Generiert automatisierte Takedown-Reports für verschiedene Kanäle
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.takedown_config = config.get('takedown', {})
        
        print(f"   ⚔️  Takedown-Vektoren initialisiert")
    
    def generate(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generiert Multi-Vector-Takedown-Report basierend auf der Analyse
        
        Args:
            analysis: Analyse-Ergebnisse von MayaLLM
            
        Returns:
            Takedown-Report mit allen Vektoren
        """
        threat_score = analysis.get('threat_score', 0)
        recommendation = analysis.get('recommendation', 'MONITOR')
        threat_type = analysis.get('threat_type', 'unknown')
        
        # Takedown-Vektoren basierend auf Threat-Score
        vectors = {
            "email_abuse": self._generate_email_report(analysis),
            "hosting_provider": self._generate_hosting_report(analysis),
            "registrar": self._generate_registrar_report(analysis),
            "browser_vendors": self._generate_browser_report(analysis),
            "search_engines": self._generate_search_engine_report(analysis),
            "social_platforms": self._generate_social_report(analysis)
        }
        
        # Priorisierte Aktionsliste
        action_items = self._prioritize_actions(vectors, threat_score, recommendation)
        
        # Zusammenfassung
        report = {
            "generated_at": datetime.now().isoformat(),
            "threat_score": threat_score,
            "recommendation": recommendation,
            "threat_type": threat_type,
            "vectors": vectors,
            "action_items": action_items,
            "priority": self._calculate_priority(threat_score, recommendation),
            "estimated_impact": self._estimate_impact(threat_score, threat_type)
        }
        
        return report
    
    def _generate_email_report(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generiert Abuse-Report für Email-Provider
        """
        url = analysis.get('url', 'unknown')
        domain = analysis.get('ingestion', {}).get('domain', 'unknown')
        
        return {
            "enabled": True,
            "template": "email_abuse",
            "recipients": [
                f"abuse@{domain}",
                "abuse@hosting-provider.com"
            ],
            "subject": f"URGENT: Phishing/Malware Report - {domain}",
            "body_template": self._email_body_template(analysis),
            "attachments": [
                "screenshot.png",
                "analysis_report.json"
            ],
            "priority": "HIGH" if analysis.get('threat_score', 0) >= 70 else "MEDIUM"
        }
    
    def _generate_hosting_report(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generiert Report für Hosting-Provider
        """
        url = analysis.get('url', 'unknown')
        domain = analysis.get('ingestion', {}).get('domain', 'unknown')
        
        return {
            "enabled": True,
            "template": "hosting_abuse",
            "target": "Hosting Provider Abuse Desk",
            "report_url": "https://abuseipdb.com/report",
            "data": {
                "url": url,
                "category": analysis.get('threat_type', 'phishing'),
                "evidence": self._extract_evidence(analysis)
            }
        }
    
    def _generate_registrar_report(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generiert Report für Domain-Registrar
        """
        domain = analysis.get('ingestion', {}).get('domain', 'unknown')
        root_domain = analysis.get('ingestion', {}).get('domain_analysis', {}).get('root_domain', domain)
        
        return {
            "enabled": True,
            "template": "registrar_abuse",
            "target": f"Registrar für {root_domain}",
            "report_url": "https://www.icann.org/compliance/complaint",
            "data": {
                "domain": root_domain,
                "violation_type": "Phishing/Malware Distribution",
                "evidence": self._extract_evidence(analysis)
            }
        }
    
    def _generate_browser_report(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generiert Report für Browser-Vendors (Google Safe Browsing, etc.)
        """
        url = analysis.get('url', 'unknown')
        
        return {
            "enabled": True,
            "template": "browser_vendor",
            "vendors": [
                {"name": "Google Safe Browsing", "url": "https://safebrowsing.google.com/safebrowsing/report_phish/"},
                {"name": "Microsoft SmartScreen", "url": "https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site"},
                {"name": "Mozilla Safe Browsing", "url": "https://safebrowsing.googleapis.com/"}
            ],
            "data": {
                "url": url,
                "threat_type": analysis.get('threat_type', 'phishing'),
                "threat_score": analysis.get('threat_score', 0)
            }
        }
    
    def _generate_search_engine_report(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generiert Report für Search-Engines zur De-Indexierung
        """
        url = analysis.get('url', 'unknown')
        
        return {
            "enabled": True,
            "template": "search_engine",
            "engines": [
                {"name": "Google", "url": "https://search.google.com/search-console/remove-outdated-content"},
                {"name": "Bing", "url": "https://www.bing.com/webmaster/tools/urlremoval"}
            ],
            "data": {
                "url": url,
                "reason": "Malicious content - Phishing/Malware"
            }
        }
    
    def _generate_social_report(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generiert Report für Social-Media-Plattformen (wenn URL dort geteilt wurde)
        """
        url = analysis.get('url', 'unknown')
        
        return {
            "enabled": False,  # Nur wenn Social-Sharing erkannt wird
            "template": "social_platform",
            "platforms": [
                {"name": "Twitter/X", "url": "https://help.twitter.com/forms/safety-and-security"},
                {"name": "Facebook", "url": "https://www.facebook.com/hacked"},
                {"name": "LinkedIn", "url": "https://www.linkedin.com/help/linkedin/answer/1359"}
            ],
            "data": {
                "url": url,
                "threat_type": analysis.get('threat_type', 'phishing')
            }
        }
    
    def _email_body_template(self, analysis: Dict[str, Any]) -> str:
        """
        Generiert Email-Body für Abuse-Reports
        """
        url = analysis.get('url', 'unknown')
        threat_score = analysis.get('threat_score', 0)
        threat_type = analysis.get('threat_type', 'phishing')
        reasoning = analysis.get('reasoning', 'No detailed reasoning provided')
        
        return f"""
Dear Abuse Team,

I am reporting a malicious URL that requires immediate attention.

URL: {url}
Threat Type: {threat_type}
Threat Score: {threat_score}/100
Detection Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

THREAT ANALYSIS:
{reasoning}

EVIDENCE:
{json.dumps(self._extract_evidence(analysis), indent=2)}

RECOMMENDED ACTIONS:
1. Immediate suspension of the URL/domain
2. Preservation of logs for investigation
3. Notification to affected parties if applicable

This is a URGENT security matter. Please acknowledge receipt and provide a timeline for action.

Best regards,
Agent Maya - Automated Cyber-Defense System
"""
    
    def _extract_evidence(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extrahiert Beweismittel aus der Analyse
        """
        ingestion = analysis.get('ingestion', {})
        risk_indicators = ingestion.get('risk_indicators', {})
        
        evidence = {
            "url": analysis.get('url', 'unknown'),
            "risk_indicators": {k: v for k, v in risk_indicators.items() if v},
            "threat_score": analysis.get('threat_score', 0),
            "llm_analysis": analysis.get('reasoning', '')[:500]
        }
        
        return evidence
    
    def _prioritize_actions(self, vectors: Dict, threat_score: int, recommendation: str) -> List[Dict[str, Any]]:
        """
        Erstellt priorisierte Aktionsliste basierend auf Threat-Level
        """
        actions = []
        
        if recommendation == "BLOCK":
            # Sofortige Maßnahmen
            actions.extend([
                {"priority": 1, "action": "Notify Hosting Provider", "vector": "hosting_provider", "deadline": "immediate"},
                {"priority": 2, "action": "Report to Google Safe Browsing", "vector": "browser_vendors", "deadline": "1 hour"},
                {"priority": 3, "action": "Email Abuse Report", "vector": "email_abuse", "deadline": "2 hours"}
            ])
            
            if threat_score >= 90:
                actions.append({"priority": 4, "action": "Contact Domain Registrar", "vector": "registrar", "deadline": "4 hours"})
        
        elif recommendation == "MONITOR":
            # Überwachungs-Maßnahmen
            actions.extend([
                {"priority": 1, "action": "Add to Watchlist", "vector": "monitoring", "deadline": "immediate"},
                {"priority": 2, "action": "Schedule Re-Analysis", "vector": "monitoring", "deadline": "24 hours"}
            ])
        
        return sorted(actions, key=lambda x: x['priority'])
    
    def _calculate_priority(self, threat_score: int, recommendation: str) -> str:
        """
        Berechnet Gesamtpriorität des Falls
        """
        if threat_score >= 80 or recommendation == "BLOCK":
            return "CRITICAL"
        elif threat_score >= 60:
            return "HIGH"
        elif threat_score >= 40:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _estimate_impact(self, threat_score: int, threat_type: str) -> Dict[str, Any]:
        """
        Schätzt potenziellen Impact des Threats
        """
        impact_levels = {
            "phishing": {"financial_risk": "HIGH", "data_risk": "CRITICAL", "reputation_risk": "MEDIUM"},
            "malware": {"financial_risk": "CRITICAL", "data_risk": "CRITICAL", "reputation_risk": "HIGH"},
            "scam": {"financial_risk": "MEDIUM", "data_risk": "LOW", "reputation_risk": "LOW"},
            "legitimate": {"financial_risk": "NONE", "data_risk": "NONE", "reputation_risk": "NONE"}
        }
        
        base_impact = impact_levels.get(threat_type, impact_levels["phishing"])
        
        # Anpassung basierend auf Score
        multiplier = threat_score / 100
        
        return {
            "financial_risk": base_impact["financial_risk"] if multiplier > 0.7 else "MEDIUM",
            "data_risk": base_impact["data_risk"] if multiplier > 0.7 else "MEDIUM",
            "reputation_risk": base_impact["reputation_risk"],
            "affected_users_estimate": "UNKNOWN"
        }
