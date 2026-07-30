"""
URL Ingestion Module - Extrahiert und analysiert URL-Daten
"""
import re
import json
import hashlib
from typing import Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, ParseResult
import socket


class URLIngestion:
    """
    Extrahiert strukturelle und semantische Informationen aus URLs
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
    
    def process_url(self, url: str) -> Dict[str, Any]:
        """
        Verarbeitet eine URL und extrahiert alle relevanten Merkmale
        
        Args:
            url: Zu analysierende URL
            
        Returns:
            Dictionary mit extrahierten Merkmalen
        """
        try:
            parsed = urlparse(url)
        except Exception as e:
            return {
                "error": f"Ungültige URL: {str(e)}",
                "threat_score": 100
            }
        
        # Basis-Informationen
        data = {
            "original_url": url,
            "scheme": parsed.scheme,
            "domain": parsed.netloc,
            "path": parsed.path,
            "query_params": parse_qs(parsed.query),
            "fragment": parsed.fragment,
            "url_hash": self._hash_url(url)
        }
        
        # Risiko-Indikatoren extrahieren
        data["risk_indicators"] = self._extract_risk_indicators(parsed, url)
        
        # Domain-Analyse
        data["domain_analysis"] = self._analyze_domain(parsed.netloc)
        
        # Pfad-Analyse
        data["path_analysis"] = self._analyze_path(parsed.path)
        
        # Query-Parameter-Analyse
        data["query_analysis"] = self._analyze_query(parse_qs(parsed.query))
        
        # Erster Threat-Score (heuristisch)
        data["preliminary_score"] = self._calculate_preliminary_score(data)
        
        return data
    
    def _hash_url(self, url: str) -> str:
        """Generiert eindeutigen Hash für URL"""
        return hashlib.sha256(url.encode()).hexdigest()[:16]
    
    def _extract_risk_indicators(self, parsed: ParseResult, url: str) -> Dict[str, Any]:
        """
        Extrahiert bekannte Risiko-Indikatoren aus der URL
        """
        indicators = {
            "suspicious_tld": False,
            "ip_address": False,
            "homoglyph": False,
            "excessive_subdomain": False,
            "brand_impersonation": False,
            "suspicious_keywords": [],
            "encoding_detected": False,
            "shortener_detected": False
        }
        
        domain = parsed.netloc.lower()
        
        # Suspicious TLDs
        suspicious_tlds = ['.xyz', '.top', '.club', '.work', '.click', '.link', '.gq', '.ml', '.cf', '.tk', '.ga']
        indicators["suspicious_tld"] = any(domain.endswith(tld) for tld in suspicious_tlds)
        
        # IP-Adresse statt Domain
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        indicators["ip_address"] = bool(re.match(ip_pattern, domain))
        
        # Homoglyph-Erkennung (vereinfacht)
        cyrillic_chars = ['а', 'е', 'о', 'р', 'с', 'у', 'х']
        indicators["homoglyph"] = any(c in domain for c in cyrillic_chars)
        
        # Subdomain-Anzahl
        subdomain_count = domain.count('.')
        indicators["excessive_subdomain"] = subdomain_count > 3
        
        # Brand-Impersonation Keywords
        brand_keywords = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 'netflix', 'banking']
        indicators["brand_impersonation"] = any(kw in domain for kw in brand_keywords)
        
        # Suspicious Keywords im Pfad
        suspicious_path_keywords = ['login', 'verify', 'update', 'secure', 'account', 'suspend', 'confirm']
        url_lower = url.lower()
        indicators["suspicious_keywords"] = [kw for kw in suspicious_path_keywords if kw in url_lower]
        
        # URL-Encoding
        indicators["encoding_detected"] = '%' in url
        
        # URL-Shortener
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly']
        indicators["shortener_detected"] = any(s in domain for s in shorteners)
        
        return indicators
    
    def _analyze_domain(self, domain: str) -> Dict[str, Any]:
        """
        Analysiert die Domain-Struktur
        """
        parts = domain.split('.')
        
        analysis = {
            "subdomains": parts[:-2] if len(parts) > 2 else [],
            "root_domain": '.'.join(parts[-2:]),
            "tld": parts[-1] if parts else '',
            "domain_length": len(domain),
            "has_www": 'www' in parts
        }
        
        # Domain-Alter könnte hier über WHOIS abgefragt werden
        analysis["domain_age_days"] = None  # TODO: WHOIS-Lookup
        
        return analysis
    
    def _analyze_path(self, path: str) -> Dict[str, Any]:
        """
        Analysiert den URL-Pfad auf verdächtige Muster
        """
        path_analysis = {
            "depth": path.count('/'),
            "length": len(path),
            "has_file_extension": '.' in path.split('/')[-1] if path else False,
            "suspicious_patterns": []
        }
        
        # Suspicious Patterns
        patterns = [
            (r'login|signin|auth', 'Authentication bait'),
            (r'verify|validate|confirm', 'Verification scam'),
            (r'account|profile|user', 'Account targeting'),
            (r'suspend|locked|disabled', 'Urgency tactic'),
            (r'secure|update|restore', 'False security claim')
        ]
        
        for pattern, description in patterns:
            if re.search(pattern, path, re.IGNORECASE):
                path_analysis["suspicious_patterns"].append(description)
        
        return path_analysis
    
    def _analyze_query(self, query_params: Dict) -> Dict[str, Any]:
        """
        Analysiert Query-Parameter auf verdächtige Muster
        """
        analysis = {
            "param_count": len(query_params),
            "has_token": any('token' in k.lower() for k in query_params.keys()),
            "has_session": any('session' in k.lower() for k in query_params.keys()),
            "has_redirect": any('redirect' in k.lower() or 'url' in k.lower() for k in query_params.keys()),
            "suspicious_values": []
        }
        
        # Prüfe Parameter-Werte auf Base64-Encoding oder andere verdächtige Muster
        for key, values in query_params.items():
            for value in values:
                if len(value) > 50:  # Sehr lange Parameter
                    analysis["suspicious_values"].append(f"{key}: [long value]")
                if value.startswith('http'):  # URL in Parameter
                    analysis["suspicious_values"].append(f"{key}: [embedded URL]")
        
        return analysis
    
    def _calculate_preliminary_score(self, data: Dict[str, Any]) -> int:
        """
        Berechnet einen ersten heuristischen Threat-Score (0-100)
        """
        score = 0
        indicators = data["risk_indicators"]
        
        # Gewichtung der Indikatoren
        weights = {
            "suspicious_tld": 15,
            "ip_address": 20,
            "homoglyph": 25,
            "excessive_subdomain": 10,
            "brand_impersonation": 30,
            "encoding_detected": 5,
            "shortener_detected": 10
        }
        
        for indicator, weight in weights.items():
            if indicators.get(indicator, False):
                score += weight
        
        # Suspicious Keywords
        score += len(indicators.get("suspicious_keywords", [])) * 5
        
        # Path-Analyse
        if len(data["path_analysis"]["suspicious_patterns"]) > 0:
            score += len(data["path_analysis"]["suspicious_patterns"]) * 8
        
        return min(100, score)
