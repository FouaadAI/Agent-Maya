"""
Maya LLM Module - Ollama-basierte URL-Analyse mit RAG-Kontext
Nutzt shared.or_client.OllamaClient für Cloud-First Fallback.
"""
import json
import re
import sys
from pathlib import Path
from typing import Dict, Any, Optional

# shared-Modul finden (maya_system liegt unter Mark-XXXIX-OR/maya_system)
_REPO = Path(__file__).resolve().parent
_ROOT = _REPO.parent
sys.path.insert(0, str(_ROOT))
from shared.or_client import OllamaClient


class MayaLLM:
    """
    Verwendet Ollama-Modelle für tiefgehende URL-Analyse mit RAG-Kontext.
    Cloud-First via shared.or_client.OllamaClient (automatisch Cloud/Local).
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.ollama_config = config.get('ollama', {})
        self.models = self.ollama_config.get('models', {})
        self._client = OllamaClient()

        print(f"   🤖 Maya LLM initialisiert (Cloud-First via OllamaClient)")

    def _call_ollama(self, model: str, prompt: str, system: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Ruft Ollama über OllamaClient auf.
        Fallback: Cloud → Local (ohne :cloud Suffix).
        """
        # Versuch 1: Mit angegebenem Modell (Cloud wenn :cloud Suffix)
        content = self._client.chat(prompt, system=system or "", model=model,
                                    max_tokens=4096, temperature=0.3)
        if content and not content.startswith("[GOD BRAIN]"):
            return {"content": content, "model": model}

        # Versuch 2: Wenn Cloud-Modell, versuche lokalen Fallback
        if model.endswith(":cloud"):
            local_model = model.replace(":cloud", "")
            print(f"   🔄 Cloud fehlgeschlagen → versuche Local: {local_model}")
            content = self._client.chat(prompt, system=system or "", model=local_model,
                                        max_tokens=4096, temperature=0.3)
            if content and not content.startswith("[GOD BRAIN]"):
                return {"content": content, "model": local_model}

        print(f"   ⚠️  Ollama-Fehler für {model} (Cloud + Local)")
        return None

    def analyze(self, url_data: Dict[str, Any], knowledge_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Führt tiefgehende LLM-Analyse durch
        """
        model = self.models.get('analysis', 'qwen2.5-coder:cloud')

        system_prompt = """Du bist Agent Maya, ein Cyber-Defense-Experte für URL-Analyse.
Deine Aufgabe ist es, URLs auf Phishing, Malware und andere Bedrohungen zu analysieren.
Antworte präzise und faktenbasiert. Gib am Ende ein JSON-Objekt mit deiner Bewertung."""

        prompt = self._build_analysis_prompt(url_data, knowledge_context)
        response = self._call_ollama(model, prompt, system_prompt)

        if not response:
            return self._fallback_analysis(url_data)

        content = response['content']
        analysis = self._parse_llm_response(content, url_data)
        return analysis
    
    def _build_analysis_prompt(self, url_data: Dict[str, Any], knowledge_context: Dict[str, Any]) -> str:
        """
        Baut einen detaillierten Analyse-Prompt aus den URL-Daten
        """
        prompt_parts = [
            "Analysiere folgende URL auf Sicherheitsbedrohungen:\n",
            f"URL: {url_data.get('original_url', 'unknown')}",
            f"Domain: {url_data.get('domain', 'unknown')}",
            f"Schema: {url_data.get('scheme', 'unknown')}",
            "",
            "Risiko-Indikatoren:",
        ]
        
        # Risk Indicators auflisten
        indicators = url_data.get('risk_indicators', {})
        for key, value in indicators.items():
            if value:
                if isinstance(value, list) and value:
                    prompt_parts.append(f"  - {key}: {', '.join(value)}")
                else:
                    prompt_parts.append(f"  - {key}: JA")
        
        # Domain-Analyse
        domain_analysis = url_data.get('domain_analysis', {})
        prompt_parts.extend([
            "",
            "Domain-Informationen:",
            f"  - Root-Domain: {domain_analysis.get('root_domain', 'unknown')}",
            f"  - TLD: {domain_analysis.get('tld', 'unknown')}",
            f"  - Subdomains: {', '.join(domain_analysis.get('subdomains', [])) or 'keine'}",
        ])
        
        # Path-Analyse
        path_analysis = url_data.get('path_analysis', {})
        if path_analysis.get('suspicious_patterns'):
            prompt_parts.extend([
                "",
                "Verdächtige Pfad-Muster:",
            ])
            for pattern in path_analysis['suspicious_patterns']:
                prompt_parts.append(f"  - {pattern}")
        
        # RAG-Kontext hinzufügen
        similar_threats = knowledge_context.get('similar_threats', [])
        if similar_threats:
            prompt_parts.extend([
                "",
                "Ähnliche bekannte Threats aus der Knowledge-Base:",
            ])
            for i, threat in enumerate(similar_threats[:3], 1):
                doc = threat.get('document', 'unknown')
                metadata = threat.get('metadata', {})
                threat_type = metadata.get('threat_type', 'unknown')
                score = metadata.get('threat_score', 0)
                prompt_parts.append(f"  {i}. {doc} (Typ: {threat_type}, Score: {score}/100)")
        
        # Heuristischer Vorscore
        preliminary_score = url_data.get('preliminary_score', 0)
        prompt_parts.extend([
            "",
            f"Heuristischer Vorscore: {preliminary_score}/100",
            "",
            "DEINE AUFGABE:",
            "1. Analysiere alle Indikatoren und bewerte die Gesamtbedrohung",
            "2. Bestimme den finalen Threat-Score (0-100)",
            "3. Gib eine klare Empfehlung: BLOCK, MONITOR, oder ALLOW",
            "4. Begründe deine Entscheidung kurz",
            "",
            "ANTWORTFORMAT (am Ende deiner Antwort als JSON):",
            '{"threat_score": 0-100, "recommendation": "BLOCK|MONITOR|ALLOW", "threat_type": "phishing|malware|scam|legitimate", "confidence": 0-100, "reasoning": "kurze Begründung"}'
        ])
        
        return "\n".join(prompt_parts)
    
    def _parse_llm_response(self, content: str, url_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parst die LLM-Antwort und extrahiert das JSON-Ergebnis
        """
        # JSON am Ende der Antwort suchen
        json_match = re.search(r'\{[^{}]*"threat_score"[^{}]*\}', content, re.DOTALL)
        
        if json_match:
            try:
                result = json.loads(json_match.group())
                
                # Validierung
                result['threat_score'] = max(0, min(100, int(result.get('threat_score', 50))))
                result['confidence'] = max(0, min(100, int(result.get('confidence', 50))))
                result['recommendation'] = result.get('recommendation', 'MONITOR').upper()
                result['threat_type'] = result.get('threat_type', 'unknown')
                result['reasoning'] = result.get('reasoning', content[:200])
                result['llm_raw_response'] = content
                
                return result
                
            except json.JSONDecodeError:
                pass
        
        # Fallback bei Parse-Fehler
        return self._fallback_analysis(url_data, content)
    
    def _fallback_analysis(self, url_data: Dict[str, Any], raw_response: Optional[str] = None) -> Dict[str, Any]:
        """
        Fallback-Analyse bei LLM-Fehlern
        """
        preliminary_score = url_data.get('preliminary_score', 50)
        
        # Einfache Regel-basierte Empfehlung
        if preliminary_score >= 70:
            recommendation = "BLOCK"
        elif preliminary_score >= 40:
            recommendation = "MONITOR"
        else:
            recommendation = "ALLOW"
        
        return {
            "threat_score": preliminary_score,
            "recommendation": recommendation,
            "threat_type": "unknown",
            "confidence": 50,
            "reasoning": "LLM-Antwort konnte nicht geparst werden. Fallback auf heuristischen Score." + (f" Raw: {raw_response[:100]}" if raw_response else ""),
            "llm_raw_response": raw_response
        }
