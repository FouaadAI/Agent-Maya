"""
Agent Maya - Hauptmodul für URL-Analyse und Takedown
"""
import sys
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Union

# shared-Module finden (maya_system liegt unter Mark-XXXIX-OR/maya_system)
_REPO = Path(__file__).resolve().parent
_ROOT = _REPO.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_REPO))
from shared.config_manager import get_api_key

# Maya-Module importieren
from ingestion import URLIngestion
from rag_knowledge import RAGKnowledgeBase
from maya_llm import MayaLLM
from takedown_vektoren import TakedownVektoren

class AgentMaya:
    """
    Hauptklasse für Agent Maya Cyber-Defense System
    
    Verwendung:
        maya = AgentMaya()
        report = maya.analyze_url("https://suspicious-site.com")
        print(report)
    """
    
    def __init__(self, config_path: Optional[Union[str, Path]] = None):
        """
        Initialisiert Agent Maya mit allen Komponenten
        
        Args:
            config_path: Pfad zur Konfigurationsdatei (optional)
        """
        if config_path is None:
            config_path = Path(__file__).parent / "config" / "config.json"
        elif isinstance(config_path, str):
            config_path = Path(config_path)
        
        self.config = self._load_config(config_path)
        
        # Komponenten initialisieren
        self.ingestion = URLIngestion(self.config)
        self.knowledge_base = RAGKnowledgeBase(self.config)
        self.llm = MayaLLM(self.config)
        self.takedown = TakedownVektoren(self.config)
        
        print("🛡️  Agent Maya initialisiert")
        print(f"   📊 Analyse-Modell: {self.config.get('ollama',{}).get('models',{}).get('analysis','qwen2.5-coder:cloud')}")
        print(f"   🧠 Reasoning-Modell: {self.config.get('ollama',{}).get('models',{}).get('reasoning','gemma4:cloud')}")
        print(f"   📚 Embedding: {self.config.get('ollama',{}).get('models',{}).get('embedding','nomic-embed-text')}")
    
    def _load_config(self, config_path: Path) -> Dict[str, Any]:
        """
        Lädt Konfiguration aus JSON-Datei.
        Shared.config_manager wird für API-Keys genutzt.
        """
        if not config_path.exists():
            print(f"⚠️  Konfiguration nicht gefunden: {config_path}")
            print("   Verwende Standard-Konfiguration")
            return {
                "ollama": {
                    "base_url": "http://localhost:11434",
                    "models": {
                        "analysis": "qwen2.5-coder:cloud",
                        "reasoning": "gemma4:cloud",
                        "embedding": "nomic-embed-text"
                    }
                },
                "chromadb": {
                    "persist_directory": "./knowledge_base/chroma_db",
                    "collection_name": "threat_intelligence"
                }
            }

        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analysiert eine URL und generiert Multi-Vector-Takedown-Report
        
        Args:
            url: Zu analysierende URL
            
        Returns:
            Dictionary mit Analyse-Ergebnissen und Takedown-Empfehlungen
        """
        print(f"\n🔍 Analysiere URL: {url}")
        
        # Phase 1: URL ingestion und preprocessing
        print("   📥 Phase 1: Ingestion...")
        url_data = self.ingestion.process_url(url)
        
        # Phase 2: RAG-basierte Wissensabfrage
        print("   📚 Phase 2: RAG Knowledge Lookup...")
        knowledge_context = self.knowledge_base.query_threats(url_data)
        
        # Phase 3: LLM-Analyse mit Kontext
        print("   🤖 Phase 3: LLM-Analyse...")
        analysis = self.llm.analyze(url_data, knowledge_context)
        
        # Phase 4: Multi-Vector-Takedown generieren
        print("   ⚔️  Phase 4: Takedown-Vektoren...")
        takedown_report = self.takedown.generate(analysis)
        
        # Zusammenführen
        report = {
            "url": url,
            "ingestion": url_data,
            "knowledge": knowledge_context,
            "analysis": analysis,
            "takedown": takedown_report,
            "threat_score": analysis.get('threat_score', 0),
            "recommendation": analysis.get('recommendation', 'MONITOR')
        }
        
        print(f"\n✅ Analyse abgeschlossen")
        print(f"   🎯 Threat Score: {report['threat_score']}/100")
        print(f"   📋 Empfehlung: {report['recommendation']}")
        
        return report
    
    def bulk_analyze(self, urls: List[str]) -> List[Dict[str, Any]]:
        """
        Analysiert mehrere URLs gleichzeitig
        
        Args:
            urls: Liste von URLs
            
        Returns:
            Liste von Analyse-Reports
        """
        print(f"\n🔍 Analysiere {len(urls)} URLs...")
        reports = []
        
        for i, url in enumerate(urls, 1):
            print(f"\n[{i}/{len(urls)}] {url}")
            report = self.analyze_url(url)
            reports.append(report)
        
        # Zusammenfassung
        high_threat = sum(1 for r in reports if r['threat_score'] >= 70)
        medium_threat = sum(1 for r in reports if 40 <= r['threat_score'] < 70)
        low_threat = len(reports) - high_threat - medium_threat
        
        print(f"\n📊 Zusammenfassung:")
        print(f"   🔴 Hochrisiko: {high_threat}")
        print(f"   🟡 Mittelrisiko: {medium_threat}")
        print(f"   🟢 Niedrigrisiko: {low_threat}")
        
        return reports
    
    def ingest_threat_data(self, source: str = "phishtank"):
        """
        Lädt externe Threat-Intelligence-Daten in die Knowledge-Base
        
        Args:
            source: Datenquelle ("phishtank", "google_safe_browsing", etc.)
        """
        print(f"\n📥 Lade Threat-Daten von {source}...")
        self.knowledge_base.ingest_external_data(source)


def main():
    """CLI-Einstiegspunkt"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Agent Maya Cyber-Defense System")
    parser.add_argument("url", nargs="?", help="Zu analysierende URL")
    parser.add_argument("--bulk", nargs="+", help="Mehrere URLs analysieren")
    parser.add_argument("--config", help="Pfad zur Konfigurationsdatei")
    parser.add_argument("--ingest", choices=["phishtank"], help="Threat-Daten laden")
    
    args = parser.parse_args()
    
    maya = AgentMaya(config_path=args.config)
    
    if args.ingest:
        maya.ingest_threat_data(args.ingest)
    elif args.bulk:
        maya.bulk_analyze(args.bulk)
    elif args.url:
        report = maya.analyze_url(args.url)
        print("\n" + "="*60)
        print("📋 VOLLSTÄNDIGER REPORT")
        print("="*60)
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
