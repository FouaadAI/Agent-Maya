"""
RAG Knowledge Base - ChromaDB-basierte Wissensspeicher für Threat Intelligence
"""
import json
import hashlib
from typing import Dict, Any, List, Optional
from pathlib import Path
import pandas as pd

class RAGKnowledgeBase:
    """
    Verwaltet Threat-Intelligence-Wissen mit ChromaDB für RAG-basierte Abfragen
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.chroma_config = config.get('chromadb', {})
        
        # ChromaDB initialisieren
        try:
            import chromadb  # type: ignore[import]
            from chromadb.config import Settings  # type: ignore[import]
            
            persist_dir = self.chroma_config.get('persist_directory', './knowledge_base/chroma_db')
            Path(persist_dir).mkdir(parents=True, exist_ok=True)
            
            self.client = chromadb.PersistentClient(path=persist_dir)
            self.collection_name = self.chroma_config.get('collection_name', 'threat_intelligence')
            
            self.collection = self.client.get_or_create_collection(
                name=self.collection_name,
                metadata={"description": "Threat Intelligence Knowledge Base"}
            )
            
            print(f"   📚 ChromaDB initialisiert: {persist_dir}")
            print(f"   📁 Collection: {self.collection_name}")
            print(f"   📊 Dokumente im Speicher: {self.collection.count()}")
            
        except ImportError:
            print("   ⚠️  ChromaDB nicht installiert. Installiere mit: pip install chromadb")
            self.client = None
            self.collection = None
        except Exception as e:
            print(f"   ⚠️  ChromaDB-Fehler: {str(e)}")
            self.client = None
            self.collection = None
    
    def query_threats(self, url_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Fragt die Knowledge-Base nach ähnlichen Threats ab
        
        Args:
            url_data: Daten von URLIngestion
            
        Returns:
            Dictionary mit relevanten Threat-Kontexten
        """
        if self.collection is None:
            return {"error": "Knowledge-Base nicht verfügbar", "similar_threats": []}
        
        try:
            # Query aus Domain-Merkmalen generieren
            domain = url_data.get('domain', '')
            risk_indicators = url_data.get('risk_indicators', {})
            
            # Query-Text aus Merkmalen zusammensetzen
            query_parts = [domain]
            
            if risk_indicators.get('brand_impersonation'):
                query_parts.append("brand impersonation phishing")
            if risk_indicators.get('suspicious_keywords'):
                query_parts.extend(risk_indicators['suspicious_keywords'])
            if risk_indicators.get('suspicious_tld'):
                query_parts.append("suspicious TLD")
            
            query_text = " ".join(query_parts)
            
            # ChromaDB Query (mit Embedding)
            # TODO: Embedding-Modell integrieren (nomic-embed-text)
            results = self.collection.query(
                query_texts=[query_text],
                n_results=min(5, self.collection.count()),
                include=["documents", "metadatas", "distances"]
            )
            
            similar_threats = []
            if results and results['documents']:
                for i, doc in enumerate(results['documents'][0]):
                    threat = {
                        "document": doc,
                        "metadata": results['metadatas'][0][i] if results['metadatas'] else {},
                        "distance": results['distances'][0][i] if results['distances'] else 0
                    }
                    similar_threats.append(threat)
            
            return {
                "query": query_text,
                "similar_threats": similar_threats,
                "threat_count": len(similar_threats)
            }
            
        except Exception as e:
            return {
                "error": f"Query-Fehler: {str(e)}",
                "similar_threats": []
            }
    
    def add_threat(self, url: str, threat_data: Dict[str, Any]):
        """
        Fügt einen neuen Threat zur Knowledge-Base hinzu
        
        Args:
            url: URL des Threats
            threat_data: Analyse-Daten des Threats
        """
        if self.collection is None:
            print("   ⚠️  Knowledge-Base nicht verfügbar")
            return
        
        try:
            # ID generieren
            threat_id = hashlib.sha256(url.encode()).hexdigest()[:16]
            
            # Dokument aus Threat-Daten generieren
            document = self._generate_threat_document(url, threat_data)
            
            # Metadata extrahieren
            metadata = {
                "url": url,
                "threat_score": threat_data.get('threat_score', 0),
                "threat_type": threat_data.get('threat_type', 'unknown'),
                "date_added": str(pd.Timestamp.now()) if 'pd' in globals() else "2026-05-18"
            }
            
            # Zu Collection hinzufügen
            self.collection.add(
                documents=[document],
                metadatas=[metadata],
                ids=[threat_id]
            )
            
            print(f"   ✅ Threat hinzugefügt: {url}")
            
        except Exception as e:
            print(f"   ⚠️  Fehler beim Hinzufügen: {str(e)}")
    
    def _generate_threat_document(self, url: str, threat_data: Dict[str, Any]) -> str:
        """
        Generiert ein durchsuchbares Dokument aus Threat-Daten
        """
        doc_parts = [
            f"URL: {url}",
            f"Threat Type: {threat_data.get('threat_type', 'unknown')}",
            f"Threat Score: {threat_data.get('threat_score', 0)}/100",
        ]
        
        # Domain-Merkmale
        if 'domain_analysis' in threat_data:
            domain_info = threat_data['domain_analysis']
            doc_parts.append(f"Domain: {domain_info.get('root_domain', 'unknown')}")
            doc_parts.append(f"TLD: {domain_info.get('tld', 'unknown')}")
        
        # Risk Indicators
        if 'risk_indicators' in threat_data:
            indicators = threat_data['risk_indicators']
            for key, value in indicators.items():
                if value:
                    doc_parts.append(f"Risk Indicator: {key}")
        
        # Takedown-Info
        if 'takedown' in threat_data:
            takedown = threat_data['takedown']
            if takedown.get('status'):
                doc_parts.append(f"Takedown Status: {takedown['status']}")
        
        return " | ".join(doc_parts)
    
    def ingest_external_data(self, source: str = "phishtank"):
        """
        Importiert externe Threat-Intelligence-Daten
        
        Args:
            source: Datenquelle ("phishtank", "google_safe_browsing", etc.)
        """
        if source == "phishtank":
            self._ingest_phishtank()
        elif source == "google_safe_browsing":
            self._ingest_google_safe_browsing()
        else:
            print(f"   ⚠️  Unbekannte Datenquelle: {source}")
    
    def _ingest_phishtank(self):
        """
        Lädt PhishTank-Daten (kostenlose API)
        """
        print("   📥 Lade PhishTank-Daten...")
        
        # PhishTank bietet CSV-Download unter:
        # http://data.phishtank.com/data/online-valid.csv
        
        try:
            import requests
            import pandas as pd
            from io import StringIO
            
            # PhishTank CSV herunterladen
            url = "http://data.phishtank.com/data/online-valid.csv"
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            # CSV parsen
            df = pd.read_csv(StringIO(response.text))
            
            # Top N Phishing-URLs extrahieren
            limit = min(100, len(df))
            print(f"   📊 Verarbeite {limit} Phishing-URLs...")
            
            for idx, row in df.head(limit).iterrows():
                url = row.get('url', '')
                if url:
                    threat_data = {
                        "threat_type": "phishing",
                        "threat_score": 95,
                        "source": "phishtank",
                        "target_brand": row.get('target', 'unknown')
                    }
                    self.add_threat(url, threat_data)
            
            print(f"   ✅ PhishTank-Import abgeschlossen: {limit} URLs")
            
        except ImportError:
            print("   ⚠️  pandas oder requests nicht installiert")
        except Exception as e:
            print(f"   ⚠️  PhishTank-Import fehlgeschlagen: {str(e)}")
    
    def _ingest_google_safe_browsing(self):
        """
        Lädt Google Safe Browsing-Daten (API-Key erforderlich)
        """
        print("   📥 Lade Google Safe Browsing-Daten...")
        
        api_key = self.config.get('threat_sources', {}).get('google_safe_browsing', {}).get('api_key_env')
        if not api_key:
            print("   ⚠️  Google Safe Browsing API-Key nicht konfiguriert")
            return
        
        # TODO: Google Safe Browsing API-Integration
        print("   ⚠️  Google Safe Browsing-Integration noch nicht implementiert")
