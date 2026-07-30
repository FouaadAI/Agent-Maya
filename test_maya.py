"""
Test-Suite für Agent Maya - Validiert alle Komponenten
"""
import sys
import json
from pathlib import Path

# Maya-System importieren
sys.path.insert(0, str(Path(__file__).parent))

from main import AgentMaya
from ingestion import URLIngestion
from rag_knowledge import RAGKnowledgeBase
from maya_llm import MayaLLM
from takedown_vektoren import TakedownVektoren


def test_url_ingestion():
    """Testet URL-Ingestion-Modul"""
    print("\n" + "="*60)
    print("🧪 TEST: URL Ingestion")
    print("="*60)
    
    config = {
        "ollama": {"base_url": "http://localhost:11434"},
        "chromadb": {"persist_directory": "./test_db"}
    }
    
    ingestion = URLIngestion(config)
    
    # Test-URLs
    test_urls = [
        "https://www.google.com",  # Legitim
        "https://paypa1-secure-login.xyz/verify",  # Phishing (Homoglyph + suspicious TLD)
        "http://192.168.1.1/login?token=abc123",  # IP-Adresse + Auth-Bait
        "https://bit.ly/3xYz123",  # URL-Shortener
        "https://microsoft-account-verify.tk/update/secure"  # Brand + suspicious TLD
    ]
    
    results = []
    for url in test_urls:
        print(f"\n   Analysiere: {url}")
        result = ingestion.process_url(url)
        results.append({
            "url": url,
            "score": result.get('preliminary_score', 0),
            "domain": result.get('domain', 'unknown'),
            "risk_indicators": result.get('risk_indicators', {})
        })
        print(f"   → Score: {result.get('preliminary_score', 0)}/100")
        print(f"   → Domain: {result.get('domain', 'unknown')}")
    
    # Zusammenfassung
    print("\n📊 Zusammenfassung:")
    for r in results:
        score = r['score']
        level = "🔴 HOCH" if score >= 70 else "🟡 MITTEL" if score >= 40 else "🟢 NIEDRIG"
        print(f"   {level}: {r['url'][:50]}... (Score: {score})")
    
    return results


def test_rag_knowledge_base():
    """Testet RAG Knowledge Base"""
    print("\n" + "="*60)
    print("🧪 TEST: RAG Knowledge Base")
    print("="*60)
    
    config = {
        "ollama": {"base_url": "http://localhost:11434"},
        "chromadb": {
            "persist_directory": "./test_knowledge_db",
            "collection_name": "test_threats"
        }
    }
    
    kb = RAGKnowledgeBase(config)
    
    if kb.collection is None:
        print("   ⚠️  ChromaDB nicht verfügbar - Test übersprungen")
        return None
    
    # Test-Threats hinzufügen
    test_threats = [
        {
            "url": "https://fake-paypal.com/login",
            "threat_data": {
                "threat_type": "phishing",
                "threat_score": 95,
                "target_brand": "PayPal"
            }
        },
        {
            "url": "https://malware-download.xyz/update.exe",
            "threat_data": {
                "threat_type": "malware",
                "threat_score": 90,
                "malware_family": "Trojan"
            }
        }
    ]
    
    print("\n   Füge Test-Threats hinzu...")
    for threat in test_threats:
        kb.add_threat(threat['url'], threat['threat_data'])
    
    print(f"   📊 Dokumente im Speicher: {kb.collection.count()}")
    
    # Test-Query
    print("\n   Teste Query für 'PayPal phishing'...")
    url_data = {
        "domain": "paypa1-secure.com",
        "risk_indicators": {
            "brand_impersonation": True,
            "suspicious_tld": False
        }
    }
    
    results = kb.query_threats(url_data)
    print(f"   Gefundene ähnliche Threats: {results.get('threat_count', 0)}")
    
    if results.get('similar_threats'):
        for i, threat in enumerate(results['similar_threats'][:2], 1):
            doc = threat.get('document', '')[:100]
            print(f"   {i}. {doc}...")
    
    return results


def test_maya_llm():
    """Testet Maya LLM-Modul"""
    print("\n" + "="*60)
    print("🧪 TEST: Maya LLM (Ollama)")
    print("="*60)
    
    config = {
        "ollama": {
            "base_url": "http://localhost:11434",
            "models": {
                "analysis": "qwen2.5-coder:14b",
                "reasoning": "gemma4:9b"
            }
        }
    }
    
    llm = MayaLLM(config)
    
    # Test-Daten
    url_data = {
        "original_url": "https://paypa1-secure.xyz/login/verify",
        "domain": "paypa1-secure.xyz",
        "scheme": "https",
        "risk_indicators": {
            "brand_impersonation": True,
            "suspicious_tld": True,
            "homoglyph": True,
            "suspicious_keywords": ["login", "verify"]
        },
        "domain_analysis": {
            "root_domain": "paypa1-secure.xyz",
            "tld": "xyz",
            "subdomains": []
        },
        "preliminary_score": 75
    }
    
    knowledge_context = {
        "similar_threats": [
            {
                "document": "PayPal phishing campaign 2026-01",
                "metadata": {"threat_type": "phishing", "threat_score": 95}
            }
        ]
    }
    
    print("\n   Starte LLM-Analyse...")
    print(f"   Modell: {config['ollama']['models']['analysis']}")
    print(f"   URL: {url_data['original_url']}")
    
    analysis = llm.analyze(url_data, knowledge_context)
    
    print("\n   📊 LLM-Ergebnis:")
    print(f"      Threat Score: {analysis.get('threat_score', 0)}/100")
    print(f"      Empfehlung: {analysis.get('recommendation', 'UNKNOWN')}")
    print(f"      Threat Type: {analysis.get('threat_type', 'unknown')}")
    print(f"      Confidence: {analysis.get('confidence', 0)}%")
    print(f"\n      Reasoning: {analysis.get('reasoning', '')[:200]}...")
    
    return analysis


def test_takedown_vectors():
    """Testet Takedown-Vektoren-Modul"""
    print("\n" + "="*60)
    print("🧪 TEST: Takedown Vektoren")
    print("="*60)
    
    config = {
        "takedown": {
            "providers": {
                "email": {"enabled": True},
                "hosting": {"enabled": True}
            }
        }
    }
    
    takedown = TakedownVektoren(config)
    
    # Test-Analyse-Daten
    analysis = {
        "url": "https://paypa1-secure.xyz/login",
        "threat_score": 85,
        "recommendation": "BLOCK",
        "threat_type": "phishing",
        "reasoning": "Brand impersonation detected with suspicious TLD and homoglyph attack",
        "ingestion": {
            "domain": "paypa1-secure.xyz",
            "domain_analysis": {"root_domain": "paypa1-secure.xyz"},
            "risk_indicators": {
                "brand_impersonation": True,
                "suspicious_tld": True,
                "homoglyph": True
            }
        }
    }
    
    print("\n   Generiere Takedown-Report...")
    report = takedown.generate(analysis)
    
    print("\n   📊 Takedown-Report:")
    print(f"      Priority: {report.get('priority', 'UNKNOWN')}")
    print(f"      Vektoren: {len(report.get('vectors', {}))}")
    print(f"      Aktionen: {len(report.get('action_items', []))}")
    
    print("\n   Aktionsliste:")
    for action in report.get('action_items', [])[:3]:
        print(f"      {action['priority']}. {action['action']} ({action['deadline']})")
    
    # Email-Template Vorschau
    email_vector = report['vectors'].get('email_abuse', {})
    if email_vector.get('body_template'):
        print("\n   📧 Email-Template Vorschau:")
        print("   " + "-"*50)
        preview = email_vector['body_template'][:300]
        for line in preview.split('\n')[:6]:
            print(f"   {line}")
        print("   ...")
    
    return report


def test_full_maya_system():
    """Testet das komplette Agent Maya System"""
    print("\n" + "="*60)
    print("🧪 TEST: Vollständiges Agent Maya System")
    print("="*60)
    
    # Agent Maya initialisieren
    print("\n🛡️  Initialisiere Agent Maya...")
    maya = AgentMaya()
    
    # Test-URL analysieren
    test_url = "https://www.google.com"  # Legitime URL als Test
    print(f"\n🔍 Analysiere Test-URL: {test_url}")
    
    report = maya.analyze_url(test_url)
    
    print("\n📊 Vollständiger Report:")
    print(f"   URL: {report['url']}")
    print(f"   Threat Score: {report['threat_score']}/100")
    print(f"   Empfehlung: {report['recommendation']}")
    
    # Report speichern
    output_file = "test_maya_report.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    print(f"\n   ✅ Report gespeichert: {output_file}")
    
    return report


def main():
    """Haupt-Testroutine"""
    print("\n" + "="*60)
    print("🛡️  AGENT MAYA TEST-SUITE")
    print("="*60)
    
    tests = [
        ("URL Ingestion", test_url_ingestion),
        ("RAG Knowledge Base", test_rag_knowledge_base),
        ("Maya LLM", test_maya_llm),
        ("Takedown Vektoren", test_takedown_vectors),
        ("Vollständiges System", test_full_maya_system)
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results[test_name] = {"status": "PASSED", "result": result}
            print(f"\n✅ {test_name}: PASSED")
        except Exception as e:
            print(f"\n❌ {test_name}: FAILED - {str(e)}")
            results[test_name] = {"status": "FAILED", "error": str(e)}
            import traceback
            traceback.print_exc()
    
    # Zusammenfassung
    print("\n" + "="*60)
    print("📊 TEST-ZUSAMMENFASSUNG")
    print("="*60)
    
    passed = sum(1 for r in results.values() if r['status'] == 'PASSED')
    failed = sum(1 for r in results.values() if r['status'] == 'FAILED')
    
    print(f"\n   Bestanden: {passed}/{len(tests)}")
    print(f"   Fehlgeschlagen: {failed}/{len(tests)}")
    
    for test_name, result in results.items():
        status = "✅" if result['status'] == 'PASSED' else "❌"
        print(f"   {status} {test_name}: {result['status']}")
    
    # Gesamtergebnis
    if failed == 0:
        print("\n🎉 ALLE TESTS ERFOLGREICH!")
        return 0
    else:
        print(f"\n⚠️  {failed} TEST(S) FEHLGESCHLAGEN")
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
