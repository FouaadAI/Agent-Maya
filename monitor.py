"""
Agent Maya Monitor - Überwacht URLs kontinuierlich
"""
import json
import time
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from pathlib import Path


class MayaMonitor:
    """
    Kontinuierliche Überwachung von URLs mit automatischer Re-Analyse
    """
    
    def __init__(self, maya, config: Optional[Dict[str, Any]] = None):
        """
        Initialisiert den Monitor
        
        Args:
            maya: AgentMaya-Instanz
            config: Konfiguration (optional)
        """
        self.maya = maya
        self.config = config or {}
        
        self.watchlist = []
        self.history = []
        self.alerts = []
        
        # Monitor-Config
        self.reanalysis_interval = self.config.get('reanalysis_hours', 24)
        self.alert_threshold = self.config.get('alert_threshold', 70)
        
        print(f"   👁️  Maya Monitor initialisiert")
        print(f"      Re-Analyse: alle {self.reanalysis_interval}h")
        print(f"      Alert-Threshold: {self.alert_threshold}/100")
    
    def add_to_watchlist(self, url: str, metadata: Optional[Dict[str, Any]] = None):
        """
        Fügt URL zur Überwachungsliste hinzu
        
        Args:
            url: Zu überwachende URL
            metadata: Zusätzliche Metadaten
        """
        entry = {
            "url": url,
            "added_at": datetime.now().isoformat(),
            "last_analysis": None,
            "next_analysis": datetime.now() + timedelta(hours=self.reanalysis_interval),
            "metadata": metadata or {},
            "status": "pending"
        }
        
        self.watchlist.append(entry)
        print(f"   ✅ URL zur Watchlist hinzugefügt: {url}")
    
    def remove_from_watchlist(self, url: str):
        """
        Entfernt URL aus der Überwachungsliste
        """
        self.watchlist = [w for w in self.watchlist if w['url'] != url]
        print(f"   ✅ URL von Watchlist entfernt: {url}")
    
    def run_monitoring_cycle(self):
        """
        Führt einen Überwachungszyklus durch
        """
        print(f"\n🔄 Starte Monitoring-Zyklus...")
        print(f"   Watchlist: {len(self.watchlist)} URLs")
        
        now = datetime.now()
        analyses_done = 0
        
        for entry in self.watchlist:
            # Prüfen ob Re-Analyse fällig
            next_analysis = datetime.fromisoformat(entry['next_analysis'])
            
            if now >= next_analysis or entry['status'] == 'pending':
                print(f"\n   🔍 Analysiere: {entry['url']}")
                
                # Analyse durchführen
                report = self.maya.analyze_url(entry['url'])
                
                # History updaten
                entry['last_analysis'] = now.isoformat()
                entry['next_analysis'] = (now + timedelta(hours=self.reanalysis_interval)).isoformat()
                entry['status'] = 'active'
                
                # Report speichern
                self.history.append({
                    "timestamp": now.isoformat(),
                    "url": entry['url'],
                    "report": report
                })
                
                # Alert prüfen
                if report['threat_score'] >= self.alert_threshold:
                    self._trigger_alert(entry, report)
                
                analyses_done += 1
        
        print(f"\n✅ Monitoring-Zyklus abgeschlossen: {analyses_done} Analysen")
    
    def _trigger_alert(self, watchlist_entry: Dict[str, Any], report: Dict[str, Any]):
        """
        Löst Alert bei hochriskanten URLs aus
        """
        alert = {
            "id": len(self.alerts) + 1,
            "timestamp": datetime.now().isoformat(),
            "url": watchlist_entry['url'],
            "threat_score": report['threat_score'],
            "recommendation": report['recommendation'],
            "threat_type": report.get('threat_type', 'unknown'),
            "severity": "CRITICAL" if report['threat_score'] >= 90 else "HIGH",
            "action_required": report['recommendation'] == "BLOCK"
        }
        
        self.alerts.append(alert)
        
        print(f"\n   🚨 ALERT #{alert['id']}")
        print(f"      URL: {alert['url']}")
        print(f"      Threat Score: {alert['threat_score']}/100")
        print(f"      Empfehlung: {alert['recommendation']}")
        print(f"      Schweregrad: {alert['severity']}")
        
        # TODO: Alert an externe Systeme senden (Email, Slack, etc.)
    
    def get_status_report(self) -> Dict[str, Any]:
        """
        Generiert Status-Report des Monitors
        """
        active_urls = len([w for w in self.watchlist if w['status'] == 'active'])
        pending_urls = len([w for w in self.watchlist if w['status'] == 'pending'])
        
        high_threats = len([h for h in self.history if h['report'].get('threat_score', 0) >= 70])
        
        return {
            "generated_at": datetime.now().isoformat(),
            "watchlist": {
                "total": len(self.watchlist),
                "active": active_urls,
                "pending": pending_urls
            },
            "history": {
                "total_analyses": len(self.history),
                "high_threat_detections": high_threats
            },
            "alerts": {
                "total": len(self.alerts),
                "critical": len([a for a in self.alerts if a['severity'] == 'CRITICAL']),
                "high": len([a for a in self.alerts if a['severity'] == 'HIGH'])
            }
        }
    
    def export_watchlist(self, filepath: str):
        """
        Exportiert Watchlist als JSON-Datei
        """
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump({
                "exported_at": datetime.now().isoformat(),
                "watchlist": self.watchlist,
                "alerts": self.alerts
            }, f, indent=2, ensure_ascii=False)
        
        print(f"   ✅ Watchlist exportiert: {filepath}")
    
    def import_watchlist(self, filepath: str):
        """
        Importiert Watchlist aus JSON-Datei
        """
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        imported = data.get('watchlist', [])
        self.watchlist.extend(imported)
        
        print(f"   ✅ {len(imported)} URLs aus Watchlist importiert")


def start_monitoring_loop(maya, interval_minutes: int = 60):
    """
    Startet kontinuierlichen Monitoring-Loop im Hintergrund
    
    Args:
        maya: AgentMaya-Instanz
        interval_minutes: Intervall zwischen Zyklen
    """
    import threading
    
    monitor = MayaMonitor(maya)
    
    def monitoring_loop():
        print(f"\n👁️  Maya Monitoring gestartet (Intervall: {interval_minutes} Min)")
        
        while True:
            try:
                monitor.run_monitoring_cycle()
                time.sleep(interval_minutes * 60)
            except KeyboardInterrupt:
                print("\n   ⏹️  Monitoring gestoppt")
                break
            except Exception as e:
                print(f"   ⚠️  Monitoring-Fehler: {str(e)}")
                time.sleep(60)  # 1 Min warten vor Retry
    
    # Hintergrund-Thread starten
    thread = threading.Thread(target=monitoring_loop, daemon=True)
    thread.start()
    
    return monitor
