"""
God Brain Action: analyze_url

Führt eine Cyber-Defense-Analyse via Agent Maya durch.
Wird vom God Brain Core aufgerufen, wenn der Benutzer
eine URL auf Bedrohungen prüfen möchte.
"""
import json
import sys
from pathlib import Path
from typing import Dict, Any

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from maya_system.main import AgentMaya


def run(url: str, verbose: bool = False) -> Dict[str, Any]:
    """
    Analysiert eine URL mit Agent Maya.

    Args:
        url: Zu analysierende URL
        verbose: Vollständigen Report ausgeben

    Returns:
        Dictionary mit threat_score, recommendation und takedown-Info
    """
    if not url.startswith(("http://", "https://")):
        return {"error": "Ungültige URL", "url": url}

    maya = AgentMaya()
    report = maya.analyze_url(url)

    summary = {
        "url": url,
        "threat_score": report.get("threat_score", 0),
        "recommendation": report.get("recommendation", "MONITOR"),
        "takedown_channels": report.get("takedown", {}).get("channels", []),
        "success": True
    }

    if verbose:
        summary["full_report"] = report

    return summary


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Agent Maya URL-Analyse")
    parser.add_argument("url", help="Zu analysierende URL")
    parser.add_argument("--verbose", action="store_true", help="Vollständiger Report")
    args = parser.parse_args()
    print(json.dumps(run(args.url, args.verbose), indent=2, ensure_ascii=False))
