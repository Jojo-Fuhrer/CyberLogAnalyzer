
from collections import Counter
from pathlib import Path
import re

import pandas as pd


FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password .* from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

SUSPICIOUS_KEYWORDS = {
    "ERROR": "Erreur système",
    "unauthorized": "Accès non autorisé",
    "malware": "Indicateur de malware",
    "privilege escalation": "Suspicion d'élévation de privilèges",
}


def analyze_logs(log_lines, threshold=3):
    """Analyse des lignes de logs et renvoie les alertes détectées."""
    alerts = []
    failed_ips = Counter()

    for line_number, line in enumerate(log_lines, start=1):
        match = FAILED_LOGIN_PATTERN.search(line)

        if match:
            failed_ips[match.group("ip")] += 1

        for keyword, description in SUSPICIOUS_KEYWORDS.items():
            if keyword.casefold() in line.casefold():
                alerts.append({
                    "line": line_number,
                    "severity": "HIGH" if keyword in {
                        "malware", "privilege escalation"
                    } else "MEDIUM",
                    "type": description,
                    "details": line.strip(),
                })
                break

    for ip, count in failed_ips.items():
        if count >= threshold:
            alerts.append({
                "line": None,
                "severity": "HIGH",
                "type": "Échecs de connexion répétés",
                "details": (
                    f"{ip} : {count} échecs de connexion "
                    f"(seuil : {threshold})"
                ),
            })

    return pd.DataFrame(
        alerts,
        columns=["line", "severity", "type", "details"],
    )


def main():
    sample_file = Path("sample_logs.txt")

    if not sample_file.exists():
        print("Fichier sample_logs.txt introuvable.")
        return

    lines = sample_file.read_text(
        encoding="utf-8"
    ).splitlines()

    alerts = analyze_logs(lines)

    print(f"Nombre de lignes analysées : {len(lines)}")
    print(f"Nombre d'alertes détectées : {len(alerts)}")

    if alerts.empty:
        print("Aucune alerte détectée.")
    else:
        print(alerts.to_string(index=False))


if __name__ == "__main__":
    main()
