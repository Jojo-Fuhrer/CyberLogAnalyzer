from detector import analyze_logs


def test_detects_repeated_failed_logins():
    logs = [
        "sshd: Failed password for admin from 198.51.100.23 port 2201 ssh2",
        "sshd: Failed password for admin from 198.51.100.23 port 2202 ssh2",
        "sshd: Failed password for admin from 198.51.100.23 port 2203 ssh2",
    ]

    alerts = analyze_logs(logs, threshold=3)

    assert len(alerts) == 1
    assert alerts.iloc[0]["type"] == "Échecs de connexion répétés"
    assert alerts.iloc[0]["severity"] == "HIGH"


def test_detects_system_error():
    logs = [
        "app: ERROR database connection failed",
    ]

    alerts = analyze_logs(logs)

    assert len(alerts) == 1
    assert alerts.iloc[0]["type"] == "Erreur système"
    assert alerts.iloc[0]["severity"] == "MEDIUM"


def test_no_alert_for_normal_log():
    logs = [
        "app: Normal service started",
    ]

    alerts = analyze_logs(logs)

    assert alerts.empty


def test_failed_logins_below_threshold():
    logs = [
        "sshd: Failed password for admin from 198.51.100.23 port 2201 ssh2",
        "sshd: Failed password for admin from 198.51.100.23 port 2202 ssh2",
    ]

    alerts = analyze_logs(logs, threshold=3)

    assert alerts.empty
