# 🛡️ CyberLog Analyzer

**A lightweight Python-based security log analyzer with a Streamlit dashboard.**

CyberLog Analyzer is a beginner-friendly cybersecurity project designed to demonstrate basic security event detection and alert review. It analyzes log files, flags suspicious patterns, and displays results in an interactive dashboard.

## Features

- **Repeated login failure detection** — flags repeated SSH password failures from the same IP address.
- **Keyword-based detection** — identifies configured terms such as `ERROR`, `unauthorized`, `malware`, and `privilege escalation`.
- **Interactive dashboard** — review alerts by severity and alert type.
- **CSV export** — export filtered alerts for further investigation.
- **Automated tests** — validate core detection behavior with `pytest`.
- **Sample logs** — test the application with fictional security events.

## Tech Stack

- Python
- Pandas
- Streamlit
- pytest

## Getting Started

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd CyberLogAnalyzer
```

Replace `YOUR_GITHUB_REPOSITORY_URL` with your repository URL.

### 2. Create a virtual environment

**Windows:**

```powershell
python -m venv .venv
```

### 3. Install dependencies

**Windows:**

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 4. Run the dashboard

**Windows:**

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Open the local URL displayed in the terminal, usually `http://localhost:8501`.

### 5. Run automated tests

**Windows:**

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

## How It Works

1. Load a log file or use the included fictional sample logs.
2. Analyze each line using predefined detection rules.
3. Group repeated SSH login failures by source IP address.
4. Review alerts and their assigned severity.
5. Filter and export the results as CSV.

## Limitations

- Detection relies on simple patterns and keywords; it is not an AI-powered detection engine.
- An alert is an indicator that requires investigation, not proof of a successful attack.
- The current implementation does not provide real-time monitoring, automated blocking, or threat intelligence enrichment.
- The included sample logs are fictional and intended for demonstration only.

## Future Improvements

- Add more robust log parsing and validation.
- Support additional log formats.
- Add detection rules with configurable thresholds.
- Introduce structured logging and richer test coverage.
- Improve alert context and reporting.

## Disclaimer

This project is intended for educational and defensive cybersecurity purposes. Analyze only log files you are authorized to access.

## Author

Created as a hands-on cybersecurity learning project.
