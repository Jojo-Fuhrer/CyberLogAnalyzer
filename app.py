
from pathlib import Path

import pandas as pd
import streamlit as st

from detector import analyze_logs


st.set_page_config(
    page_title="CyberLog Analyzer | SOC",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ CyberLog Analyzer")
st.caption("Security Operations Center · Log Analysis & Threat Detection")

with st.sidebar:
    st.header("Configuration")
    threshold = st.slider(
        "Seuil d'échecs de connexion",
        min_value=2,
        max_value=10,
        value=3,
    )
    st.info(
        "Analyse locale de journaux. "
        "Les alertes sont des indicateurs à examiner, "
        "pas des preuves définitives d'attaque."
    )

uploaded_file = st.file_uploader(
    "Importer un fichier de logs (.txt ou .log)",
    type=["txt", "log"],
)

if uploaded_file is not None:
    try:
        content = uploaded_file.getvalue().decode("utf-8")
        lines = content.splitlines()
    except UnicodeDecodeError:
        st.error("Le fichier doit être encodé en UTF-8.")
        st.stop()
else:
    sample_path = Path("sample_logs.txt")
    if sample_path.exists():
        lines = sample_path.read_text(
            encoding="utf-8"
        ).splitlines()
        st.info("Démonstration avec les logs fictifs du projet.")
    else:
        lines = []
        st.warning("Importe un fichier de logs pour commencer.")

alerts = analyze_logs(lines, threshold=threshold)

high_count = int((alerts["severity"] == "HIGH").sum())
medium_count = int((alerts["severity"] == "MEDIUM").sum())

col1, col2, col3 = st.columns(3)

col1.metric("Lignes analysées", len(lines))
col2.metric("Alertes détectées", len(alerts))
col3.metric("Alertes prioritaires", high_count)

st.divider()
st.subheader("Vue des alertes")

if alerts.empty:
    st.success("Aucune alerte détectée avec les règles actuelles.")
else:
    f1, f2 = st.columns(2)

    with f1:
        severity_filter = st.multiselect(
            "Filtrer par priorité",
            options=["HIGH", "MEDIUM"],
            default=["HIGH", "MEDIUM"],
        )

    with f2:
        type_options = sorted(alerts["type"].unique().tolist())
        type_filter = st.multiselect(
            "Filtrer par type",
            options=type_options,
            default=type_options,
        )

    filtered = alerts[
        alerts["severity"].isin(severity_filter)
        & alerts["type"].isin(type_filter)
    ]

    st.dataframe(
        filtered,
        use_container_width=True,
        hide_index=True,
    )

    st.download_button(
        "📥 Exporter les alertes en CSV",
        data=filtered.to_csv(index=False).encode("utf-8"),
        file_name="cyberlog_alerts.csv",
        mime="text/csv",
    )

with st.expander("Consulter les journaux analysés"):
    st.code("\n".join(lines) if lines else "Aucun journal chargé.")
