from database.db import save_scan , get_scan_history

from unittest import result

import streamlit as st
import json
import yaml
import csv
import pandas as pd
import plotly.express as px

from parser.policy_parser import normalize_policy
from core.policy_engine import analyze_policy
from graph.policy_graph import visualize_graph

from detector.misconfig_detector import (
    detect_misconfigurations,
    generate_ai_explanation,
    generate_recommendations,
    detect_policy_conflicts
)

def run_dashboard():

    st.title("🔍 AI Cloud Security Interactive Dashboard")

    uploaded_files = st.file_uploader(
        "Upload Cloud Policy Files",
        type=["json", "yaml", "yml", "txt", "csv"],
        accept_multiple_files=True
    )

    all_rules = []

    if uploaded_files:


        for file in uploaded_files:
            name = file.name.lower()

            # JSON
            if name.endswith(".json"):
                data = json.load(file)
                if "Statement" in data:
                    all_rules.extend(normalize_policy(data))

            # YAML
            elif name.endswith(".yaml") or name.endswith(".yml"):
                data = yaml.safe_load(file)
                if data and "Statement" in data:
                    all_rules.extend(normalize_policy(data))

            # TXT
            elif name.endswith(".txt"):
                text = file.read().decode("utf-8")
                if "*" in text:
                    all_rules.append({
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*"
                    })

            # CSV
            elif name.endswith(".csv"):
                decoded = file.read().decode("utf-8").splitlines()
                reader = csv.DictReader(decoded)
                for row in reader:
                    all_rules.append({
                        "Effect": row.get("Effect", "Allow"),
                        "Action": row.get("Action", "*"),
                        "Resource": row.get("Resource", "*")
                    })

        if not all_rules:
            st.warning("No valid policies detected")
            return

        result = analyze_policy(all_rules)

        issues = result["issues"]
        risk_score = result["risk_score"]
        ai_text = result["ai_text"]
        recs = result["recommendations"]
        G = result["graph"]
        attack_paths = result["attack_paths"]

        # -------- SMART RISK LEVEL MAPPING --------
        if risk_score >= 100:
            risk_level = "CRITICAL"
            risk_color = "red"
        elif risk_score >= 60:
            risk_level = "HIGH"
            risk_color = "orange"
        elif risk_score >= 30:
            risk_level = "MEDIUM"
            risk_color = "gold"
        elif risk_score > 0:
            risk_level = "LOW"
            risk_color = "green"
        else:
            risk_level = "SAFE"
            risk_color = "green"

        # -------- Save scan to DB --------
        username = st.session_state["username"]
        save_scan(username, risk_score, risk_level, len(issues))
        
        st.success("Scan saved successfully!")
        st.markdown(f"""
        ### 🧠 AI Risk Assessment:
        <span style='color:{risk_color}; font-size:22px; font-weight:bold'>
        {risk_level}
        </span>
        """, unsafe_allow_html=True)

        # -------- METRICS --------
        col1, col2, col3 = st.columns(3)

        col1.metric("🔴 Risk Score", risk_score)
        col2.metric("⚠ Issues Found", len(issues))
        col3.metric("📂 Files Scanned", len(uploaded_files))

        st.progress(min(risk_score / 150, 1.0))
        st.divider()

        # -------- TABS --------
        tab1, tab2, tab3, tab4 = st.tabs([
            "📊 Risk Analysis",
            "🤖 AI Explanation",
            "🛠 Recommendations",
            "🕸 Attack Graph"
        ])

        # -------- TAB 1 --------
        with tab1:
            st.subheader("Detected Security Issues")

            if not issues:
                st.success("No major risks detected")
            else:
                df = pd.DataFrame(issues)
                df.insert(0, "Issue No.", range(1, len(df) + 1))
                st.dataframe(df, use_container_width=True, hide_index=True)

                risk_counts = df["risk"].value_counts().reset_index()
                risk_counts.columns = ["Risk Level", "Count"]

                fig = px.pie(
                    risk_counts,
                    names="Risk Level",
                    values="Count",
                    title="Risk Distribution"
                )
                st.plotly_chart(fig, use_container_width=True)

        # -------- TAB 2 --------
        with tab2:
            st.subheader("AI Security Explanation")
            st.info(ai_text)

        # -------- TAB 3 --------
        with tab3:
            st.subheader("Recommended Fixes")
            for r in recs:
                st.write("✔", r)

        # -------- TAB 4 --------
        with tab4:
            st.subheader("Attack Path Visualization")

            visualize_graph(G)

            st.divider()
            st.subheader("🧠 Simulated Attack Paths")


            if not attack_paths:
                st.success("No attack paths found.")
            else:
                for i, path in enumerate(attack_paths, 1):
                    formatted_path = " → ".join(path)
                    st.write(f"**Attack Path {i}:** {formatted_path}")

        # -------- DOWNLOAD REPORT --------
        report_data = {
            "Risk Score": risk_score,
            "Risk Level": risk_level,
            "Total Issues": len(issues),
            "AI Analysis": ai_text,
            "Recommendations": recs
        }

        report_text = json.dumps(report_data, indent=4)

        st.download_button(
            label="📥 Download Security Report",
            data=report_text,
            file_name="cloud_security_report.json",
            mime="application/json"
        )

        # ---------- SCAN HISTORY SECTION ----------
    st.divider()
    st.subheader("📈 Scan History Analytics")

    history = get_scan_history("default_user")

    if history:

        history_df = pd.DataFrame(history, columns=[
            "Risk Score",
            "Risk Level",
            "Issue Count",
            "Timestamp"
        ])

        st.dataframe(history_df, use_container_width=True, hide_index=True)

        # Trend chart
        fig = px.line(
            history_df,
            x="Timestamp",
            y="Risk Score",
            title="Risk Score Trend Over Time",
            markers=True
        )

        st.plotly_chart(fig, use_container_width=True)

        # Additional Metrics
        avg_risk = history_df["Risk Score"].mean()
        max_risk = history_df["Risk Score"].max()

        colA, colB = st.columns(2)
        colA.metric("📊 Average Risk Score", round(avg_risk, 2))
        colB.metric("🚨 Highest Recorded Risk", max_risk)

    else:
        st.info("No previous scan history available.")