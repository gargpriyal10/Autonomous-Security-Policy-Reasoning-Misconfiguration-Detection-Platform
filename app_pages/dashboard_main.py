from database.db import save_scan, get_scan_history

import streamlit as st
import json
import yaml
import csv
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from parser.policy_parser import normalize_policy
from core.policy_engine import analyze_policy
from graph.policy_graph import visualize_graph


st.set_page_config(layout="wide")


def run_dashboard():

    st.title("🔍 AI Cloud Security Interactive Dashboard")

    uploaded_files = st.file_uploader(
        "Upload Cloud Policy Files",
        type=["json", "yaml", "yml", "txt", "csv"],
        accept_multiple_files=True,
    )

    all_rules = []

    if uploaded_files:

        for file in uploaded_files:

            name = file.name.lower()

            if name.endswith(".json"):
                data = json.load(file)

                if "Statement" in data:
                    all_rules.extend(normalize_policy(data))

            elif name.endswith(".yaml") or name.endswith(".yml"):
                data = yaml.safe_load(file)

                if data and "Statement" in data:
                    all_rules.extend(normalize_policy(data))

            elif name.endswith(".txt"):
                text = file.read().decode("utf-8")

                if "*" in text:
                    all_rules.append(
                        {"Effect": "Allow", "Action": "*", "Resource": "*"}
                    )

            elif name.endswith(".csv"):
                decoded = file.read().decode("utf-8").splitlines()
                reader = csv.DictReader(decoded)

                for row in reader:
                    all_rules.append(
                        {
                            "Effect": row.get("Effect", "Allow"),
                            "Action": row.get("Action", "*"),
                            "Resource": row.get("Resource", "*"),
                        }
                    )

        if not all_rules:
            st.warning("No valid policies detected")
            return

        result = analyze_policy(all_rules)

        issues = result["issues"]
        risk_score = result["risk_score"]
        security_score = result["security_score"]
        ai_text = result["ai_text"]
        ai_summary = result["ai_summary"]
        recs = result["recommendations"]
        G = result["graph"]
        attack_paths = result["attack_paths"]

        # Risk level
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

        username = st.session_state["username"]

        save_scan(username, risk_score, risk_level, len(issues))

        st.success("Scan saved successfully")

        st.markdown(
            f"""
            ### 🧠 AI Risk Assessment
            <span style='color:{risk_color}; font-size:22px; font-weight:bold'>
            {risk_level}
            </span>
            """,
            unsafe_allow_html=True,
        )

        col1, col2, col3, col4 = st.columns(4)

        col1.metric("Risk Score", risk_score)
        col2.metric("Security Score", f"{security_score}/100")
        col3.metric("Issues Found", len(issues))
        col4.metric("Files Scanned", len(uploaded_files))

        st.progress(min(risk_score / 150, 1.0))
        st.divider()

        # Security score gauge
        fig = go.Figure(
            go.Indicator(
                mode="gauge+number",
                value=security_score,
                title={"text": "Cloud Security Score"},
                gauge={
                    "axis": {"range": [0, 100]},
                    "steps": [
                        {"range": [0, 40], "color": "red"},
                        {"range": [40, 70], "color": "orange"},
                        {"range": [70, 100], "color": "lightgreen"},
                    ],
                },
            )
        )

        st.plotly_chart(fig, use_container_width=True)

        tab1, tab2, tab3, tab4, tab5 = st.tabs(
            [
                "Risk Analysis",
                "AI Explanation",
                "Recommendations",
                "Attack Graph",
                "Service Analytics",
            ]
        )

        # ---------------- Risk Analysis ----------------
        with tab1:

            st.subheader("Detected Security Issues")

            if not issues:
                st.success("No major risks detected")

            else:
                df = pd.DataFrame(issues)

                if "service" not in df.columns:
                    df["service"] = "Unknown"

                df.insert(0, "Issue No.", range(1, len(df) + 1))

                st.dataframe(df, use_container_width=True, hide_index=True)

                risk_counts = df["risk"].value_counts().reset_index()
                risk_counts.columns = ["Risk Level", "Count"]

                pie = px.pie(
                    risk_counts,
                    names="Risk Level",
                    values="Count",
                    title="Risk Distribution",
                )

                st.plotly_chart(pie, use_container_width=True)

        # ---------------- AI Explanation ----------------
        with tab2:

            st.subheader("AI Security Explanation")
            st.info(ai_text)

            st.subheader("AI Security Summary")
            st.success(ai_summary)

        # ---------------- Recommendations ----------------
        with tab3:

            st.subheader("Recommended Fixes")

            for r in recs:
                st.write("✔", r)

        # ---------------- Attack Graph ----------------
        with tab4:

            st.subheader("Attack Path Visualization")

            visualize_graph(G)

            st.divider()

            if not attack_paths:
                st.success("No attack paths found")

            else:
                for i, path in enumerate(attack_paths, 1):
                    st.write(f"Attack Path {i}: {' → '.join(path)}")

        # ---------------- Service Analytics ----------------
        with tab5:

            st.subheader("Cloud Service Risk Analytics")

            if issues:

                df = pd.DataFrame(issues)

                if "service" not in df.columns:
                    st.info("No service information available.")

                else:

                    service_counts = df["service"].value_counts().reset_index()
                    service_counts.columns = ["Service", "Issues"]

                    st.dataframe(
                        service_counts, use_container_width=True, hide_index=True
                    )

                    fig = px.bar(
                        service_counts,
                        x="Issues",
                        y="Service",
                        orientation="h",
                        title="Security Issues by Cloud Service",
                        text="Issues",
                        color="Issues",
                    )

                    st.plotly_chart(fig, use_container_width=True)

                    # Attack surface chart
                    st.divider()
                    st.subheader("🚨 Cloud Attack Surface")

                    top_services = service_counts.sort_values(
                        by="Issues", ascending=False
                    ).head(5)

                    fig2 = px.bar(
                        top_services,
                        x="Issues",
                        y="Service",
                        orientation="h",
                        title="Top Risky Cloud Services",
                        text="Issues",
                        color_discrete_sequence=["#4CAF50"],
                    )

                    st.plotly_chart(fig2, use_container_width=True)

            else:
                st.info("No issues detected to analyze services.")

        # Download report
        report_data = {
            "Risk Score": risk_score,
            "Risk Level": risk_level,
            "Issues": len(issues),
            "AI Analysis": ai_text,
            "Recommendations": recs,
        }

        report_text = json.dumps(report_data, indent=4)

        st.download_button(
            label="Download Security Report",
            data=report_text,
            file_name="cloud_security_report.json",
            mime="application/json",
        )

    # ---------------- Scan History ----------------
    st.divider()
    st.subheader("Scan History Analytics")

    username = st.session_state["username"]
    history = get_scan_history(username)

    if history:

        history_df = pd.DataFrame(
            history,
            columns=["Risk Score", "Risk Level", "Issue Count", "Timestamp"],
        )

        st.dataframe(history_df, use_container_width=True, hide_index=True)

        line = px.line(
            history_df,
            x="Timestamp",
            y="Risk Score",
            title="Risk Score Trend",
            markers=True,
        )

        st.plotly_chart(line, use_container_width=True)

        colA, colB = st.columns(2)

        colA.metric("Average Risk Score", round(history_df["Risk Score"].mean(), 2))
        colB.metric("Highest Risk Score", history_df["Risk Score"].max())

    else:
        st.info("No previous scan history available.")
