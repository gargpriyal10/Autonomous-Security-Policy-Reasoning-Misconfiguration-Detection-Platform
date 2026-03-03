from database.db import init_db

init_db()
import streamlit as st

st.set_page_config(page_title="AI Security Platform", layout="wide")

# ---------- TOP HEADER ----------
st.markdown("""
<div style="background-color:#111827;padding:15px;border-radius:10px">
<h2 style="color:white;text-align:center;">AI Cloud Security Reasoning Platform</h2>
<p style="color:#9ca3af;text-align:center;">Autonomous Misconfiguration Detection & Attack Path Analysis</p>
</div>
""", unsafe_allow_html=True)

st.write("")

# ---------- SIDEBAR ----------
st.sidebar.title("Navigation")

page = st.sidebar.radio("", [
    "Dashboard",
    "Analyzer",
    "Project Details",
    "Developer"
])

# ---------- DASHBOARD HOME ----------
if page == "Dashboard":
    st.title("Security Overview")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.info("AI Risk Detection")

    with col2:
        st.info("Attack Path Simulation")

    with col3:
        st.info("Cloud Security Recommendations")

    st.write("")
    st.write("This platform analyzes cloud IAM policies and detects security risks using AI reasoning.")

# ---------- ANALYZER ----------
elif page == "Analyzer":
    from app_pages.dashboard_main import run_dashboard
    run_dashboard()

# ---------- PROJECT DETAILS ----------
elif page == "Project Details":
    st.title("Project Features")

    st.write("""
    • Cloud policy misconfiguration detection  
    • AI-based risk reasoning engine  
    • Risk scoring & threat analysis  
    • Attack path simulation  
    • Interactive security graph  
    • Intelligent recommendations  
    """)

# ---------- DEVELOPER ----------
elif page == "Developer":
    st.title("Developer Info")
    st.write("Department: AIML")
    st.write("Project: Autonomous Security Policy Reasoning Platform")
