import streamlit as st
from auth.auth_manager import login
from app_pages.dashboard_main import run_dashboard
from database.db import init_db

# Initialize database
init_db()

# Authentication state
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

# Show login page if not authenticated
if not st.session_state["authenticated"]:
    login()
else:
    run_dashboard()