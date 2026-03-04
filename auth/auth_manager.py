import streamlit as st

# demo users
USERS = {
    "admin": "admin123",
    "student": "student123"
}


def login():

    st.title("🔐 Cloud Security Analyzer Login")

    st.write("Autonomous Security Policy Reasoning Platform")

    st.divider()

    username = st.text_input("Username")

    password = st.text_input(
        "Password",
        type="password"
    )

    col1, col2 = st.columns([1,1])

    login_btn = col1.button("Login")
    clear_btn = col2.button("Clear")

    if clear_btn:
        st.rerun()

    if login_btn:

        if username in USERS and USERS[username] == password:

            st.session_state["authenticated"] = True
            st.session_state["username"] = username

            st.success("Login successful")
            st.rerun()

        else:
            st.error("Invalid username or password")

    st.info("Demo login → admin / admin123")


def logout():

    st.session_state["authenticated"] = False
    st.session_state["username"] = None