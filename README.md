# 🔐 AI Cloud Security Policy Analyzer

Autonomous Security Policy Reasoning & Misconfiguration Detection Platform.

This project analyzes cloud IAM policies to detect **misconfigurations, excessive permissions, and potential attack paths** using a graph-based reasoning engine and provides results through an **interactive Streamlit dashboard**.

---

## 🚀 Features

* Detects IAM policy misconfigurations
* Identifies wildcard and overly permissive access
* Finds **policy conflicts**
* Generates **attack path graphs**
* Calculates **Cloud Security Score**
* Provides **AI-based security explanations**
* Interactive dashboard with analytics
* Downloadable security report

---

## 🧠 How It Works

1. Upload cloud policy files (JSON/YAML/TXT/CSV)
2. Policies are normalized
3. Security engine detects risks and conflicts
4. Attack graph is generated
5. Risk score and security score are calculated
6. Results are shown in the interactive dashboard

---

## 🛠 Tech Stack

* Python
* Streamlit
* Plotly
* NetworkX
* PyVis
* SQLite
* Pandas

---

## 📂 Supported Policy Formats

* JSON
* YAML / YML
* TXT
* CSV

---

## ⚙️ Run the Project

Clone the repository:

git clone https://github.com/gargpriyal10/Autonomous-Security-Policy-Reasoning-Misconfiguration-Detection-Platform.git

Go to the project directory:

cd Autonomous-Security-Policy-Reasoning-Misconfiguration-Detection-Platform

Install dependencies:

pip install -r requirements.txt

Run the dashboard:

streamlit run app/dashboard.py

---

## 👨‍💻 Author

Priyal Garg
Computer Science Engineering Student
