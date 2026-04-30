# 🔐 Autonomous Security Policy Analyzer

### AI-Powered Cloud Security Misconfiguration Detection & Risk Analysis Platform

---

## 📌 Overview

**Autonomous Security Policy Analyzer** is an intelligent cloud security analysis platform designed to detect, analyze, and mitigate security risks in cloud IAM policies.

It helps developers and organizations identify:

* 🔍 IAM Misconfigurations
* ⚠️ Privilege Escalation Risks
* 🔐 Over-Permissive Access
* 🔄 Policy Conflicts

The system processes uploaded policy files and generates **actionable security insights, attack simulations, and detailed reports**.

---

## 🎯 Objectives

* Automate cloud policy security analysis
* Detect critical vulnerabilities in IAM configurations
* Provide AI-based recommendations
* Simulate real-world attack paths
* Generate professional security reports

---

## 🚀 Features

### 🔍 Security Analysis

* Detects wildcard (`*`) permissions
* Identifies excessive IAM privileges
* Detects public exposure (S3, EC2, etc.)
* Finds Allow/Deny conflicts

### 🤖 AI-Based Insights

* Intelligent explanation of risks
* Priority-based recommendations
* Smart summarization of issues

### 📊 Risk Analytics

* Risk Score & Security Score calculation
* Service-wise risk analysis
* Historical scan tracking

### 🧭 Attack Path Simulation

* Graph-based attack modeling
* Visualization of possible exploitation paths

### 📄 Reporting

* Downloadable **PDF reports**
* Export results in **JSON format**
* Structured issue breakdown

### 📂 Multi-format Support

* JSON, YAML, CSV, TXT

---

## 🛠️ Tech Stack

| Category          | Technology            |
| ----------------- | --------------------- |
| Backend           | Python, Flask         |
| Frontend          | HTML, CSS, JavaScript |
| Data Processing   | Pandas                |
| Visualization     | Plotly                |
| Graph Engine      | NetworkX              |
| Report Generation | ReportLab             |
| Database          | SQLite                |

---

## 🏗️ System Architecture

```
User (Frontend UI)
        ↓
Flask API Server (app.py)
        ↓
Policy Parser → Misconfiguration Detector → Risk Analyzer
        ↓
Attack Graph Generator (NetworkX)
        ↓
SQLite Database
        ↓
Report Generator (PDF/JSON)
```

---

## 📁 Project Structure

```
autonomous-security-policy-analyzer/
│
├── app.py
├── core/
├── detector/
├── parser/
├── graph/
├── database/
├── utils/
│
├── templates/
├── static/
├── data/
│
├── .env
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation & Setup

### 1️⃣ Clone Repository

```
git clone https://github.com/gargpriyal10/Autonomous-Security-Policy-Reasoning-Misconfiguration-Detection-Platform.git
cd Autonomous-Security-Policy-Reasoning-Misconfiguration-Detection-Platform
```

### 2️⃣ Install Dependencies

```
pip install -r requirements.txt
```

### 3️⃣ Setup Environment Variables

Create a `.env` file:

```
SECRET_KEY=your_secret_key
```

### 4️⃣ Run Application

```
python app.py
```

Open:

```
http://127.0.0.1:5000
```

---

## 🔌 API Endpoints (Important for Evaluation)

| Endpoint   | Method | Description        |
| ---------- | ------ | ------------------ |
| `/upload`  | POST   | Upload policy file |
| `/analyze` | POST   | Analyze policy     |
| `/report`  | GET    | Download report    |
| `/history` | GET    | View past scans    |

---

## 🔐 Security Measures

* ✅ Rate Limiting (Flask-Limiter)
* ✅ Secure Headers (CSP, HSTS, XSS Protection)
* ✅ Input Validation
* ✅ File Sanitization
* ✅ Environment Variable Protection

---

## 📊 Workflow

1. User uploads policy file
2. Policy is parsed & normalized
3. Misconfigurations are detected
4. Risk score is calculated
5. Attack paths are generated
6. AI insights are produced
7. Results shown on dashboard
8. Report generated (PDF/JSON)

---

## 📌 Sample Output

* Risk Score
* Security Score
* Detected Issues
* Recommendations
* Attack Paths
* Service Risk Analysis
* AI Insights

---

## ⚠️ Limitations

* Currently supports static policy files only
* No real-time cloud integration
* Limited authentication support

---

## 🔮 Future Enhancements

* AWS / GCP / Azure integration
* Real-time monitoring
* Multi-user authentication system
* Automated remediation engine
* Advanced visualization dashboards

---

## 👨‍💻 Contributors

* Priyal Garg
* Shrishti Agarwal

---

## 📄 License

This project is developed for academic purposes.

---

## 🔗 Repository

GitHub:
https://github.com/gargpriyal10/Autonomous-Security-Policy-Reasoning-Misconfiguration-Detection-Platform

---
