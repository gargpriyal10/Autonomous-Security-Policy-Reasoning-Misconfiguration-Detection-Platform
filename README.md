# 🔐 Autonomous Security Policy Reasoning & Misconfiguration Detection Platform

## 📌 Overview

The **Autonomous Security Policy Reasoning Platform** is an intelligent cloud security analysis system designed to detect:

* IAM misconfigurations
* Privilege escalation risks
* Policy conflicts
* Over-permissive access controls

The platform analyzes uploaded cloud policy files and generates:

* 📊 Risk Scores
* 🤖 AI-based Security Insights
* 🔍 Misconfiguration Detection
* 🛡️ Security Recommendations
* 🧭 Attack Path Simulation
* 📄 Downloadable PDF Reports

It is implemented as a **full-stack Flask web application** with an interactive dashboard.

---

## 🚀 Key Features

### 🔍 Security Analysis

* Detects wildcard (`*`) permissions
* Identifies excessive IAM access
* Detects public exposure risks (S3, EC2, etc.)
* Finds Allow/Deny policy conflicts

### 🤖 AI-Powered Insights

* AI-based explanations of issues
* Smart security summaries
* Priority-based action recommendations

### 📊 Advanced Analytics

* Risk Score & Security Score calculation
* Service-wise risk analytics
* Scan history tracking

### 🧭 Attack Simulation

* Graph-based attack path generation
* Visualization of potential attack paths

### 📄 Reporting

* Downloadable **PDF Security Reports**
* Export results as **JSON**
* Structured issue & recommendation reporting

### 📂 Multi-format Support

* JSON
* YAML
* CSV
* TXT

---

## 🛠️ Technology Stack

### Backend

* Python
* Flask
* Flask-Limiter (Rate Limiting)

### Frontend

* HTML
* CSS
* JavaScript

### Data Processing

* Pandas

### Visualization

* Plotly

### Graph Analysis

* NetworkX

### Report Generation

* ReportLab

### Database

* SQLite

---

## 🏗️ Project Architecture

```
Frontend (HTML + JavaScript)
        ↓
Flask Backend API
        ↓
Policy Analysis Engine
        ↓
Graph Simulation Engine
        ↓
SQLite Database
```

---

## 📁 Project Structure

```
autonomous-security-policy-analyzer
│
├── app.py                # Flask backend server
│
├── core/                 # Policy analysis engine
├── detector/             # Misconfiguration detection
├── parser/               # Policy parsing
├── graph/                # Attack path simulation
├── database/             # SQLite DB
├── utils/                # Report generation & helpers
│
├── templates/            # HTML frontend
├── static/               # CSS & JS
├── data/                 # Sample policies
│
├── .env                  # Environment variables 
├── requirements.txt      # Dependencies
└── README.md
```

---

## ⚙️ Setup & Installation

### 1️⃣ Clone Repository

```
git clone https://github.com/gargpriyal10/Autonomous-Security-Policy-Reasoning-Misconfiguration-Detection-Platform.git
cd Autonomous-Security-Policy-Reasoning-Misconfiguration-Detection-Platform
```

---

### 2️⃣ Install Dependencies

```
pip install -r requirements.txt
```

---

### 3️⃣ Setup Environment Variables

Create a `.env` file:

```
SECRET_KEY=your_secret_key_here
```

---

### 4️⃣ Run Application

```
python app.py
```

Open in browser:

```
http://127.0.0.1:5000
```

---

## 🔐 Security Enhancements

* Rate Limiting using Flask-Limiter
* Secure HTTP Headers (CSP, XSS Protection, HSTS)
* Input Validation & File Sanitization
* Session-based Authentication
* Environment Variable Protection (.env)

---

## 📊 How It Works

1. User uploads a policy file
2. Policy is parsed & normalized
3. System detects:

   * Misconfigurations
   * Policy conflicts
   * Privilege escalation risks
4. Risk Score is calculated
5. Attack paths are simulated
6. AI generates insights
7. Results displayed on dashboard
8. User downloads PDF report

---

## 📌 Example Output

* Risk Score
* Security Score
* Detected Issues
* Recommendations
* Attack Paths
* Service Risk Analytics
* AI Explanation
* PDF Report

---

## 📈 Recent Improvements

* Improved risk scoring using weighted severity
* Duplicate issue removal
* Enhanced misconfiguration detection
* Better AI-based recommendations
* Improved PDF report formatting
* Service-level risk analytics enhancement
* Attack path simulation improvements

---

## 🔮 Future Scope

* Heatmap visualization
* Cloud integration (AWS, GCP, Azure)
* Automated remediation suggestions
* Multi-user dashboards
* Real-time monitoring

---

## 👨‍💻 Authors

* **Priyal Garg**
* **Shrishti Agarwal**

Computer Science Engineering Students

---

## 🔗 GitHub Repository

https://github.com/gargpriyal10/Autonomous-Security-Policy-Reasoning-Misconfiguration-Detection-Platform
