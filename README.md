# Autonomous Security Policy Reasoning & Misconfiguration Detection Platform

## Overview

The **Autonomous Security Policy Reasoning Platform** is a cloud security analysis system designed to detect **IAM misconfigurations, privilege escalation risks, and policy conflicts** in cloud policies.

The platform analyzes uploaded policy files and generates **security insights, risk scores, recommendations, attack path simulations, and downloadable security reports**.

The system is implemented as a **full-stack web application using Flask**, allowing users to upload policies and interactively view security analytics through a dashboard.

---

## Features

* Detects **IAM misconfigurations** such as wildcard permissions and excessive access.
* Identifies **policy conflicts** between Allow and Deny rules.
* Detects **privilege escalation risks** in cloud IAM policies.
* Generates **AI-based explanations and security summaries**.
* Simulates **attack paths using graph modeling**.
* Provides **service-level risk analytics** for cloud resources.
* Maintains **scan history analytics** for security monitoring.
* Provides **interactive security dashboards and visualizations**.
* Export analysis results as **JSON**.
* Download **full security reports as PDF**.
* Supports **multiple policy formats**:

  * JSON
  * YAML
  * TXT
  * CSV

---

## Technology Stack

### Backend

* Python
* Flask

### Frontend

* HTML
* JavaScript

### Data Processing

* Pandas

### Visualization

* Plotly

### Graph Analysis

* NetworkX
* PyVis

### Report Generation

* ReportLab

---

## Project Architecture

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

## Project Structure

```
autonomous-security-policy-analyzer
│
├── app.py                # Flask backend server
│
├── core/                 # Policy analysis engine
├── detector/             # Misconfiguration detection logic
├── parser/               # Policy normalization and parsing
├── graph/                # Attack path simulation
├── database/             # Scan history storage
├── utils/                # Utility modules (report generation)
│
├── templates/            # HTML frontend pages
│   └── index.html
│
├── static/               # CSS and JavaScript files
│
├── data/                 # Sample policies
│
└── requirements.txt
```

---

## How It Works

1. User uploads a cloud policy file.
2. The system parses the policy and normalizes the rules.
3. The **security engine analyzes the policy** for:

   * misconfigurations
   * privilege escalation
   * policy conflicts
4. A **risk score and security posture score** are calculated.
5. Attack paths are simulated using graph analysis.
6. Results are displayed on the dashboard with charts and tables.
7. Users can export results as **JSON** or download a **PDF security report**.

---

## Example Output

The system generates:

* Risk Score
* Security Score
* Detected Security Issues
* Security Recommendations
* Attack Path Visualization
* Cloud Service Risk Analytics
* AI Security Explanation
* Downloadable **PDF Security Report**
* Exportable **JSON Analysis Report**

---

## Installation

Clone the repository:

```
git clone https://github.com/gargpriyal10/Autonomous-Security-Policy-Reasoning-Misconfiguration-Detection-Platform.git
```

Move to the project directory:

```
cd Autonomous-Security-Policy-Reasoning-Misconfiguration-Detection-Platform
```

Install dependencies:

```
pip install -r requirements.txt
```

---

## Running the Application

Start the Flask server:

```
python app.py
```

Open the application in your browser:

```
http://127.0.0.1:5000
```

Upload a policy file to begin analysis.

---

## Future Improvements

* Heatmap visualization for service risk exposure
* Automated remediation suggestions
* Integration with real cloud environments
* User authentication and multi-user support
* Real-time cloud policy monitoring

---

## Author

**Priyal Garg**
**Shrishti Agarwal**
Computer Science Engineering Student

---

## Repository

GitHub Repository:

```
https://github.com/gargpriyal10/Autonomous-Security-Policy-Reasoning-Misconfiguration-Detection-Platform
```
