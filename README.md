# AI-Powered Security Operations Center (SOC) & Threat Detection Platform

An enterprise-grade, mini-Security Operations Center (SOC) platform designed to monitor logs, detect anomalies using Machine Learning, visualize real-time network attacks, and execute automated incident response playbooks. 

This project showcases production-level architecture combining cybersecurity monitoring, asynchronous backend APIs, real-time data streaming, AI/ML pipeline integration, and automated infrastructure deployment.

---

## 🚀 Core & Advanced Features

### 🖥️ Monitoring & Ingestion
* **Multi-Host Log Collection:** Ingests system logs from Linux, Windows, Web Servers, and Applications.
* **Network IDS:** Real-time packet inspection and signature-based intrusion detection.
* **Infrastructure Metrics:** Continuous monitoring of host resource usage (CPU, Memory, Disk IO).

### 🧠 AI & Analytics Engine
* **Unsupervised Anomaly Detection:** Utilizes Scikit-learn (Isolation Forest/One-Class SVM) to detect zero-day anomalies and abnormal behavior without prior signatures.
* **Behavior Analytics:** Tracks user and process baselines to flag suspicious deviations.
* **AI Incident Summarizer:** Generates automated, human-readable breach summaries and impact reports.

### ⚡ Response & Alerting
* **Instant Notification Ingestion:** Routes high-severity alerts seamlessly to Slack, Telegram, and Email.
* **Automated Active Response:** Execution engine to automatically block rogue IPs, isolate container environments, or kill malicious processes upon detection.

---

## 🛠️ Tech Stack

* **Backend:** FastAPI (Python) - High-performance, asynchronous REST & WebSocket API.
* **Frontend/Dashboard:** Streamlit - Real-time, reactive security visualization dashboard.
* **Database:** PostgreSQL - Relational database optimized for structured logs and alert history.
* **AI/ML:** Scikit-learn, Pandas, NumPy - Data preprocessing and machine learning inference.
* **Network & Monitoring:** Scapy (Packet sniffing/analysis) & psutil (Host metrics).
* **Containerization & DevOps:** Docker & Docker Compose.

---

## 📁 System Architecture & Directory Structure

```text
soc_platform/
│
├── backend/
│   ├── api/             # FastAPI routes, routers, and WebSocket endpoints
│   ├── detection/       # Signature rules, IDS engine, and Scapy packet sniffer
│   ├── monitoring/      # System log ingestion pipelines and metric collections
│   ├── alerts/          # Alert routing integrations (Slack, Telegram, Email)
│   ├── ai_engine/       # Scikit-learn anomaly detection training and inference
│   ├── response/        # Automated incident response playbooks
│   ├── models/          # SQLAlchemy DB models and saved ML models
│   ├── logs/            # Internal application storage logs
│   ├── reports/         # AI-generated markdown/PDF security incidents
│   └── main.py          # FastAPI server entry point
│
├── dashboard/
│   └── app.py           # Streamlit application UI
├── agents/              # Lightweight python logging agents deployed on target machines
└── docker-compose.yml   # Multi-container local orchestration