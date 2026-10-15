# AI-Assisted Automated Attack Timeline Reconstruction and Digital Forensic Reporting Using Splunk

> **College Cybersecurity Capstone Project**  
> *Stage 1: Web Interface & Splunk Connector Foundation*

---

## 📌 Project Overview
This project enhances **Splunk Enterprise** with a specialized web application tailored for cybersecurity investigators and digital forensic analysts. It assists in analyzing security logs, reconstructing end-to-end multi-stage attack timelines, and generating defensible forensic reports.

In **Stage 1 (Current Version)**, we establish:
- A clean, modular **Flask** web application.
- A modern **cybersecurity SOC/SIEM dark theme** interface.
- A secure **environment-based configuration system** (no hardcoded passwords or API keys).
- A non-intrusive **Splunk REST API service module** ready to connect to Splunk Enterprise management port (`8089`).
- A clearly demarcated **Test/Demo Mode** for evaluating the interface with simulated events without ever misrepresenting simulated data as live Splunk data.

---

## 📁 Project Structure

```text
AI_Forensics_Splunk/
│
├── .env.example              # Template configuration with all environment variables
├── .env                      # Local environment configuration (IGNORED by git)
├── .gitignore                # Protects secrets, cache, and virtual environments
├── requirements.txt          # Python dependencies (Flask, python-dotenv, requests)
├── config.py                 # Central configuration loader with credential masking
├── run.py                    # Entry point to launch the local development server
│
├── app/
│   ├── __init__.py           # Flask application factory (create_app)
│   ├── routes/
│   │   ├── __init__.py       # Blueprint exports
│   │   ├── main.py           # Web routes (Dashboard, Settings, Health)
│   │   └── api.py            # JSON API routes (Splunk test-connection & status)
│   │
│   ├── services/
│   │   ├── __init__.py       # Service exports
│   │   └── splunk_service.py # Splunk Enterprise REST API client & test handlers
│   │
│   ├── static/
│   │   ├── css/
│   │   │   └── cyber_theme.css # Cybersecurity SOC dark theme styles
│   │   └── js/
│   │       └── dashboard.js    # Client-side connection ping and UI interactions
│   │
│   └── templates/
│       ├── base.html         # Base layout with persistent demo banner & navigation
│       ├── dashboard.html    # Forensic dashboard & attack timeline workspace
│       ├── settings.html     # Secure configuration viewer & setup instructions
│       └── 404.html          # Custom error page
│
└── README.md                 # Setup, configuration, and execution guide
```

---

## 💻 Prerequisites (Windows 11)
- **Python 3.10+** (You have Python 3.13 installed)
- **Splunk Enterprise** (Installed and running on Windows 11)
- **Splunk Universal Forwarder** (Configured to forward Windows security logs)
- **VS Code** (Recommended editor)

---

## 🚀 Setup & Installation

### Step 1: Open PowerShell or VS Code Terminal
Navigate to your project directory:
```powershell
cd "c:\Users\SHRUTI JAYAKRISHNAN\OneDrive\Documents\AI_Forensics_Splunk"
```

### Step 2: (Optional but Recommended) Create a Virtual Environment
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```
*(If PowerShell restricts script execution, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first).*

### Step 3: Install Required Dependencies
```powershell
pip install -r requirements.txt
```

---

## ⚙️ Configuration (`.env`)

The project uses a `.env` file to manage all credentials securely. **Never commit your `.env` file to GitHub or share it.**

A default `.env` file has already been created for you with safe defaults:
```env
# Flask Settings
FLASK_APP=run.py
FLASK_ENV=development
FLASK_DEBUG=True
FLASK_PORT=5000
FLASK_HOST=127.0.0.1
SECRET_KEY=cyber-forensics-dev-secret-key-stage1

# Operational Mode (True = Demo Mode with simulated logs; False = Live Splunk queries)
DEMO_MODE=True

# Splunk Enterprise REST API Settings
SPLUNK_HOST=localhost
SPLUNK_MANAGEMENT_PORT=8089
SPLUNK_SCHEME=https
SPLUNK_USERNAME=
SPLUNK_PASSWORD=
SPLUNK_BEARER_TOKEN=
SPLUNK_VERIFY_SSL=False
SPLUNK_TIMEOUT=10
```

> [!NOTE]
> **Splunk Ports Clarification**:
> - **Port 8000**: Splunk Web UI (for human browser viewing).
> - **Port 8089**: Splunk REST API Management Port (used by Python scripts and this web app).
> - **Port 9997**: Splunk Forwarder Receiver Port (used by Universal Forwarder to send logs).

---

## ▶️ How to Run the Application

Start the Flask server by running:
```powershell
python run.py
```

You will see terminal output similar to:
```text
======================================================================
 AI-Assisted Attack Timeline Reconstruction & Digital Forensic Reporting
======================================================================
 * Mode:            DEMO / TEST MODE
 * Splunk Host:     https://localhost:8089
 * Splunk Config:   Not Configured (Awaiting credentials in .env)
 * Dashboard URL:   http://127.0.0.1:5000
======================================================================
 * Serving Flask app 'app'
 * Debug mode: on
 * Running on http://127.0.0.1:5000
```

Open your browser and visit:
👉 **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

## 🧪 Testing the Splunk Connection

1. On the dashboard, click the **"⚡ Test Splunk Connection"** button.
2. If credentials are not yet entered in `.env`, the system will report:
   ```json
   {
     "connected": false,
     "status": "Not Configured",
     "message": "Splunk connection credentials are not configured in your .env file..."
   }
   ```
3. When you are ready to connect to your live Splunk:
   - Edit `.env` and fill in `SPLUNK_USERNAME` and `SPLUNK_PASSWORD` (e.g., your Splunk admin login).
   - Click the button again to see live ping latency and Splunk server details!

---

## 🧪 Stage 2: Windows Security Log Ingestion (4624, 4625, 4672, 4720)

Stage 2 introduces live query capability against Windows Security Event logs stored in Splunk Enterprise:

### Targeted Event IDs:
- **Event ID 4624**: Successful Logon (Authentication / Initial Access / Lateral Movement - MITRE T1078)
- **Event ID 4625**: Failed Logon Attempt (Credential Access / Brute Force - MITRE T1110)
- **Event ID 4672**: Special Privileges Assigned to New Logon (Privilege Escalation - MITRE T1078)
- **Event ID 4720**: User Account Created (Persistence / Account Manipulation - MITRE T1136)

### How to Query Real Splunk Logs:
1. Configure your `.env` file:
   ```env
   SPLUNK_HOST=localhost
   SPLUNK_MANAGEMENT_PORT=8089
   SPLUNK_USERNAME=your_splunk_admin_user
   SPLUNK_PASSWORD=your_splunk_admin_password
   DEMO_MODE=False
   ```
2. Start the application:
   ```powershell
   python run.py
   ```
3. On the Dashboard:
   - Click **"⚡ Test Splunk Connection"** &rarr; Verify the green **"Connected"** badge and latency.
   - Use the **Filter Console** to select an Event ID (e.g. `4624 - Successful Logon`) or `All Target Events`.
   - Select a Time Range (e.g. `Last 24 Hours` or `All Time`).
   - Click **"🔎 Fetch Logs from Splunk"**.
   - Inspect the normalized events in the table (Timestamp, User, Source IP, Target Machine, Logon Type, Narrative).
   - Click **"Inspect"** on any row to view the full raw event telemetry returned from Splunk.
   - Click **"Show Generated SPL"** to view the exact SPL query dispatched to Splunk.

### How to Verify Events are from Your Real Splunk Instance:
1. **Compare with Splunk Web**:
   - Open Splunk Web in your browser (`http://localhost:8000`).
   - Run the exact search shown in the **"Show Generated SPL"** box (e.g. `search index=* EventCode IN (4624, 4625, 4672, 4720) | sort - _time`).
   - Compare timestamps, usernames, and hostnames—they will match your Splunk search results 1:1.
2. **Generate a Live Test Security Event**:
   - On your Windows machine, open a Command Prompt and type:
     ```powershell
     net user SplunkTestUser CyberP@ssw0rd123! /add
     ```
     *(This generates an Event ID 4720 - User Account Created).*
   - Then in this web app, select **"Event 4720 - User Account Created"** and click **"Fetch Logs from Splunk"**.
   - You will see `SplunkTestUser` immediately appear in the table!
   - (Clean up after test: `net user SplunkTestUser /delete`).

---

## ⏳ Stage 3: Automated Attack Timeline Reconstruction

Stage 3 introduces deterministic forensic correlation that automatically processes raw security events and reconstructs the end-to-end multi-stage intrusion narrative:

### Key Features:
- **Temporal Causality**: Strictly orders events chronologically (`oldest → newest`) to map the true attack progression, with optional reverse view.
- **Multi-Entity Linkage**: Chains together Source IPs, User Accounts, and Computer Names across sessions.
- **Forensic Separation**: Distinguishes **Confirmed Forensic Evidence** (tamper-resistant facts from the log) from the **Correlation Hypothesis & Suspicion Level** (*Critical, High, Suspicious, Medium, Baseline*).
- **Attack Phase Mapping**:
  1. *Reconnaissance / Credential Access*: Password spraying & brute-force attempts (`4625`).
  2. *Initial Access / Breach*: Successful logon following failed attempts (`4624`).
  3. *Privilege Escalation*: Assignment of sensitive privileges (`4672`).
  4. *Lateral Movement*: Remote Desktop interactive sessions (`4624` Type 10).
  5. *Persistence*: Rogue local account creation (`4720`) and secondary backdoor logon.
- **Actionable Guidance**: Every reconstructed timeline step provides investigator remediation guidance.
- **Baseline Isolation**: Routine events (such as scheduled backup tasks) are categorized as *Routine Baseline Operations* to prevent false alarms.

---

## 📑 Stage 4: AI Summary & Digital Forensic Report Export

Stage 4 introduces automated incident summarization and defensible digital forensic documentation:

### Key Features:
- **Automated Incident Narrative**: Synthesizes the reconstructed timeline into a clear executive summary capturing the attack sequence, affected accounts, source IP addresses, and relevant Event IDs.
- **Defensible Evidence Integrity**: Strictly derived from ingested event records. Zero fabricated telemetry or hallucinated indicators.
- **Separation of Facts & Hypotheses**: Distinguishes verified log facts (tamper-evident timestamps, hosts, accounts) from correlation hypotheses.
- **Actionable Remediation Guidance**: Provides prioritized defensive recommendations (P1 Critical through P3 Medium) framed explicitly as investigative response guidance.
- **Defensible PDF Export**: Uses `ReportLab` to produce publication-grade digital forensic documentation featuring:
  - Document Title & Running Headers/Footers with dynamic **"Page X of Y"** numbering.
  - Prominent **Data Provenance Banner** (`[DEMO DATA - SIMULATED]` vs `LIVE PRODUCTION SPLUNK`).
  - Incident Metadata Matrix & Executive Verdict.
  - Chronological Timeline Table & Observed Correlation Chains.
  - Legal Forensic Disclaimer & Scope Limitations.
- **Transparent Methodology**: Operates via a deterministic, 100% on-premises Automated Rule-Based Forensic Analysis Engine requiring zero paid external AI API keys.

---

## 🛡️ Demo Mode vs Live Mode Policy
- **When `DEMO_MODE=True`**: The interface displays clearly tagged sample events (`[DEMO DATA - SIMULATED]`) demonstrating a multi-stage attack. A prominent amber banner is visible at all times.
- **When `DEMO_MODE=False`**: Simulated telemetry is completely disabled. The application requires a live Splunk connection and will only show genuine logs queried from your Splunk Enterprise index. **Zero fake data is ever generated in Live Mode.**

---

## 🗺️ Project Implementation Roadmap
- [x] **Stage 1**: Flask Web App, Cybersecurity UI, Environment Config, Splunk REST Client Stub, Demo Mode.
- [x] **Stage 2**: Live Splunk SPL Search Ingestion (Windows Security Logs: 4624, 4625, 4672, 4720, filters, normalizer).
- [x] **Stage 3**: Automated Attack Timeline Reconstruction Engine (Chronological Correlation & MITRE ATT&CK Mapping).
- [x] **Stage 4**: AI Summary Generation & Exportable Digital Forensic PDF Reports.

