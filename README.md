# AI-Assisted Automated Attack Timeline Reconstruction and Digital Forensic Reporting

> **College Cybersecurity Capstone Project (React & TypeScript Edition)**  
> *100% Standalone Offline Forensic Architecture &bull; Zero External Splunk Connections or Paid Licenses Required*

---

## 📌 Project Overview
This application equips cybersecurity incident response (IR) investigators and digital forensic analysts with a specialized platform for analyzing security logs, reconstructing end-to-end multi-stage attack timelines, and generating court-defensible forensic documentation.

The platform operates in **100% Standalone Offline Mode**:
- **Zero Splunk License Required**: No Splunk Enterprise installation, forwarder receiver, or API credentials are needed.
- **High-Fidelity Simulated Telemetry**: Includes a multi-stage Windows Active Directory attack sequence (Events `4624`, `4625`, `4672`, and `4720`).
- **Multi-Cloud Ingestion**: Ingests and reconstructs AWS CloudTrail, Microsoft Entra ID / Azure AD, and GCP Audit logs.
- **Custom Log File Upload**: Drag and drop custom `.json` or `.csv` forensic logs directly into the browser.
- **Incident Email Alerting**: Automatically packages and dispatches incident alerts to investigators (`shruti.cvv240901@cvv.ac.in`).
- **Court-Defensible Forensic PDF Export**: Instantly exports publication-grade digital forensic reports.

---

## 🛡️ Core Capabilities

### 1. Forensic Security Operations Dashboard (Stage 1)
- Cybersecurity SOC/SIEM dark theme with high contrast indicators, glowing status pills, and responsive layout.
- Standalone in-memory telemetry ingestion with sub-2ms query processing.
- Zero external network dependencies.

### 2. Multi-Source Log Ingestion & Filtering (Stage 2)
- Targeted Windows Security Event IDs:
  - **Event ID 4624**: Successful Logon (Authentication / Initial Access / Lateral Movement - MITRE T1078)
  - **Event ID 4625**: Failed Logon Attempt (Credential Access / Brute Force - MITRE T1110)
  - **Event ID 4672**: Special Privileges Assigned to New Logon (Privilege Escalation - MITRE T1078)
  - **Event ID 4720**: User Account Created (Persistence / Account Manipulation - MITRE T1136)
- Cloud Integrations: AWS CloudTrail, Azure Entra ID, and GCP IAM/Storage audit logs.
- Interactive Filter Console: Filter by Event ID, relative time range (`-15m`, `-1h`, `-24h`, `-7d`, All Time), and record limits (25, 50, 100, 200).
- Raw Event Telemetry inspection modal with complete event records.

### 3. Automated Attack Timeline Reconstruction (Stage 3)
- **Temporal Causality**: Deterministic chronological ordering (`oldest → newest` or reverse) to map true attack progression.
- **Multi-Entity Linkage**: Chains together Source IPs (e.g. Kali VM `192.168.56.105`), User Accounts (`Administrator`, `backdoor_svc`), and Host machines (`CORP-DC01.corp.local`).
- **Forensic Separation**: Explicitly distinguishes **Confirmed Forensic Evidence (Log Truth)** from **Correlation Rationale & Threat Hypothesis** (*Critical, High, Suspicious, Baseline*).
- **Attack Phase Mapping**:
  1. *Reconnaissance / Credential Access*: Password spraying & brute force attempts (`4625`).
  2. *Initial Access / Breach*: Successful logon following failed attempts (`4624`).
  3. *Privilege Escalation*: Assignment of sensitive privileges (`4672` with `SeDebugPrivilege`).
  4. *Lateral Movement*: Remote Desktop interactive sessions (`4624` Type 10) and federated SSO pivots.
  5. *Persistence*: Rogue local account creation (`4720`) and secondary backdoor logon.
- **Actionable Guidance**: Every reconstructed step provides investigator response guidance checklists.
- **Correlation Chains**: Automatically groups events into campaigns (e.g., Credential Access Campaign, Account Manipulation & Persistence).

### 4. Automated Incident Summary, Alerts & PDF Reports (Stage 4)
- **Automated Incident Narrative**: Synthesizes the reconstructed timeline into a clear executive summary capturing the attack sequence, affected accounts, source IP addresses, and relevant Event IDs.
- **Defensible Evidence Integrity**: Strictly derived from ingested event records with transparent methodology.
- **Prioritized Recommendations**: Provides defensive remediation steps (P1 Critical through P3 Medium).
- **Email Incident Alerting**: Dispatches structured, tamper-evident HTML security alerts to investigator email addresses.
- **Publication-Grade PDF Export**: Generates and downloads a digital forensic PDF report featuring:
  - Header & "Page X of Y" two-pass numbering.
  - Prominent Data Provenance Banner (`[!] DATA INTEGRITY NOTICE — DEMO DATASET`).
  - Incident Metadata Matrix & Executive Verdict.
  - Chronological Timeline Table & Observed Correlation Chains.
  - Actionable Remediation Guidance table.
  - Legal Forensic Disclaimer & Scope Limitations.

---

## 🚀 Running the Application

```bash
# Install dependencies
npm install

# Start development server on port 3000
npm run dev

# Build production bundle
npm run build
```

Open your browser to `http://localhost:3000`.
