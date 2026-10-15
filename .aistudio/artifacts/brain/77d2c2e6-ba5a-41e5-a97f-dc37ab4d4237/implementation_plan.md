# Standalone Digital Forensic & Attack Reconstruction Platform (Semester 5 Mini-Project Viva Edition)

Transform the platform into an offline-first, standalone cybersecurity forensic investigation suite with zero external Splunk licensing dependencies, complete custom CSV/JSON log upload with sample test datasets, an interactive in-browser viva presentation deck, and an evaluator demonstration cheat-sheet.

## User Review & Critical Decisions

> [!IMPORTANT]
> The following architectural decisions incorporate the student's confirmed choices from Phase 1:
> - **Evaluation Delivery**: Live browser demonstration with interactive workflow walkthrough.
> - **Ingestion Demonstration**: Custom forensic log file upload supporting both JSON and CSV schemas, paired with a bundled sample test file download.
> - **Evaluator Materials**: Dedicated in-app Teacher Presentation Suite featuring both an interactive slide deck and an evaluator viva Q&A cheat-sheet with timing scripts.
> - **Splunk Decoupling**: All Splunk licensing requirements and external server credentials are permanently detached from the environment configuration and operational views, transforming the app into a self-contained Digital Forensic & SIEM Analysis Engine.

---

## 1. Overview & Core Concept

- **What It Does**: A digital forensic investigation and incident response web application that ingests Windows security logs and cloud incident records, reconstructs chronologically ordered multi-stage cyber attack timelines mapped to the MITRE ATT&CK framework, triggers simulated SOC email alerts, and exports court-ready forensic PDF reports.
- **Target Audience / Persona**: Computer Science & Cybersecurity faculty evaluators and examiners assessing a Semester 5 Mini Project, as well as student investigators presenting a live technical demonstration without relying on paid enterprise infrastructure.
- **Key Value**: Provides a reliable, offline-ready demonstration environment that proves technical competence in SIEM concepts, log parsing, attack chain correlation, and digital forensic reporting without licensing failures or server downtime.

---

## 2. User Experience & Visual Design

### Key User Flows

1. **Zero-State & Presentation Setup**:
   - The student launches the application on `localhost:3000`. The navigation bar features a prominent **"Teacher Presentation Mode"** toggle and a **"Upload Logs"** action.
   - The student opens the **Presentation Deck** to walk evaluators through the 7-slide project overview (Problem Statement, Architecture, Attack Chain, Timeline Engine, SOC Alerting, Forensic PDF, Conclusions).
2. **Custom Forensic Log Upload Demonstration**:
   - The student clicks **"Upload Security Logs"** in front of the teacher.
   - The modal provides two options: (a) Download pre-packaged `sample_apt29_incident.json` or `sample_incident.csv`, and (b) Drag and drop or browse to upload any custom forensic CSV or JSON file.
   - Upon upload, the parser validates timestamps, Event IDs, actor accounts, source IPs, and MITRE tactics, instantly populating the dashboard with parsed events.
3. **Attack Timeline Reconstruction & Inspection**:
   - The student navigates through the interactive attack sequence: Brute Force (`4625`) $\rightarrow$ Lateral Movement via RDP (`4624 Type 10`) $\rightarrow$ Privilege Escalation (`4672`) $\rightarrow$ Scheduled Task Persistence (`4698`) $\rightarrow$ Shadow Copy Erasure / Ransomware execution (`4688`).
   - The student clicks any event node to open the **Forensic Deep-Dive Modal**, showing raw Event Viewer XML/JSON, MITRE sub-technique details, and evidentiary chain of custody.
4. **SOC Alert Dispatch & PDF Report Generation**:
   - The student triggers an automated High-Severity Incident Notification, previewing the SOC email alert with formatted severity indicators and recipient distribution.
   - The student clicks **"Export Forensic PDF"** to produce and download an official digital forensic report with executive summaries, evidentiary tables, and remediation roadmaps.
5. **Viva Cheat-Sheet & Evaluator Questions**:
   - A dedicated **"Viva Cheat-Sheet"** drawer is accessible at any time, providing the student with exact 3-minute speaking notes, theoretical answers to anticipated teacher questions, and technical justifications for log correlation heuristics.

### Visual Identity & Theme

- **Aesthetic Direction**: High-precision Cyber Operations / Digital Forensic Lab interface following clean SaaS and dashboard layout conventions (dark slate background `#0B1120`, slate structural panels `#1E293B`, subtle hairline borders `rgba(148, 163, 184, 0.15)`).
- **Color Discipline**:
  - 60% Dominant Canvas: `#0B1120` (Dark slate deep workspace)
  - 30% Structural Surfaces: `#151E32` / `#1E293B` (Structured cards, hairline dividers, tabular grids)
  - 10% Intentional Semantic Accents: Cyan (`#06B6D4`) for primary actions, Emerald (`#10B981`) for nominal states, Amber (`#F59E0B`) for medium severity, Crimson (`#EF4444`) for critical attack indicators.
- **Typography**: Clean contemporary typography using `Plus Jakarta Sans` for display headers and UI labels, paired with tabular monospace numerals (`JetBrains Mono` / `font-mono tabular-nums`) for event IDs, IP addresses, hashes, and timestamps.
- **Anti-Slop Restraint**: Zero static pill enclosures on metadata; tags and timestamps rendered as clean unboxed typography with typographic separators (`·`). Zero fake pulsing dots on static text.

---

## 3. Key Product Decisions & Trade-Offs

- **Decision 1: Full Splunk Decoupling in Favor of a Standalone Forensic Engine**
  - *Chosen Approach*: Remove all required Splunk host credentials, bearer tokens, and server ports from `.env.example` and the operational dashboard. Replace with an internal high-performance log analysis engine that runs deterministically in the client.
  - *Why*: The student ran out of Splunk licenses and cannot host a live enterprise Splunk instance during the viva. A standalone engine ensures zero runtime failures, zero network latency, and 100% offline reliability.
  - *Alternatives Considered*: Pointing to a dummy localhost Splunk port (causes CORS/SSL connection errors in front of evaluators) or keeping Splunk settings hidden (confusing to evaluators who ask how to configure it).
- **Decision 2: Dual File Upload Ingestion (CSV & JSON) with Built-In Sample Test File Generator**
  - *Chosen Approach*: Implement a flexible client-side parser supporting standard Windows Event Log CSV exports and SIEM JSON dumps, alongside an instant "Download Sample Incident Dataset" button.
  - *Why*: Allows the student to either upload a fresh file live in front of the teacher to prove the system isn't hardcoded, or quickly load the verified reference attack scenario.
  - *Alternatives Considered*: Requiring external log files only (risks the student forgetting the file on demo day) vs. static demo data only (teachers may suspect hardcoded values).
- **Decision 3: Integrated In-App Viva Presentation Deck & Cheat-Sheet Drawer**
  - *Chosen Approach*: Build the presentation slides directly into the web application via a full-screen or slide modal viewer, accompanied by a quick-reference technical Q&A drawer.
  - *Why*: Eliminates awkward window switching between PowerPoint and the browser during a time-constrained 5-to-10-minute viva.

---

## 4. Technical Architecture & Data Strategy

### System Architecture Diagram

```
┌────────────────────────────────────────────────────────────────────────┐
│                        User Interface Layer                            │
│  ┌─────────────────────────┐  ┌─────────────────────────────────────┐  │
│  │   Navigation & Controls │  │  Teacher Presentation Deck (Slides) │  │
│  └────────────┬────────────┘  └──────────────────┬──────────────────┘  │
│               │                                  │                     │
│  ┌────────────▼────────────┐  ┌──────────────────▼──────────────────┐  │
│  │  Custom Log File Upload │  │   Live Viva Oral Cheat-Sheet Modal  │  │
│  │   (CSV / JSON Parser)   │  │    (Anticipated Evaluator Q&A)      │  │
│  └────────────┬────────────┘  └─────────────────────────────────────┘  │
│               │                                                        │
│  ┌────────────▼─────────────────────────────────────────────────────┐  │
│  │     Forensic Dashboard & Interactive Attack Flow Track           │  │
│  │  (Event Filtering, MITRE Mapping, Evidence Inspector Modal)      │  │
│  └────────────┬──────────────────────────────────┬──────────────────┘  │
└───────────────┼──────────────────────────────────┼─────────────────────┘
                │                                  │
┌───────────────▼──────────────────────────────────▼─────────────────────┐
│                 Forensic Core & Processing Engine                      │
│  ┌──────────────────────────┐      ┌────────────────────────────────┐  │
│  │   Timeline Reconstructor │      │  Investigation Summary Service │  │
│  │  - MITRE Technique Map   │      │  - Confirmed Evidence          │  │
│  │  - Suspicious Heuristics │      │  - Attack Hypotheses           │  │
│  │  - Temporal Ordering     │      │  - Actionable Remediation      │  │
│  └────────────┬─────────────┘      └────────────────┬───────────────┘  │
│               │                                     │                  │
│  ┌────────────▼─────────────┐      ┌────────────────▼───────────────┐  │
│  │ SOC Email Alert Preview  │      │   Court-Ready PDF Generator    │  │
│  │  (Simulated Dispatch)    │      │  (jsPDF + autoTable Exporter)  │  │
│  └──────────────────────────┘      └────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

### Data Models & State Structure

- **WindowsEvent Model**:
  - `timestamp`: ISO-8601 string.
  - `event_id`: Standard Windows Security Event ID (`4624`, `4625`, `4672`, `4698`, `4688`, `1102`, `4720`, `4738`, `7045`).
  - `event_name`: Human-readable description (e.g., "An account was successfully logged on").
  - `category`: Logon, Privilege Escalation, Persistence, Execution, Defense Evasion.
  - `severity`: Low, Medium, High, Critical.
  - `mitre_tactic` & `mitre_technique`: Official MITRE ATT&CK codes (e.g., `T1110`, `T1021.002`, `T1078`, `T1053.005`).
  - `username`, `source_ip`, `computer_name`, `logon_type`, `process_name`, `target_object`.
  - `raw_data`: Complete structured log representation for evidentiary inspection.
- **Presentation Deck State**:
  - 7 curated slides with next/prev keyboard controls, presenter bullet highlights, and architectural diagrams.
- **Viva Cheat-Sheet State**:
  - Collapsible accordion of 8 critical evaluation questions (Correlation algorithm, MITRE mapping, Event 4625 vs 4624 Type 10, False positive suppression, Chain of custody).

### Implementation Plan Milestones

1. **Splunk Disconnection & Environment Sanitation**:
   - Clean `.env.example` of all Splunk URLs, ports, and tokens.
   - Refactor settings and health indicators to reflect the standalone forensic engine.
2. **Custom File Ingestion (CSV / JSON) & Sample Downloader**:
   - Implement client-side CSV parser (`PapaParse` or custom robust tokenizer) and JSON schema validator.
   - Add a "Download Sample Attack Log" button generating an authentic multi-stage attack dataset for the student to keep on a flash drive.
3. **Teacher Presentation Suite (Slide Deck & Viva Cheat-Sheet)**:
   - Create `src/components/PresentationDeck.tsx` containing the 7-slide academic presentation.
   - Create `src/components/VivaCheatSheet.tsx` containing oral walkthrough notes and evaluator answers.
4. **End-to-End Workflow Verification**:
   - Verify upload $\rightarrow$ attack timeline reconstruction $\rightarrow$ alert dispatch $\rightarrow$ PDF generation with TypeScript compilation and testing.
