"""
Timeline Reconstruction & Forensic Correlation Service.
Stage 3: Automated Attack Timeline Reconstruction.

Forensic Principles:
1. Strict Separation: Clearly distinguishes Confirmed Forensic Facts from Heuristic Hypotheses.
2. Temporal Causality: Sorts events chronologically (oldest -> newest) to map attack progression.
3. Multi-Entity Correlation: Correlates events across Source IP, User Account, Computer Name, and Event IDs.
4. Baseline Protection: Non-malicious baseline events are categorized as routine activity, not attacks.
5. Deterministic & Explainable: No paid or external AI APIs required. Pure, transparent Python heuristics.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
import re
import logging

logger = logging.getLogger(__name__)


class TimelineReconstructionService:
    """
    Forensic correlation service that analyzes Windows Security logs,
    reconstructs causal attack sequences, and generates structured investigation notes.
    """

    # Common MITRE ATT&CK kill-chain stages
    PHASE_RECON = "Reconnaissance / Credential Access"
    PHASE_INITIAL_ACCESS = "Initial Access"
    PHASE_PRIV_ESC = "Privilege Escalation"
    PHASE_LATERAL_MOVE = "Lateral Movement"
    PHASE_PERSISTENCE = "Persistence"
    PHASE_BASELINE = "Routine Baseline Operations"

    @classmethod
    def parse_event_time(cls, timestamp_str: str) -> datetime:
        """Safely parses timestamp string into a datetime object for accurate chronological sorting."""
        if not timestamp_str or timestamp_str == "N/A":
            return datetime.min

        clean_str = str(timestamp_str).strip()
        
        # Format 1: 2026-10-15 10:45:00
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%m/%d/%Y %I:%M:%S %p",
            "%m/%d/%Y %H:%M:%S",
        ):
            try:
                # Strip timezone if simple format
                return datetime.strptime(clean_str[:19].replace("T", " "), "%Y-%m-%d %H:%M:%S")
            except Exception:
                pass

        try:
            return datetime.fromisoformat(clean_str)
        except Exception:
            return datetime.min

    @classmethod
    def reconstruct_attack_timeline(
        cls,
        events: List[Dict[str, Any]],
        reverse: bool = False
    ) -> Dict[str, Any]:
        """
        Reconstructs an end-to-end attack timeline from a list of security events.

        Args:
            events: List of normalized event dictionaries.
            reverse: If True, returns newest -> oldest. Default False (oldest -> newest for causal flow).

        Returns:
            Dict containing timeline items, correlation summary, threat metrics, and chain groups.
        """
        if not events:
            return {
                "success": True,
                "count": 0,
                "timeline": [],
                "summary": {
                    "total_events": 0,
                    "threat_level": "None (No Events)",
                    "unique_actors": [],
                    "targeted_accounts": [],
                    "created_accounts": [],
                    "detected_attack_phases": [],
                    "earliest_event": None,
                    "latest_event": None,
                },
                "correlation_chains": [],
                "message": "No events provided for timeline reconstruction.",
            }

        # 1. Sort events chronologically (Oldest to Newest for causal reconstruction)
        sorted_events = sorted(events, key=lambda e: cls.parse_event_time(e.get("timestamp", "")))

        # 2. Extract Entities across entire dataset
        all_actors = set()
        all_targets = set()
        all_hosts = set()
        created_accounts = set()

        for ev in sorted_events:
            src = ev.get("source_ip", "").strip()
            if src and src != "-" and "localhost" not in src.lower() and "127.0.0.1" not in src:
                all_actors.add(src)
            usr = ev.get("username", "").strip()
            if usr and usr != "-" and usr.lower() != "system":
                all_targets.add(usr)
            hst = ev.get("computer_name", "").strip()
            if hst and hst != "-":
                all_hosts.add(hst)
            if str(ev.get("event_id")) == "4720":
                created_accounts.add(usr)

        # 3. Contextual Pattern Tracking
        # Track history per IP and per username to detect multi-stage transitions
        failed_attempts_by_ip: Dict[str, List[int]] = {}  # ip -> list of step indices
        failed_attempts_by_user: Dict[str, List[int]] = {}
        successful_logons_by_ip: Dict[str, List[int]] = {}
        accounts_created_indices: List[int] = []

        timeline_items: List[Dict[str, Any]] = []
        correlation_chains: List[Dict[str, Any]] = []

        # First pass: Build pattern associations
        for idx, ev in enumerate(sorted_events):
            eid = str(ev.get("event_id", "")).strip()
            ip = ev.get("source_ip", "-")
            user = ev.get("username", "-")

            if eid == "4625":
                failed_attempts_by_ip.setdefault(ip, []).append(idx)
                failed_attempts_by_user.setdefault(user, []).append(idx)
            elif eid == "4624":
                successful_logons_by_ip.setdefault(ip, []).append(idx)
            elif eid == "4720":
                accounts_created_indices.append(idx)

        # 4. Correlation & Heuristic Analysis Pass
        detected_phases = set()
        has_critical = False
        has_high = False

        for idx, ev in enumerate(sorted_events):
            step_num = idx + 1
            eid = str(ev.get("event_id", "")).strip()
            ev_name = ev.get("event_name", f"Windows Event {eid}")
            user = ev.get("username", "Unknown User")
            src_ip = ev.get("source_ip", "-")
            host = ev.get("computer_name", "Unknown Host")
            logon_type = ev.get("logon_type", "N/A")
            logon_code = str(ev.get("logon_type_code", "")).strip()
            timestamp = ev.get("timestamp", "N/A")
            raw_snippet = ev.get("raw_snippet", "")

            # Default heuristic values
            confirmed_facts = ""
            correlation_reason = ""
            suspicion_level = "Informational / Baseline"
            kill_chain_phase = cls.PHASE_BASELINE
            investigation_guidance = ""

            # Check if this IP is associated with repeated brute force
            ip_failures = failed_attempts_by_ip.get(src_ip, [])
            prior_failures_from_ip = [f for f in ip_failures if f < idx]
            is_external_ip = src_ip not in ("-", "127.0.0.1", "::1", "Local Host") and not src_ip.startswith("10.0.")

            # -------------------------------------------------------------
            # Pattern Evaluation by Event ID
            # -------------------------------------------------------------
            if eid == "4625":
                # Failed Logon
                kill_chain_phase = cls.PHASE_RECON
                detected_phases.add(cls.PHASE_RECON)
                confirmed_facts = (
                    f"Authentication failure recorded on '{host}'. "
                    f"Account targeted: '{user}'. "
                    f"Network source IP: '{src_ip}'. "
                    f"Logon mechanism: {logon_type}."
                )

                if len(prior_failures_from_ip) >= 2 or len(ip_failures) >= 3:
                    suspicion_level = "High"
                    has_high = True
                    correlation_reason = (
                        f"Part of a repeated failure cluster ({len(ip_failures)} failed attempts total from {src_ip}). "
                        f"Matches password spraying or brute force pattern targeting user '{user}'."
                    )
                    investigation_guidance = (
                        f"1. Check perimeter firewall logs for connections from {src_ip} on port 445 (SMB) and 3389 (RDP).\n"
                        f"2. Inspect if account lockout policies were triggered on '{host}'.\n"
                        f"3. Verify if {src_ip} originates from a VPN, proxy, or unrecognized external network."
                    )
                else:
                    suspicion_level = "Suspicious"
                    correlation_reason = f"Isolated authentication failure from source {src_ip}."
                    investigation_guidance = "Monitor whether this failure is followed by additional attempts or a logon success."

            elif eid == "4624":
                # Successful Logon
                confirmed_facts = (
                    f"Authentication succeeded for account '{user}' on '{host}'. "
                    f"Source network address: '{src_ip}'. "
                    f"Logon Type: {logon_type}."
                )

                # Check if this successful login came from an IP that previously conducted brute force!
                if prior_failures_from_ip and is_external_ip:
                    suspicion_level = "Critical"
                    has_critical = True
                    kill_chain_phase = cls.PHASE_INITIAL_ACCESS
                    detected_phases.add(cls.PHASE_INITIAL_ACCESS)
                    correlation_reason = (
                        f"CRITICAL BREACH INDICATOR: Account '{user}' successfully logged on from {src_ip} "
                        f"immediately following {len(prior_failures_from_ip)} prior failed login attempts from the exact same IP. "
                        "Strong evidence of password guessing or credential compromise."
                    )
                    investigation_guidance = (
                        f"1. IMMEDIATELY isolate host '{host}' from network segment.\n"
                        f"2. Force password reset and revoke active Kerberos/NTLM ticket grants for '{user}'.\n"
                        f"3. Inspect process creation events (Sysmon Event 1) spawned within 10 minutes of {timestamp}."
                    )
                elif user in created_accounts:
                    # Newly created rogue backdoor account logging in!
                    suspicion_level = "Critical"
                    has_critical = True
                    kill_chain_phase = cls.PHASE_PERSISTENCE
                    detected_phases.add(cls.PHASE_PERSISTENCE)
                    correlation_reason = (
                        f"HIGH RISK SECONDARY INGRESS: Logon by rogue account '{user}', which was recently created "
                        f"(Event 4720) during this intrusion. Attacker is validating persistent backdoor access."
                    )
                    investigation_guidance = (
                        f"1. Terminate active sessions for rogue account '{user}'.\n"
                        f"2. Delete or disable account '{user}' immediately using 'net user {user} /active:no'.\n"
                        f"3. Audit all files modified by '{user}' in C:\\Users\\{user} and Temp directories."
                    )
                elif logon_code == "10":
                    # Remote Desktop (RDP)
                    if prior_failures_from_ip or is_external_ip:
                        suspicion_level = "High"
                        has_high = True
                        kill_chain_phase = cls.PHASE_LATERAL_MOVE
                        detected_phases.add(cls.PHASE_LATERAL_MOVE)
                        correlation_reason = (
                            f"Remote Desktop (RDP) interactive session established by '{user}' from external source {src_ip}. "
                            "Indicates interactive GUI control over the target machine."
                        )
                        investigation_guidance = (
                            f"1. Review RDP session logs in 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'.\n"
                            f"2. Inspect clipboard transfer and drive redirection activity during RDP session."
                        )
                    else:
                        suspicion_level = "Medium"
                        kill_chain_phase = cls.PHASE_BASELINE
                        correlation_reason = f"Internal Remote Desktop session from internal IP {src_ip}."
                        investigation_guidance = f"Verify whether internal IP {src_ip} belongs to authorized IT administration workstation."
                else:
                    # Normal or baseline logon
                    suspicion_level = "Informational / Baseline"
                    kill_chain_phase = cls.PHASE_BASELINE
                    detected_phases.add(cls.PHASE_BASELINE)
                    correlation_reason = "Standard baseline authentication without prior anomalous indicators."
                    investigation_guidance = "No immediate remediation required unless user '{user}' was scheduled for off-hours."

            elif eid == "4672":
                # Special Privileges Assigned
                confirmed_facts = (
                    f"Special administrative privileges (e.g. SeDebugPrivilege, SeSecurityPrivilege) assigned "
                    f"to logon session for user '{user}' on '{host}'."
                )

                if is_external_ip or user in created_accounts:
                    suspicion_level = "High"
                    has_high = True
                    kill_chain_phase = cls.PHASE_PRIV_ESC
                    detected_phases.add(cls.PHASE_PRIV_ESC)
                    correlation_reason = (
                        f"High-risk administrative privileges granted to session originating from external address {src_ip} "
                        f"or belonging to rogue persistence user '{user}'."
                    )
                    investigation_guidance = (
                        f"1. Check if SeDebugPrivilege was utilized to dump LSASS process memory (e.g., Mimikatz).\n"
                        f"2. Review Security Event ID 4673 (Privileged Service Called) for unauthorized token impersonation."
                    )
                else:
                    suspicion_level = "Informational / Baseline"
                    kill_chain_phase = cls.PHASE_BASELINE
                    correlation_reason = f"Routine administrative elevation for internal admin session on {host}."
                    investigation_guidance = "Verify that this elevation corresponds to scheduled internal maintenance."

            elif eid == "4720":
                # User Account Created
                confirmed_facts = (
                    f"A new local Windows user account named '{user}' was created on '{host}'. "
                    f"Target creator session was active on machine."
                )
                suspicion_level = "Critical"
                has_critical = True
                kill_chain_phase = cls.PHASE_PERSISTENCE
                detected_phases.add(cls.PHASE_PERSISTENCE)
                correlation_reason = (
                    f"CRITICAL PERSISTENCE ACTION: New user account '{user}' created on domain/host. "
                    "In forensic analysis, creation of unmanaged local accounts during off-hours or following a breach "
                    "strongly indicates attacker establishing persistence."
                )
                investigation_guidance = (
                    f"1. Check Windows Event 4728 / 4732 to see if '{user}' was added to Administrators or Remote Desktop Users group.\n"
                    f"2. Check creation timestamp against employee onboarding records to verify legitimacy.\n"
                    f"3. Disable account '{user}' immediately if unauthorized."
                )

            # Build timeline card item
            item = {
                "step": step_num,
                "timestamp": timestamp,
                "event_id": eid,
                "event_name": ev_name,
                "actor": src_ip if src_ip != "-" else "Local Machine Session",
                "target_user": user,
                "target_host": host,
                "logon_type": logon_type,
                "kill_chain_phase": kill_chain_phase,
                "suspicion_level": suspicion_level,
                "confirmed_facts": confirmed_facts,
                "correlation_reason": correlation_reason,
                "investigation_guidance": investigation_guidance,
                "raw_snippet": raw_snippet,
                "is_real_data": ev.get("is_real_data", False),
            }
            timeline_items.append(item)

        # 5. Extract Cohesive Correlation Chains
        if ip_failures:
            for ip, idxs in failed_attempts_by_ip.items():
                if len(idxs) >= 2:
                    succs = successful_logons_by_ip.get(ip, [])
                    correlation_chains.append({
                        "chain_id": f"CHAIN-BRUTE-{ip.replace('.', '_')}",
                        "title": "Credential Access Campaign",
                        "primary_actor": ip,
                        "events_involved": len(idxs) + len(succs),
                        "tactic": "Credential Access / Initial Access",
                        "verdict": "Compromised Access" if succs else "Unsuccessful Brute Force",
                        "description": (
                            f"Detected {len(idxs)} authentication failures from {ip}."
                            + (f" Followed by successful logon ({len(succs)} events)." if succs else "")
                        ),
                    })

        if accounts_created_indices:
            correlation_chains.append({
                "chain_id": "CHAIN-PERSISTENCE-01",
                "title": "Account Manipulation & Persistence",
                "primary_actor": "Elevated Session",
                "events_involved": len(accounts_created_indices),
                "tactic": "Persistence (T1136)",
                "verdict": "High-Risk Persistence",
                "description": f"Created {len(accounts_created_indices)} rogue user account(s): {', '.join(created_accounts)}.",
            })

        # Overall threat level synthesis
        if has_critical:
            threat_level = "Critical Threat (Active Multi-Stage Compromise)"
        elif has_high:
            threat_level = "High Suspicion (Targeted Attacks Detected)"
        elif len(timeline_items) > 0:
            threat_level = "Low / Baseline (Routine Security Telemetry)"
        else:
            threat_level = "None"

        earliest = sorted_events[0].get("timestamp") if sorted_events else None
        latest = sorted_events[-1].get("timestamp") if sorted_events else None

        # Sort order adjustment if reverse requested
        if reverse:
            timeline_items.reverse()
            for idx, item in enumerate(timeline_items):
                item["display_index"] = idx + 1
        else:
            for idx, item in enumerate(timeline_items):
                item["display_index"] = idx + 1

        return {
            "success": True,
            "count": len(timeline_items),
            "timeline": timeline_items,
            "summary": {
                "total_events": len(timeline_items),
                "threat_level": threat_level,
                "unique_actors": sorted(list(all_actors)),
                "targeted_accounts": sorted(list(all_targets)),
                "created_accounts": sorted(list(created_accounts)),
                "detected_attack_phases": sorted(list(detected_phases)),
                "earliest_event": earliest,
                "latest_event": latest,
            },
            "correlation_chains": correlation_chains,
            "message": f"Successfully reconstructed attack timeline with {len(timeline_items)} correlated steps.",
        }
