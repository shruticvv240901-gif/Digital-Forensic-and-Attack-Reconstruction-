"""
Splunk REST API Service Module.
Handles communication, health checks, SPL search execution, and Windows Security Log normalization.

Design Principles:
1. No assumed credentials: If credentials are missing, reports unconfigured state gracefully.
2. Demo mode isolation: Clearly demarcates simulated data vs real data. Zero fake data when DEMO_MODE=False.
3. Beginner-friendly: Descriptive error messages and robust exception handling.
"""

import re
import time
import logging
from typing import Dict, Any, List, Optional
import requests
import urllib3

from config import Config
from app.services.demo_data import generate_demo_events, filter_demo_events

logger = logging.getLogger(__name__)

# Suppress insecure SSL warnings if user intentionally disables verification for local Splunk
if not Config.SPLUNK_VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SplunkService:
    """Service class for interfacing with the Splunk Enterprise REST API."""

    # Human-friendly descriptions and MITRE ATT&CK mapping for target Windows Event IDs
    EVENT_METADATA = {
        "4624": {
            "name": "Successful Logon",
            "category": "Logon / Authentication",
            "default_severity": "Low",
            "mitre_tactic": "Initial Access / Lateral Movement",
            "mitre_technique": "T1078 (Valid Accounts)",
        },
        "4625": {
            "name": "Failed Logon Attempt",
            "category": "Account Access Attempt",
            "default_severity": "High",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1110 (Brute Force / Password Guessing)",
        },
        "4672": {
            "name": "Special Privileges Assigned",
            "category": "Privilege Escalation",
            "default_severity": "Medium",
            "mitre_tactic": "Privilege Escalation",
            "mitre_technique": "T1078 (Privileged Account Abuse)",
        },
        "4720": {
            "name": "User Account Created",
            "category": "Account Management",
            "default_severity": "High",
            "mitre_tactic": "Persistence",
            "mitre_technique": "T1136 (Create Account)",
        },
    }

    # Standard Windows Logon Types
    LOGON_TYPES = {
        "2": "Interactive (Console / Local Keyboard)",
        "3": "Network (SMB, Shared Folder, PsExec)",
        "4": "Batch (Scheduled Task)",
        "5": "Service (Service Controller)",
        "7": "Unlock (Workstation Unlocked)",
        "8": "NetworkCleartext (IIS / Basic Auth)",
        "9": "NewCredentials (RunAs / Keymgr)",
        "10": "RemoteInteractive (RDP / Remote Desktop)",
        "11": "CachedInteractive (Cached Domain Logon)",
    }

    def __init__(self):
        self.base_url = f"{Config.SPLUNK_SCHEME}://{Config.SPLUNK_HOST}:{Config.SPLUNK_MANAGEMENT_PORT}"
        self.username = Config.SPLUNK_USERNAME
        self.password = Config.SPLUNK_PASSWORD
        self.bearer_token = Config.SPLUNK_BEARER_TOKEN
        self.verify_ssl = Config.SPLUNK_VERIFY_SSL
        self.timeout = Config.SPLUNK_TIMEOUT
        self.demo_mode = Config.DEMO_MODE
        self.default_index = Config.SPLUNK_INDEX
        self.max_count = Config.SPLUNK_SEARCH_MAX_COUNT

    def is_configured(self) -> bool:
        """Checks if minimal connection parameters are present."""
        return Config.is_splunk_configured()

    def get_auth_headers_or_tuple(self):
        """
        Builds the authentication parameters for requests.
        Returns:
            tuple: (auth_tuple, headers_dict)
        """
        headers = {
            "Accept": "application/json"
        }
        auth = None

        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        elif self.username and self.password:
            auth = (self.username, self.password)

        return auth, headers

    def test_connection(self) -> Dict[str, Any]:
        """
        Tests connection to the Splunk Enterprise instance.
        Queries the standard '/services/server/info' endpoint.
        """
        if not self.is_configured():
            return {
                "connected": False,
                "status": "Not Configured",
                "message": (
                    "Splunk credentials are not configured in your .env file. "
                    "Please provide SPLUNK_USERNAME and SPLUNK_PASSWORD (or SPLUNK_BEARER_TOKEN) "
                    "in .env to connect to your live Splunk instance."
                ),
                "server_url": self.base_url,
                "latency_ms": None,
                "server_info": None,
            }

        endpoint = f"{self.base_url}/services/server/info?output_mode=json"
        auth, headers = self.get_auth_headers_or_tuple()

        start_time = time.time()
        try:
            response = requests.get(
                endpoint,
                auth=auth,
                headers=headers,
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
            elapsed_ms = round((time.time() - start_time) * 1000, 2)

            if response.status_code == 200:
                data = response.json()
                entry = data.get("entry", [{}])[0].get("content", {})
                return {
                    "connected": True,
                    "status": "Connected",
                    "message": f"Successfully connected to Splunk Enterprise at {self.base_url}",
                    "latency_ms": elapsed_ms,
                    "server_url": self.base_url,
                    "server_info": {
                        "server_name": entry.get("serverName", "Unknown"),
                        "version": entry.get("version", "Unknown"),
                        "os_name": entry.get("os_name", "Unknown"),
                        "license_state": entry.get("licenseState", "Unknown"),
                        "mode": entry.get("mode", "Unknown"),
                    },
                }
            elif response.status_code == 401:
                return {
                    "connected": False,
                    "status": "Authentication Failed",
                    "message": "Invalid Splunk credentials. Check SPLUNK_USERNAME and SPLUNK_PASSWORD in .env.",
                    "latency_ms": elapsed_ms,
                    "server_url": self.base_url,
                    "server_info": None,
                }
            else:
                return {
                    "connected": False,
                    "status": f"HTTP Error {response.status_code}",
                    "message": f"Splunk responded with status code {response.status_code}: {response.text[:200]}",
                    "latency_ms": elapsed_ms,
                    "server_url": self.base_url,
                    "server_info": None,
                }

        except requests.exceptions.ConnectTimeout:
            return {
                "connected": False,
                "status": "Connection Timeout",
                "message": f"Timed out after {self.timeout}s trying to reach {self.base_url}. Verify that Splunk is running on Windows 11.",
                "latency_ms": None,
                "server_url": self.base_url,
                "server_info": None,
            }
        except requests.exceptions.ConnectionError as e:
            return {
                "connected": False,
                "status": "Connection Refused",
                "message": (
                    f"Unable to connect to {self.base_url}. "
                    "Make sure Splunk Enterprise service is running and management port 8089 is accessible."
                ),
                "details": str(e),
                "latency_ms": None,
                "server_url": self.base_url,
                "server_info": None,
            }
        except Exception as e:
            return {
                "connected": False,
                "status": "Unexpected Error",
                "message": f"An error occurred while connecting to Splunk: {str(e)}",
                "latency_ms": None,
                "server_url": self.base_url,
                "server_info": None,
            }

    def execute_spl(
        self,
        spl_query: str,
        earliest_time: str = "-24h",
        latest_time: str = "now",
        max_count: int = 100
    ) -> Dict[str, Any]:
        """
        Executes an SPL search against Splunk Enterprise using synchronous 'oneshot' mode.

        Args:
            spl_query: The SPL query string.
            earliest_time: Splunk relative or absolute earliest time (e.g. '-24h', '-7d', '0').
            latest_time: Splunk relative or absolute latest time (default 'now').
            max_count: Max count limit for results.

        Returns:
            Dict containing success boolean, results list, count, and execution time.
        """
        if not self.is_configured():
            return {
                "success": False,
                "error": "Splunk credentials are not configured in .env.",
                "results": [],
                "count": 0,
                "execution_time_ms": None,
            }

        # Ensure query begins with the mandatory 'search ' command
        trimmed_query = spl_query.strip()
        if not trimmed_query.startswith("search ") and not trimmed_query.startswith("|"):
            trimmed_query = f"search {trimmed_query}"

        endpoint = f"{self.base_url}/services/search/jobs"
        auth, headers = self.get_auth_headers_or_tuple()

        payload = {
            "search": trimmed_query,
            "exec_mode": "oneshot",
            "output_mode": "json",
            "earliest_time": earliest_time,
            "latest_time": latest_time,
            "count": max_count,
        }

        start_time = time.time()
        try:
            response = requests.post(
                endpoint,
                data=payload,
                auth=auth,
                headers=headers,
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
            elapsed_ms = round((time.time() - start_time) * 1000, 2)

            if response.status_code == 200:
                data = response.json()
                results = data.get("results", [])
                return {
                    "success": True,
                    "results": results,
                    "count": len(results),
                    "execution_time_ms": elapsed_ms,
                    "query": trimmed_query,
                }
            elif response.status_code == 400:
                return {
                    "success": False,
                    "error": f"Invalid SPL Syntax (HTTP 400): {response.text[:300]}",
                    "results": [],
                    "count": 0,
                    "execution_time_ms": elapsed_ms,
                }
            elif response.status_code == 401:
                return {
                    "success": False,
                    "error": "Authentication Failed (HTTP 401). Please verify SPLUNK_USERNAME and SPLUNK_PASSWORD in .env.",
                    "results": [],
                    "count": 0,
                    "execution_time_ms": elapsed_ms,
                }
            else:
                return {
                    "success": False,
                    "error": f"Splunk returned HTTP {response.status_code}: {response.text[:300]}",
                    "results": [],
                    "count": 0,
                    "execution_time_ms": elapsed_ms,
                }

        except requests.exceptions.ConnectTimeout:
            return {
                "success": False,
                "error": f"Search timed out after {self.timeout}s while connecting to Splunk Enterprise.",
                "results": [],
                "count": 0,
                "execution_time_ms": None,
            }
        except requests.exceptions.ConnectionError as e:
            return {
                "success": False,
                "error": f"Could not reach Splunk at {self.base_url}. Verify that Splunk Enterprise is running.",
                "details": str(e),
                "results": [],
                "count": 0,
                "execution_time_ms": None,
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Unexpected error during search execution: {str(e)}",
                "results": [],
                "count": 0,
                "execution_time_ms": None,
            }

    def query_windows_security_events(
        self,
        event_id: Optional[str] = None,
        time_range: str = "-24h",
        limit: int = 50
    ) -> Dict[str, Any]:
        """
        Retrieves real Windows Security Event Log data from Splunk Enterprise.
        Focuses on Event IDs: 4624, 4625, 4672, and 4720.

        Strict Separation:
        - If DEMO_MODE=True: returns clearly tagged simulated events.
        - If DEMO_MODE=False: executes a real SPL search. Never fabricates data.
        """
        # If in Demo Mode, return clearly marked simulated events with accurate filtering
        if self.demo_mode:
            all_demo_events = generate_demo_events()
            filtered_events = filter_demo_events(
                events=all_demo_events,
                event_id=event_id or "all",
                time_range=time_range or "-24h",
                limit=limit,
            )
            target_desc = f"EventCode={event_id}" if event_id and str(event_id).lower() != "all" else "EventCode IN (4624, 4625, 4672, 4720)"
            simulated_spl = f"[DEMO SPL EMULATION]: search index=* ({target_desc}) earliest={time_range} | sort - _time | head {limit}"
            
            return {
                "success": True,
                "mode": "DEMO",
                "events": filtered_events,
                "count": len(filtered_events),
                "execution_time_ms": 1.5,
                "spl_query": simulated_spl,
                "message": f"[DEMO DATA - SIMULATED] Retrieved {len(filtered_events)} simulated Windows security events. No live Splunk query was executed.",
            }

        # In Live Mode, verify configuration
        if not self.is_configured():
            return {
                "success": False,
                "mode": "LIVE",
                "error": (
                    "Splunk connection credentials are not configured. "
                    "Please edit your .env file with valid SPLUNK_USERNAME and SPLUNK_PASSWORD."
                ),
                "events": [],
                "count": 0,
                "execution_time_ms": None,
            }

        # Build dynamic SPL query targeting the requested Windows Event IDs
        target_ids = ["4624", "4625", "4672", "4720"]
        if event_id and event_id != "all" and str(event_id) in target_ids:
            event_filter = f"(EventCode={event_id} OR EventID={event_id})"
        else:
            in_clause = ", ".join(target_ids)
            event_filter = f"(EventCode IN ({in_clause}) OR EventID IN ({in_clause}))"

        # Index search expression
        index_expr = f"index={self.default_index}" if self.default_index != "*" else "index=*"

        # Constructed SPL query
        spl = (
            f"search {index_expr} "
            f'(sourcetype="*WinEventLog:Security*" OR sourcetype="*Security*" OR {event_filter}) '
            f"{event_filter} "
            f"| sort - _time "
            f"| head {limit}"
        )

        spl_result = self.execute_spl(
            spl_query=spl,
            earliest_time=time_range,
            latest_time="now",
            max_count=limit,
        )

        if not spl_result.get("success"):
            return {
                "success": False,
                "mode": "LIVE",
                "error": spl_result.get("error"),
                "events": [],
                "count": 0,
                "execution_time_ms": spl_result.get("execution_time_ms"),
                "spl_query": spl,
            }

        # Normalize the raw results from Splunk
        raw_results = spl_result.get("results", [])
        normalized_events = [self._normalize_windows_event(r) for r in raw_results]

        return {
            "success": True,
            "mode": "LIVE",
            "events": normalized_events,
            "count": len(normalized_events),
            "execution_time_ms": spl_result.get("execution_time_ms"),
            "spl_query": spl,
            "message": f"Successfully retrieved {len(normalized_events)} live events from Splunk Enterprise.",
        }

    def _normalize_windows_event(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalizes a raw Splunk event dict into a standardized forensic security event schema.
        Handles both Splunk TA field extractions and raw text regex fallback.
        """
        raw_text = str(raw.get("_raw", ""))

        # 1. Extract Event Code / ID
        event_id = str(raw.get("EventCode") or raw.get("EventID") or "").strip()
        if not event_id:
            m = re.search(r"EventCode[=:]\s*(\d+)", raw_text, re.IGNORECASE)
            event_id = m.group(1) if m else "Unknown"

        # 2. Lookup event metadata
        meta = self.EVENT_METADATA.get(event_id, {
            "name": f"Windows Event {event_id}",
            "category": "Security Event",
            "default_severity": "Informational",
            "mitre_tactic": "Unknown",
            "mitre_technique": "Unclassified",
        })

        # 3. Extract Timestamp
        timestamp = raw.get("_time") or ""
        if not timestamp:
            # Fallback to current or raw regex
            m = re.search(r"(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})", raw_text)
            timestamp = m.group(1) if m else "N/A"

        # 4. Extract User / Account Name
        # In Windows logs, TargetUserName represents the target of the logon/action.
        username = (
            raw.get("TargetUserName")
            or raw.get("user")
            or raw.get("Account_Name")
            or raw.get("Target_User_Name")
            or raw.get("SubjectUserName")
            or ""
        )
        if not username or username == "-":
            # Attempt regex from _raw (support multi-line and single-line raw logs)
            m = re.search(r"(?:Target\s*Account\s*Name|Account\s*Name|User\s*Name)[\s:=]+([^\r\n\t]+)", raw_text, re.IGNORECASE)
            if m:
                extracted = m.group(1).strip()
                # If subsequent field names were captured on the same line, split before them
                extracted = re.split(r"\s+(?:Source|Domain|Security|Computer|Logon)", extracted, flags=re.IGNORECASE)[0].strip()
                if extracted != "-" and extracted.lower() != "system":
                    username = extracted
            if not username or username == "-":
                username = raw.get("SubjectUserName") or "SYSTEM"

        # 5. Extract Source IP / Workstation Address
        source_ip = (
            raw.get("IpAddress")
            or raw.get("src_ip")
            or raw.get("Source_Network_Address")
            or raw.get("src")
            or ""
        )
        if not source_ip or source_ip == "-":
            m = re.search(r"(?:Source\s*Network\s*Address|Source\s*IP|IpAddress)[\s:=]+([^\r\n\t\s]+)", raw_text, re.IGNORECASE)
            source_ip = m.group(1).strip() if m else "-"
        if source_ip in ("::1", "127.0.0.1"):
            source_ip = f"{source_ip} (Localhost)"

        # 6. Extract Computer / Host
        computer_name = (
            raw.get("ComputerName")
            or raw.get("dest")
            or raw.get("host")
            or raw.get("Workstation_Name")
            or "Local Host"
        )

        # 7. Extract Logon Type (for 4624 / 4625)
        logon_type_code = str(raw.get("Logon_Type") or raw.get("LogonType") or "").strip()
        if not logon_type_code:
            m = re.search(r"Logon Type:\s*(\d+)", raw_text)
            logon_type_code = m.group(1) if m else ""

        logon_type_desc = self.LOGON_TYPES.get(logon_type_code, f"Type {logon_type_code}" if logon_type_code else "N/A")

        # 8. Build forensic message summary
        message = raw.get("Message") or raw.get("signature") or ""
        if not message:
            # Provide clean narrative summary based on Event ID and fields
            if event_id == "4624":
                message = f"Successful authentication by '{username}' from {source_ip}. Logon Type: {logon_type_desc}."
            elif event_id == "4625":
                message = f"Failed logon attempt for account '{username}' from {source_ip}. (Bad password or unknown account)."
            elif event_id == "4672":
                message = f"Special administrative privileges granted to account '{username}'."
            elif event_id == "4720":
                message = f"New user account created: '{username}' on host '{computer_name}'."
            else:
                message = raw_text[:200] if raw_text else f"Windows Security Event {event_id}"

        # 9. Determine severity
        severity = meta["default_severity"]
        if event_id == "4624" and logon_type_code in ("10", "3") and username.lower() in ("administrator", "root"):
            severity = "High"  # Remote admin logon is elevated risk

        return {
            "timestamp": timestamp,
            "event_id": event_id,
            "event_name": meta["name"],
            "category": meta["category"],
            "severity": severity,
            "mitre_tactic": meta["mitre_tactic"],
            "mitre_technique": meta["mitre_technique"],
            "username": username,
            "source_ip": source_ip,
            "computer_name": computer_name,
            "logon_type": logon_type_desc,
            "logon_type_code": logon_type_code,
            "message": message,
            "raw_snippet": (raw_text[:350] + "...") if len(raw_text) > 350 else raw_text,
            "is_real_data": not self.demo_mode,
        }

    def get_sample_timeline_events(self) -> List[Dict[str, Any]]:
        """
        Returns mock timeline events ONLY when DEMO_MODE is True.
        Clearly tagged so they cannot be confused with live forensic evidence.
        """
        if not self.demo_mode:
            # When demo mode is disabled, NEVER return fake data as real data.
            return []

        # Return realistic multi-stage simulated attack dataset
        return generate_demo_events()
