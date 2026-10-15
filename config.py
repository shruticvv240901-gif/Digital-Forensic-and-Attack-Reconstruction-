"""
Configuration module for AI-Assisted Attack Timeline Reconstruction.
Loads settings from environment variables and .env file.
"""

import os
from pathlib import Path

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent

# Attempt to load python-dotenv; if not installed, fallback to manual .env parsing
try:
    from dotenv import load_dotenv
    env_path = BASE_DIR / ".env"
    if env_path.exists():
        load_dotenv(dotenv_path=env_path)
except ImportError:
    # Minimal fallback parser if python-dotenv is not yet installed
    env_path = BASE_DIR / ".env"
    if env_path.exists():
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, val = line.split("=", 1)
                    key = key.strip()
                    val = val.strip().strip("'\"")
                    if key not in os.environ:
                        os.environ[key] = val


def _str_to_bool(value: str, default: bool = False) -> bool:
    """Safely convert string environment variables to booleans."""
    if value is None:
        return default
    return value.strip().lower() in ("true", "1", "yes", "on", "t")


class Config:
    """Application configuration loaded from environment variables."""

    # Flask Settings
    SECRET_KEY = os.getenv("SECRET_KEY", "cyber-forensics-dev-secret-key-change-me")
    DEBUG = _str_to_bool(os.getenv("FLASK_DEBUG", "True"), default=True)
    PORT = int(os.getenv("FLASK_PORT", "5000"))
    HOST = os.getenv("FLASK_HOST", "127.0.0.1")

    # Mode Selector: Demo / Test Mode vs Live Splunk
    DEMO_MODE = _str_to_bool(os.getenv("DEMO_MODE", "True"), default=True)

    # Splunk Enterprise Settings (Management REST API port is typically 8089)
    SPLUNK_HOST = os.getenv("SPLUNK_HOST", "localhost").strip()
    SPLUNK_MANAGEMENT_PORT = int(os.getenv("SPLUNK_MANAGEMENT_PORT", "8089"))
    SPLUNK_SCHEME = os.getenv("SPLUNK_SCHEME", "https").strip().lower()
    SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME", "").strip()
    SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD", "").strip()
    SPLUNK_BEARER_TOKEN = os.getenv("SPLUNK_BEARER_TOKEN", "").strip()
    SPLUNK_VERIFY_SSL = _str_to_bool(os.getenv("SPLUNK_VERIFY_SSL", "False"), default=False)
    SPLUNK_TIMEOUT = int(os.getenv("SPLUNK_TIMEOUT", "15"))

    # Splunk Search Settings
    SPLUNK_INDEX = os.getenv("SPLUNK_INDEX", "*").strip()
    SPLUNK_SEARCH_MAX_COUNT = int(os.getenv("SPLUNK_SEARCH_MAX_COUNT", "100"))

    @classmethod
    def is_splunk_configured(cls) -> bool:
        """
        Check if minimal Splunk connection parameters are provided.
        Requires host, port, and either (username + password) or bearer token.
        """
        has_host = bool(cls.SPLUNK_HOST)
        has_credentials = (
            bool(cls.SPLUNK_USERNAME and cls.SPLUNK_PASSWORD)
            or bool(cls.SPLUNK_BEARER_TOKEN)
        )
        return has_host and has_credentials

    @classmethod
    def get_safe_summary(cls) -> dict:
        """
        Returns a masked, safe dictionary of connection settings suitable for display.
        No plain-text credentials are ever returned.
        """
        auth_type = "None"
        if cls.SPLUNK_BEARER_TOKEN:
            auth_type = "Bearer Token (Configured: ••••••••)"
        elif cls.SPLUNK_USERNAME and cls.SPLUNK_PASSWORD:
            auth_type = f"Basic Auth (User: {cls.SPLUNK_USERNAME}, Pass: ••••••••)"
        elif cls.SPLUNK_USERNAME:
            auth_type = f"Basic Auth (User: {cls.SPLUNK_USERNAME}, Password Missing)"

        return {
            "demo_mode": cls.DEMO_MODE,
            "splunk_host": cls.SPLUNK_HOST,
            "splunk_port": cls.SPLUNK_MANAGEMENT_PORT,
            "splunk_scheme": cls.SPLUNK_SCHEME,
            "splunk_base_url": f"{cls.SPLUNK_SCHEME}://{cls.SPLUNK_HOST}:{cls.SPLUNK_MANAGEMENT_PORT}",
            "splunk_index": cls.SPLUNK_INDEX,
            "search_max_count": cls.SPLUNK_SEARCH_MAX_COUNT,
            "auth_configured": cls.is_splunk_configured(),
            "auth_type": auth_type,
            "verify_ssl": cls.SPLUNK_VERIFY_SSL,
            "timeout_seconds": cls.SPLUNK_TIMEOUT,
        }
