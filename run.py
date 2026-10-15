"""
Application Entry Point.
Run this script to start the local Flask development server.

Usage:
    python run.py
"""

from app import create_app
from config import Config

app = create_app()

if __name__ == "__main__":
    print("=" * 70)
    print(" AI-Assisted Attack Timeline Reconstruction & Digital Forensic Reporting")
    print("=" * 70)
    print(f" * Mode:            {'DEMO / TEST MODE' if Config.DEMO_MODE else 'LIVE SPLUNK MODE'}")
    print(f" * Splunk Host:     {Config.SPLUNK_SCHEME}://{Config.SPLUNK_HOST}:{Config.SPLUNK_MANAGEMENT_PORT}")
    print(f" * Splunk Config:   {'Configured' if Config.is_splunk_configured() else 'Not Configured (Awaiting credentials in .env)'}")
    print(f" * Dashboard URL:   http://{Config.HOST}:{Config.PORT}")
    print("=" * 70)
    
    app.run(
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.DEBUG,
    )
