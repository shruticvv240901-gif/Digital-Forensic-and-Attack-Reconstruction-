"""
Main routes for the forensic dashboard and overview interfaces.
"""

from flask import Blueprint, render_template
from config import Config
from app.services.splunk_service import SplunkService
from app.services.timeline_service import TimelineReconstructionService
from app.services.report_service import ForensicReportService

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def dashboard():
    """
    Renders the primary cybersecurity attack reconstruction dashboard.
    Initializes filter options, raw log events, the reconstructed attack timeline,
    and the automated forensic investigation summary.
    """
    service = SplunkService()
    safe_config = Config.get_safe_summary()
    
    # If in demo mode, load initial sample events matching the default UI filters (Last 24h, Limit 50)
    if Config.DEMO_MODE:
        from app.services.demo_data import filter_demo_events
        demo_events = filter_demo_events(
            service.get_sample_timeline_events(),
            event_id="all",
            time_range="-24h",
            limit=50,
        )
    else:
        demo_events = []

    # Compute initial attack timeline from available events
    initial_timeline = TimelineReconstructionService.reconstruct_attack_timeline(demo_events)

    # Compute initial automated investigation summary
    initial_summary = ForensicReportService.generate_investigation_summary(
        timeline_data=initial_timeline,
        is_demo=Config.DEMO_MODE,
    )

    target_event_ids = [
        {"id": "all", "label": "All Target Events (4624, 4625, 4672, 4720)"},
        {"id": "4624", "label": "Event 4624 - Successful Logon"},
        {"id": "4625", "label": "Event 4625 - Failed Logon Attempt"},
        {"id": "4672", "label": "Event 4672 - Special Privileges Assigned"},
        {"id": "4720", "label": "Event 4720 - User Account Created"},
    ]

    time_ranges = [
        {"val": "-15m", "label": "Last 15 Minutes"},
        {"val": "-1h", "label": "Last 1 Hour"},
        {"val": "-24h", "label": "Last 24 Hours (Default)"},
        {"val": "-7d", "label": "Last 7 Days"},
        {"val": "0", "label": "All Time"},
    ]

    return render_template(
        "dashboard.html",
        config=safe_config,
        demo_mode=Config.DEMO_MODE,
        is_configured=Config.is_splunk_configured(),
        demo_events=demo_events,
        initial_timeline=initial_timeline,
        initial_summary=initial_summary,
        target_event_ids=target_event_ids,
        time_ranges=time_ranges,
    )


@main_bp.route("/settings")
def settings():
    """
    Displays the current environment configuration in a secure, masked format.
    """
    safe_config = Config.get_safe_summary()
    return render_template(
        "settings.html",
        config=safe_config,
        demo_mode=Config.DEMO_MODE,
    )


@main_bp.route("/health")
def health():
    """Simple application health check endpoint."""
    return {
        "status": "healthy",
        "app": "AI-Assisted Attack Timeline Reconstruction",
        "stage": "Stage 4: AI Summary & Digital Forensic Report Export",
        "demo_mode": Config.DEMO_MODE,
        "splunk_configured": Config.is_splunk_configured(),
    }
