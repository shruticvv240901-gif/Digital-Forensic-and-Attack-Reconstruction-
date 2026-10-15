"""
JSON API routes for diagnostic checks, Splunk SPL integration, timeline reconstruction, and forensic reporting.
"""

from datetime import datetime
from flask import Blueprint, jsonify, request, send_file
from app.services.splunk_service import SplunkService
from app.services.timeline_service import TimelineReconstructionService
from app.services.report_service import ForensicReportService
from config import Config

api_bp = Blueprint("api", __name__, url_prefix="/api")


@api_bp.route("/splunk/test-connection", methods=["GET", "POST"])
def test_splunk_connection():
    """
    Executes a live health-check against the configured Splunk Enterprise instance.
    Returns JSON status with latency and server details if successful.
    """
    service = SplunkService()
    result = service.test_connection()
    return jsonify(result), 200


@api_bp.route("/splunk/status", methods=["GET"])
def splunk_status():
    """
    Returns current configuration status without initiating network requests.
    """
    return jsonify({
        "configured": Config.is_splunk_configured(),
        "demo_mode": Config.DEMO_MODE,
        "summary": Config.get_safe_summary(),
    })


@api_bp.route("/splunk/query-windows-logs", methods=["GET", "POST"])
def query_windows_logs():
    """
    Executes an SPL search against Splunk Enterprise to retrieve Windows Security Event logs.
    Supports filtering by Event ID (4624, 4625, 4672, 4720) and relative time range.

    Query Parameters / Body:
        event_id (str): 'all', '4624', '4625', '4672', '4720' (default: 'all')
        time_range (str): '-15m', '-1h', '-24h', '-7d', '0' (default: '-24h')
        limit (int): max results to return (default: 50, max: 200)
    """
    event_id = request.args.get("event_id") or (request.json.get("event_id") if request.is_json else None) or "all"
    time_range = request.args.get("time_range") or (request.json.get("time_range") if request.is_json else None) or "-24h"
    limit_raw = request.args.get("limit") or (request.json.get("limit") if request.is_json else None) or 50

    try:
        limit = min(max(int(limit_raw), 1), 200)
    except ValueError:
        limit = 50

    service = SplunkService()
    result = service.query_windows_security_events(
        event_id=event_id,
        time_range=time_range,
        limit=limit,
    )

    return jsonify(result), 200


@api_bp.route("/timeline/reconstruct", methods=["GET", "POST"])
def reconstruct_timeline():
    """
    Reconstructs an end-to-end attack timeline from security logs.
    """
    payload = request.get_json(silent=True) or {}
    reverse = payload.get("reverse", False) or (request.args.get("reverse", "false").lower() in ("true", "1", "yes"))
    events = payload.get("events")

    if events is None:
        event_id = request.args.get("event_id") or payload.get("event_id") or "all"
        time_range = request.args.get("time_range") or payload.get("time_range") or "-24h"
        limit_raw = request.args.get("limit") or payload.get("limit") or 100

        try:
            limit = min(max(int(limit_raw), 1), 200)
        except ValueError:
            limit = 100

        service = SplunkService()
        query_res = service.query_windows_security_events(
            event_id=event_id,
            time_range=time_range,
            limit=limit,
        )
        events = query_res.get("events", [])

    timeline_result = TimelineReconstructionService.reconstruct_attack_timeline(
        events=events,
        reverse=reverse,
    )

    return jsonify(timeline_result), 200


@api_bp.route("/report/summary", methods=["GET", "POST"])
def report_summary():
    """
    Generates a structured forensic investigation summary JSON.
    Uses transparent, rule-based forensic analysis engine.
    """
    payload = request.get_json(silent=True) or {}
    events = payload.get("events")

    if events is None:
        event_id = request.args.get("event_id") or payload.get("event_id") or "all"
        time_range = request.args.get("time_range") or payload.get("time_range") or "-24h"
        limit_raw = request.args.get("limit") or payload.get("limit") or 100

        try:
            limit = min(max(int(limit_raw), 1), 200)
        except ValueError:
            limit = 100

        service = SplunkService()
        query_res = service.query_windows_security_events(
            event_id=event_id,
            time_range=time_range,
            limit=limit,
        )
        events = query_res.get("events", [])

    timeline_result = TimelineReconstructionService.reconstruct_attack_timeline(events=events)
    summary_result = ForensicReportService.generate_investigation_summary(
        timeline_data=timeline_result,
        is_demo=Config.DEMO_MODE,
    )

    return jsonify({
        "success": True,
        "mode": "DEMO" if Config.DEMO_MODE else "LIVE",
        "summary": summary_result,
        "timeline_count": timeline_result.get("count", 0),
    }), 200


@api_bp.route("/report/export-pdf", methods=["GET"])
def export_pdf():
    """
    Generates and returns an exportable Digital Forensic Investigation PDF Report.
    """
    event_id = request.args.get("event_id", "all")
    time_range = request.args.get("time_range", "-24h")
    limit_raw = request.args.get("limit", 100)
    reverse = request.args.get("reverse", "false").lower() in ("true", "1", "yes")

    try:
        limit = min(max(int(limit_raw), 1), 200)
    except ValueError:
        limit = 100

    service = SplunkService()
    query_res = service.query_windows_security_events(
        event_id=event_id,
        time_range=time_range,
        limit=limit,
    )
    events = query_res.get("events", [])

    timeline_data = TimelineReconstructionService.reconstruct_attack_timeline(
        events=events,
        reverse=reverse,
    )
    summary_data = ForensicReportService.generate_investigation_summary(
        timeline_data=timeline_data,
        is_demo=Config.DEMO_MODE,
    )

    pdf_buffer = ForensicReportService.generate_pdf_report(
        timeline_data=timeline_data,
        summary_data=summary_data,
        is_demo=Config.DEMO_MODE,
    )

    timestamp_slug = datetime.now().strftime("%Y%m%d_%H%M%S")
    mode_prefix = "DEMO" if Config.DEMO_MODE else "LIVE"
    filename = f"Forensic_Report_{mode_prefix}_{timestamp_slug}.pdf"

    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )
