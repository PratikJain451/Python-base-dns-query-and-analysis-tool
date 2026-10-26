"""
Main Flask Application for DNS Query and Analysis Tool
Implements routing, request handling, input validation, POST-Redirect-GET pattern,
CSV/JSON export, PCAP file uploads, and error handlers.
"""

import os
import sys
import socket
import uuid
import time
import io
import csv
import json
from datetime import datetime
from typing import List, Dict, Any

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    send_file,
    Response,
    abort
)
from werkzeug.utils import secure_filename

import database
import dns_service
import graph_service
import packet_analyzer

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dns_analysis_super_secret_key_2026")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB max upload
app.config["UPLOAD_FOLDER"] = os.path.join(os.path.dirname(__file__), "uploads")

# Ensure required runtime directories exist at startup
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(os.path.join(app.root_path, "static", "generated"), exist_ok=True)
os.makedirs(os.path.join(app.root_path, "instance"), exist_ok=True)

# Initialize SQLite database schema
database.init_db()


@app.context_processor
def inject_global_vars():
    """Provides common variables across all Jinja2 templates."""
    return {
        "current_year": datetime.now().year,
        "graph_version": int(time.time()),
        "supported_record_types": dns_service.SUPPORTED_RECORD_TYPES
    }


# ==========================================
# 1. Dashboard Route
# ==========================================
@app.route("/", methods=["GET"])
def index():
    """
    Renders the modern Dashboard featuring:
    - Overview metrics (Total, Successful, Failed queries, Avg response time)
    - Quick search form with example domains
    - Recent queries table
    - Generated Matplotlib charts
    """
    stats = database.get_dashboard_statistics()
    recent_queries_graph = database.get_recent_queries_for_graph(limit=15)

    # Automatically generate / refresh charts with real DB data
    graph_service.generate_all_dashboard_graphs(stats, recent_queries_graph)

    return render_template(
        "index.html",
        stats=stats,
        recent_queries=stats.get("recent_queries", []),
        page_title="Dashboard - DNS Query & Analysis Tool"
    )


# ==========================================
# 2. DNS Query Routes (POST-Redirect-GET)
# ==========================================
@app.route("/dns-query", methods=["GET", "POST"])
def dns_query():
    """
    Handles single-domain DNS queries.
    GET: Displays the query configuration form.
    POST: Validates input, executes DNS queries, logs to SQLite, updates graphs,
          and redirects to results page (POST-Redirect-GET pattern).
    """
    if request.method == "POST":
        raw_domain = request.form.get("domain", "")
        selected_types = request.form.getlist("record_types")
        resolver_choice = request.form.get("resolver", "System Default")

        # Fallback if no types checked
        if not selected_types:
            selected_types = ["A"]

        # Server-side validation
        is_valid, domain, error_msg = dns_service.clean_and_validate_domain(raw_domain)
        if not is_valid:
            flash(error_msg, "danger")
            return render_template(
                "dns_query.html",
                domain=raw_domain,
                selected_types=selected_types,
                resolver_choice=resolver_choice,
                page_title="Perform DNS Query"
            )

        # Generate unique batch ID
        batch_id = uuid.uuid4().hex[:12]

        # Execute queries sequentially
        results = dns_service.resolve_domain_records(
            domain=domain,
            record_types=selected_types,
            resolver_ip=resolver_choice
        )

        # Save results in SQLite
        database.save_batch_results(results, batch_id)

        # Regenerate graphs with fresh data
        stats = database.get_dashboard_statistics()
        recent_for_graph = database.get_recent_queries_for_graph(limit=15)
        graph_service.generate_all_dashboard_graphs(stats, recent_for_graph)

        # Store in session and redirect to avoid duplicate submissions on refresh
        session["last_batch_id"] = batch_id
        flash(f"DNS queries for '{domain}' completed successfully.", "success")
        return redirect(url_for("results", batch_id=batch_id))

    # Pre-fill example if passed via query string (e.g. from Dashboard quick-links)
    prefill_domain = request.args.get("domain", "")
    return render_template(
        "dns_query.html",
        domain=prefill_domain,
        selected_types=["A", "AAAA", "CNAME", "MX"],
        resolver_choice="System Default",
        page_title="Perform DNS Query"
    )


@app.route("/results", methods=["GET"])
def results():
    """
    Displays the detailed results table for a completed query batch.
    """
    batch_id = request.args.get("batch_id") or session.get("last_batch_id")
    if not batch_id:
        flash("No recent query results found. Please perform a DNS query first.", "info")
        return redirect(url_for("dns_query"))

    batch_records = database.get_queries_by_batch(batch_id)
    if not batch_records:
        flash("Query batch not found or session expired.", "warning")
        return redirect(url_for("dns_query"))

    domain_name = batch_records[0]["domain"] if batch_records else "Domain"
    resolver_used = batch_records[0]["resolver"] if batch_records else "System Default"

    # Compute batch summary metrics
    total_time = sum(r["response_time_ms"] for r in batch_records)
    avg_time = round(total_time / len(batch_records), 2) if batch_records else 0.0
    success_count = sum(1 for r in batch_records if r["status"] == "SUCCESS")

    return render_template(
        "results.html",
        records=batch_records,
        batch_id=batch_id,
        domain_name=domain_name,
        resolver_used=resolver_used,
        avg_time=avg_time,
        success_count=success_count,
        total_count=len(batch_records),
        page_title=f"Query Results for {domain_name}"
    )


# ==========================================
# 3. Multi-Domain Comparison
# ==========================================
@app.route("/compare", methods=["GET", "POST"])
def compare():
    """
    Allows side-by-side comparison of multiple domain names.
    Measures response times, min/max/average stats, and generates comparison chart.
    """
    comparison_data = None
    domains_text = ""
    selected_types = ["A", "MX"]

    if request.method == "POST":
        domains_text = request.form.get("domains", "")
        selected_types = request.form.getlist("record_types")
        resolver_choice = request.form.get("resolver", "System Default")

        if not selected_types:
            selected_types = ["A"]

        # Parse domains line by line
        raw_domains = [line.strip() for line in domains_text.splitlines() if line.strip()]

        if not raw_domains:
            flash("Please enter at least one valid domain name to compare.", "warning")
        elif len(raw_domains) > 10:
            flash("Maximum of 10 domains allowed per comparison request.", "warning")
            raw_domains = raw_domains[:10]

        if raw_domains:
            comparison_data = dns_service.compare_multiple_domains(
                domains_list=raw_domains,
                record_types=selected_types,
                resolver_ip=resolver_choice
            )

            # Generate comparison chart
            if comparison_data.get("domain_summaries"):
                graph_service.generate_comparison_chart(comparison_data)

            # Also record queries in history database under a batch
            batch_id = uuid.uuid4().hex[:12]
            database.save_batch_results(comparison_data.get("results", []), batch_id)

    return render_template(
        "compare.html",
        comparison=comparison_data,
        domains_text=domains_text,
        selected_types=selected_types,
        page_title="Multiple-Domain Comparison"
    )


# ==========================================
# 4. Graphical Representation (Matplotlib)
# ==========================================
@app.route("/graphs", methods=["GET"])
def graphs():
    """
    Displays the dedicated graphical analysis page featuring 4 Matplotlib charts:
    1. Response time bar chart
    2. Response time trend line graph
    3. Success vs Failure pie chart
    4. Query distribution by record type
    """
    stats = database.get_dashboard_statistics()
    recent_queries = database.get_recent_queries_for_graph(limit=20)
    chart_files = graph_service.generate_all_dashboard_graphs(stats, recent_queries)

    return render_template(
        "graphs.html",
        stats=stats,
        charts=chart_files,
        total_queries=stats.get("total_queries", 0),
        page_title="Visual Analytics & Charts"
    )


# ==========================================
# 5. Query History & Query Details
# ==========================================
@app.route("/history", methods=["GET"])
def history():
    """
    Displays query history stored in SQLite with search, record-type filtering,
    status filtering, sorting, and pagination.
    """
    search_query = request.args.get("q", "").strip()
    record_type = request.args.get("type", "").strip()
    status_filter = request.args.get("status", "").strip()
    sort_by = request.args.get("sort", "date_desc").strip()

    try:
        page = int(request.args.get("page", 1))
    except ValueError:
        page = 1

    per_page = 12
    records, total_count, total_pages = database.get_filtered_history(
        search=search_query,
        record_type=record_type,
        status=status_filter,
        sort_by=sort_by,
        page=page,
        per_page=per_page
    )

    return render_template(
        "history.html",
        records=records,
        total_count=total_count,
        total_pages=total_pages,
        current_page=page,
        search_query=search_query,
        record_type=record_type,
        status_filter=status_filter,
        sort_by=sort_by,
        page_title="DNS Query History"
    )


@app.route("/history/<int:query_id>", methods=["GET"])
def query_details(query_id: int):
    """
    Displays detailed technical breakdown of an individual DNS query.
    """
    record = database.get_query_by_id(query_id)
    if not record:
        flash(f"Query record #{query_id} not found in database.", "danger")
        return redirect(url_for("history"))

    explanation = dns_service.RECORD_DESCRIPTIONS.get(record["record_type"], "Standard DNS Record")

    return render_template(
        "query_details.html",
        record=record,
        explanation=explanation,
        page_title=f"Query #{query_id} - {record['domain']}"
    )


@app.route("/history/clear", methods=["POST"])
def clear_history():
    """
    Clears all saved DNS query history after user confirmation.
    """
    deleted_count = database.clear_all_history()
    flash(f"Query history cleared successfully. Removed {deleted_count} record(s).", "info")
    return redirect(url_for("history"))


# ==========================================
# 6. CSV and JSON Data Export
# ==========================================
@app.route("/export/csv", methods=["GET"])
def export_csv():
    """
    Generates and downloads a CSV file containing all DNS query records
    using Python's built-in csv module.
    """
    records = database.get_all_records_for_export()
    output = io.StringIO()
    writer = csv.writer(output)

    # CSV Header
    writer.writerow([
        "Query ID",
        "Batch ID",
        "Domain Name",
        "Record Type",
        "DNS Answer(s)",
        "MX Priority",
        "Response Time (ms)",
        "Query Status",
        "Error Message",
        "DNS Resolver",
        "Timestamp"
    ])

    for r in records:
        writer.writerow([
            r["id"],
            r["batch_id"],
            r["domain"],
            r["record_type"],
            r["answers"],
            r["mx_priority"],
            r["response_time_ms"],
            r["status"],
            r["error_message"],
            r["resolver"],
            r["created_at"]
        ])

    csv_data = output.getvalue()
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"dns_query_history_{timestamp_str}.csv"

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.route("/export/json", methods=["GET"])
def export_json():
    """
    Generates and downloads a JSON file containing all DNS query records
    using Python's built-in json module.
    """
    records = database.get_all_records_for_export()
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"dns_query_history_{timestamp_str}.json"

    export_payload = {
        "tool": "DNS Query and Analysis Tool",
        "export_timestamp": datetime.now().isoformat(),
        "total_records": len(records),
        "queries": records
    }

    json_str = json.dumps(export_payload, indent=2, default=str)

    return Response(
        json_str,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# ==========================================
# 7. Wireshark Packet Analysis
# ==========================================
@app.route("/wireshark", methods=["GET", "POST"])
def wireshark():
    """
    Dedicated Wireshark Packet Analysis page.
    Includes Wireshark capture tutorial, display filter cheatsheet,
    PCAP/PCAPNG file upload handling, and Scapy packet inspection table.
    """
    analysis_data = None

    if request.method == "POST":
        if "pcap_file" not in request.files:
            flash("No file part provided in request.", "warning")
            return redirect(request.url)

        file = request.files["pcap_file"]
        if file.filename == "":
            flash("Please choose a PCAP or PCAPNG file to upload.", "warning")
            return redirect(request.url)

        if not packet_analyzer.is_allowed_file(file.filename):
            flash("Invalid file format. Please upload a .pcap or .pcapng file.", "danger")
            return redirect(request.url)

        filename = secure_filename(file.filename)
        unique_name = f"{uuid.uuid4().hex[:8]}_{filename}"
        saved_path = os.path.join(app.config["UPLOAD_FOLDER"], unique_name)

        try:
            file.save(saved_path)
            analysis_data = packet_analyzer.parse_pcap_packets(saved_path)

            if "error" in analysis_data:
                flash(analysis_data["error"], "danger")
                analysis_data = None
            else:
                flash(f"Successfully analyzed '{filename}'. Found {analysis_data.get('total_dns_packets', 0)} DNS packet(s).", "success")
        except Exception as exc:
            flash(f"Failed to process packet capture: {str(exc)}", "danger")
        finally:
            # Clean up uploaded file safely to avoid storing user uploads indefinitely
            if os.path.exists(saved_path):
                try:
                    os.remove(saved_path)
                except OSError:
                    pass

    return render_template(
        "wireshark.html",
        analysis=analysis_data,
        page_title="Wireshark Packet Analysis"
    )


@app.route("/wireshark/sample", methods=["GET"])
def download_sample_pcap():
    """
    Generates and downloads a valid test PCAP capture file with sample DNS queries and responses.
    """
    sample_path = os.path.join(app.config["UPLOAD_FOLDER"], "sample_dns_capture.pcap")
    packet_analyzer.generate_sample_pcap(sample_path)
    return send_file(
        sample_path,
        as_attachment=True,
        download_name="sample_dns_capture.pcap",
        mimetype="application/vnd.tcpdump.pcap"
    )


# ==========================================
# 8. About & Project Documentation Page
# ==========================================
@app.route("/about", methods=["GET"])
def about():
    """
    Renders the comprehensive project report documentation suitable for
    a Computer Science Engineering presentation, project viva, and submission.
    """
    return render_template(
        "about.html",
        page_title="About Project - DNS Query & Analysis Tool"
    )


# ==========================================
# 9. Error Handlers
# ==========================================
@app.errorhandler(404)
def page_not_found(e):
    return render_template(
        "error.html",
        error_code=404,
        error_title="Page Not Found",
        error_message="The requested URL was not found on this server. Please check the address or return to the Dashboard."
    ), 404


@app.errorhandler(413)
def file_too_large(e):
    return render_template(
        "error.html",
        error_code=413,
        error_title="File Too Large",
        error_message="The uploaded packet capture file exceeds the maximum allowed limit of 16 MB. Please upload a smaller capture."
    ), 413


@app.errorhandler(500)
def internal_server_error(e):
    return render_template(
        "error.html",
        error_code=500,
        error_title="Internal Server Error",
        error_message="An unexpected server error occurred while processing your request. Please try again or return to the Dashboard."
    ), 500


def get_local_ip() -> str:
    """Detect the machine's primary local IP address on Wi-Fi or Ethernet."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    local_ip = get_local_ip()

    print("=" * 68)
    print("  DNS Query and Analysis Tool - Flask Server Starting")
    print(f"  * Local Machine:       http://127.0.0.1:{port}")
    if local_ip != "127.0.0.1":
        print(f"  * Other Devices (LAN): http://{local_ip}:{port}")
    print("  Press Ctrl+C to stop the server.")
    print("=" * 68)

    # host="0.0.0.0" allows connections from other devices on the same network
    app.run(host="0.0.0.0", port=port, debug=True)

