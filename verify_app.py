"""
Comprehensive Test and Verification Suite for DNS Query and Analysis Tool
Tests all database operations, DNS resolutions, Matplotlib chart generations,
Scapy packet dissections, and Flask routes.
"""

import os
import sys
import io

print("=" * 60)
print("  Running DNS Query & Analysis Tool Verification Suite")
print("=" * 60)

# 1. Test Database Operations
print("\n[1/5] Testing Database Module (database.py)...")
import database
database.init_db()

# Insert test records
batch_id = "test_batch_01"
id1 = database.save_query_result(
    batch_id=batch_id,
    domain="google.com",
    record_type="A",
    answers="142.250.190.46",
    mx_priority=None,
    response_time_ms=21.45,
    status="SUCCESS",
    resolver="Google DNS (8.8.8.8)"
)

id2 = database.save_query_result(
    batch_id=batch_id,
    domain="google.com",
    record_type="MX",
    answers="smtp.google.com (Priority: 10)",
    mx_priority="10: smtp.google.com",
    response_time_ms=25.80,
    status="SUCCESS",
    resolver="Google DNS (8.8.8.8)"
)

id3 = database.save_query_result(
    batch_id=batch_id,
    domain="non-existent-domain-test-xyz.org",
    record_type="A",
    answers="",
    mx_priority=None,
    response_time_ms=35.12,
    status="NXDOMAIN",
    error_message="Domain does not exist.",
    resolver="System Default"
)

# Test query retrieval
rec = database.get_query_by_id(id1)
assert rec is not None, "Failed to retrieve query by ID"
assert rec["domain"] == "google.com"

# Test filtered history
items, total, pages = database.get_filtered_history(search="google", record_type="A")
assert total >= 1, "Failed to search history"

# Test stats
stats = database.get_dashboard_statistics()
assert stats["total_queries"] >= 3, "Total queries count mismatch"
assert stats["successful_queries"] >= 2, "Successful queries count mismatch"
print(f"  OK: Database verified. Total queries: {stats['total_queries']}, Avg time: {stats['avg_response_time']}ms")

# 2. Test DNS Service
print("\n[2/5] Testing DNS Service (dns_service.py)...")
import dns_service

# Domain validation tests
valid, clean, err = dns_service.clean_and_validate_domain("https://GOOGLE.COM/search?q=test")
assert valid and clean == "google.com", f"Domain cleaning failed: {clean}"

invalid, _, err = dns_service.clean_and_validate_domain("invalid..domain..com")
assert not invalid, "Domain validation should have rejected consecutive dots"

# DNS record resolution test (live query)
print("  Resolving A record for google.com...")
res_a = dns_service.resolve_single_record("google.com", "A")
print(f"  Result: Status={res_a['status']}, Latency={res_a['response_time_ms']}ms, Answers={res_a['answers_text']}")
assert res_a["status"] == "SUCCESS", f"DNS query failed: {res_a}"

# Multi-domain comparison test
print("  Comparing domains: google.com, github.com...")
cmp_res = dns_service.compare_multiple_domains(["google.com", "github.com"], ["A"])
assert len(cmp_res["domain_summaries"]) >= 2, "Domain comparison failed"
print(f"  OK: Comparison completed. Fastest domain: {cmp_res['fastest_domain']['domain']}")

# 3. Test Graph Service (Matplotlib)
print("\n[3/5] Testing Graph Generation (graph_service.py)...")
import graph_service
recent = database.get_recent_queries_for_graph(10)
charts = graph_service.generate_all_dashboard_graphs(stats, recent)

for chart_name, file_name in charts.items():
    p = os.path.join(graph_service.STATIC_GEN_DIR, file_name)
    assert os.path.exists(p) and os.path.getsize(p) > 0, f"Chart {file_name} missing or empty"
    print(f"  OK: Generated {file_name} ({os.path.getsize(p)} bytes)")

# Test comparison chart
cmp_chart = graph_service.generate_comparison_chart(cmp_res)
p_cmp = os.path.join(graph_service.STATIC_GEN_DIR, cmp_chart)
assert os.path.exists(p_cmp) and os.path.getsize(p_cmp) > 0, "Comparison chart missing"
print(f"  OK: Generated {cmp_chart} ({os.path.getsize(p_cmp)} bytes)")

# 4. Test Packet Analyzer
print("\n[4/5] Testing Packet Analyzer (packet_analyzer.py)...")
import packet_analyzer
sample_file = os.path.join("uploads", "test_verification.pcap")
packet_analyzer.generate_sample_pcap(sample_file)
assert os.path.exists(sample_file), "Sample PCAP generation failed"

pcap_analysis = packet_analyzer.parse_pcap_packets(sample_file)
assert "error" not in pcap_analysis, f"PCAP parsing error: {pcap_analysis.get('error')}"
assert pcap_analysis["total_dns_packets"] == 6, f"Expected 6 DNS packets, got {pcap_analysis['total_dns_packets']}"
print(f"  OK: PCAP parsed successfully. Found {pcap_analysis['total_dns_packets']} DNS packets.")

# Clean up test capture
if os.path.exists(sample_file):
    os.remove(sample_file)

# 5. Test Flask Application Routes
print("\n[5/5] Testing Flask Routes and Endpoints (app.py)...")
from app import app
client = app.test_client()

routes_to_test = [
    ("/", 200, "Dashboard"),
    ("/dns-query", 200, "DNS Query Form"),
    ("/compare", 200, "Compare Page"),
    ("/history", 200, "History Page"),
    (f"/history/{id1}", 200, "Query Details Page"),
    ("/graphs", 200, "Visual Analytics Page"),
    ("/wireshark", 200, "Wireshark Page"),
    ("/wireshark/sample", 200, "Download Sample PCAP"),
    ("/export/csv", 200, "CSV Export"),
    ("/export/json", 200, "JSON Export"),
    ("/about", 200, "About Project"),
    ("/nonexistent_page", 404, "Custom 404 Error Handler")
]

for url, expected_code, label in routes_to_test:
    response = client.get(url)
    assert response.status_code == expected_code, f"{label} returned {response.status_code}, expected {expected_code}"
    print(f"  OK: GET {url:<25} -> {response.status_code} ({label})")

# Test POST-Redirect-GET on /dns-query
post_res = client.post("/dns-query", data={
    "domain": "google.com",
    "record_types": ["A", "MX"],
    "resolver": "System Default"
}, follow_redirects=False)

assert post_res.status_code == 302, f"POST /dns-query expected 302 redirect, got {post_res.status_code}"
redirect_url = post_res.headers.get("Location")
print(f"  OK: POST /dns-query -> 302 Redirect to {redirect_url} (POST-Redirect-GET Pattern Verified)")

# Follow redirect to /results
results_res = client.get(redirect_url)
assert results_res.status_code == 200, f"GET {redirect_url} failed with {results_res.status_code}"
assert b"Authoritative DNS Answers" in results_res.data
print(f"  OK: Followed redirect to results page successfully.")

print("\n" + "=" * 60)
print("  ALL TESTS PASSED! Project is completely verified & ready.")
print("=" * 60)
