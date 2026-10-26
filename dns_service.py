"""
DNS Service Module for DNS Query and Analysis Tool
Performs DNS record resolution using dnspython, measures high-precision response time
using time.perf_counter(), validates domains, and handles all DNS error classes.
"""

import re
import time
from typing import List, Dict, Any, Tuple, Optional
import dns.resolver
import dns.exception
import dns.name


# Standard RFC 1123 hostname regex
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)

# Supported DNS record types
SUPPORTED_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX"]

# Record type educational explanations
RECORD_DESCRIPTIONS = {
    "A": "Maps a domain name to an IPv4 address (32-bit address, e.g., 142.250.190.46).",
    "AAAA": "Maps a domain name to an IPv6 address (128-bit address, e.g., 2607:f8b0:4005::200e).",
    "CNAME": "Canonical Name - specifies that one domain name is an alias of another domain.",
    "MX": "Mail Exchange - specifies the mail server responsible for accepting emails, with priority."
}


def clean_and_validate_domain(raw_domain: str) -> Tuple[bool, str, Optional[str]]:
    """
    Cleans domain input by stripping protocols, ports, slashes, and whitespace,
    then validates it according to standard RFC 1123 domain name rules.
    Returns: (is_valid, cleaned_domain, error_message)
    """
    if not raw_domain or not isinstance(raw_domain, str):
        return False, "", "Domain name cannot be empty."

    cleaned = raw_domain.strip().lower()

    # Strip URL schemes if user inadvertently pasted a URL
    if cleaned.startswith("http://"):
        cleaned = cleaned[7:]
    elif cleaned.startswith("https://"):
        cleaned = cleaned[8:]

    # Remove paths, queries, ports, and trailing slashes
    cleaned = cleaned.split("/")[0].split("?")[0].split(":")[0].strip()

    # Strip trailing dot if present for FQDN
    if cleaned.endswith("."):
        cleaned = cleaned[:-1]

    if not cleaned:
        return False, "", "Domain name is required."

    if len(cleaned) > 253:
        return False, cleaned, "Domain name exceeds maximum allowed length of 253 characters."

    # Verify each label length (max 63 octets)
    labels = cleaned.split(".")
    if len(labels) < 2:
        return False, cleaned, "Domain must contain at least a name and a top-level domain (e.g., example.com)."

    for label in labels:
        if not label:
            return False, cleaned, "Domain cannot have empty labels or consecutive dots."
        if len(label) > 63:
            return False, cleaned, f"Domain label '{label}' exceeds maximum 63 characters."
        if label.startswith("-") or label.endswith("-"):
            return False, cleaned, f"Domain label '{label}' cannot start or end with a hyphen."

    if not DOMAIN_REGEX.match(cleaned):
        return False, cleaned, "Invalid domain name syntax. Use alphanumeric characters and hyphens only."

    return True, cleaned, None


def get_configured_resolver(resolver_ip: Optional[str] = None, timeout: float = 3.0) -> Tuple[dns.resolver.Resolver, str]:
    """
    Configures a dnspython Resolver with safe timeouts and custom or system nameservers.
    """
    res = dns.resolver.Resolver()
    res.timeout = timeout
    res.lifetime = timeout + 1.0

    resolver_name = "System Default"
    if resolver_ip and resolver_ip.strip():
        clean_ip = resolver_ip.strip()
        if clean_ip in ["System Default", "Default", "OS Default"]:
            resolver_name = "System Default"
        elif clean_ip in ["8.8.8.8", "Google DNS (8.8.8.8)"]:
            res.nameservers = ["8.8.8.8"]
            resolver_name = "Google DNS (8.8.8.8)"
        elif clean_ip in ["1.1.1.1", "Cloudflare DNS (1.1.1.1)"]:
            res.nameservers = ["1.1.1.1"]
            resolver_name = "Cloudflare DNS (1.1.1.1)"
        elif clean_ip in ["9.9.9.9", "Quad9 DNS (9.9.9.9)"]:
            res.nameservers = ["9.9.9.9"]
            resolver_name = "Quad9 DNS (9.9.9.9)"
        else:
            try:
                # Validate custom IP format
                import ipaddress
                ipaddress.ip_address(clean_ip)
                res.nameservers = [clean_ip]
                resolver_name = f"Custom ({clean_ip})"
            except ValueError:
                # If invalid IP, keep system default
                resolver_name = "System Default"

    return res, resolver_name


def resolve_single_record(
    domain: str,
    record_type: str,
    resolver_ip: Optional[str] = None,
    timeout: float = 3.0
) -> Dict[str, Any]:
    """
    Executes a single DNS query using dnspython and measures response time with time.perf_counter().
    Distinguishes clearly between SUCCESS, NO_ANSWER (NODATA), NXDOMAIN, TIMEOUT, and ERROR.
    """
    record_type = record_type.upper()
    resolver, resolver_label = get_configured_resolver(resolver_ip, timeout)

    answers_list: List[str] = []
    mx_priority_list: List[str] = []
    status = "ERROR"
    error_message = ""
    duration_ms = 0.0

    start_time = time.perf_counter()
    try:
        query_response = resolver.resolve(domain, record_type)
        end_time = time.perf_counter()
        duration_ms = round((end_time - start_time) * 1000.0, 2)

        for rdata in query_response:
            if record_type == "A":
                answers_list.append(str(rdata.address))
            elif record_type == "AAAA":
                answers_list.append(str(rdata.address))
            elif record_type == "CNAME":
                answers_list.append(str(rdata.target).rstrip("."))
            elif record_type == "MX":
                target = str(rdata.exchange).rstrip(".")
                pref = str(rdata.preference)
                answers_list.append(f"{target} (Priority: {pref})")
                mx_priority_list.append(f"{pref}: {target}")
            else:
                answers_list.append(str(rdata))

        status = "SUCCESS" if answers_list else "NO_ANSWER"

    except dns.resolver.NXDOMAIN:
        end_time = time.perf_counter()
        duration_ms = round((end_time - start_time) * 1000.0, 2)
        status = "NXDOMAIN"
        error_message = f"Domain '{domain}' does not exist (NXDOMAIN)."

    except dns.resolver.NoAnswer:
        end_time = time.perf_counter()
        duration_ms = round((end_time - start_time) * 1000.0, 2)
        status = "NO_ANSWER"
        error_message = f"Domain exists, but no {record_type} records were found (NODATA)."

    except dns.resolver.Timeout:
        end_time = time.perf_counter()
        duration_ms = round((end_time - start_time) * 1000.0, 2)
        status = "TIMEOUT"
        error_message = f"Query timed out after {timeout} seconds."

    except dns.resolver.NoNameservers:
        end_time = time.perf_counter()
        duration_ms = round((end_time - start_time) * 1000.0, 2)
        status = "ERROR"
        error_message = "All nameservers failed to respond or refused query (SERVFAIL/REFUSED)."

    except Exception as exc:
        end_time = time.perf_counter()
        duration_ms = round((end_time - start_time) * 1000.0, 2)
        status = "ERROR"
        error_message = f"DNS resolution failed: {type(exc).__name__} - {str(exc)}"

    return {
        "domain": domain,
        "record_type": record_type,
        "answers": answers_list,
        "answers_text": ", ".join(answers_list) if answers_list else ("No records found" if status == "NO_ANSWER" else "None"),
        "mx_priority": ", ".join(mx_priority_list) if mx_priority_list else None,
        "response_time_ms": duration_ms,
        "status": status,
        "error_message": error_message,
        "resolver": resolver_label,
        "description": RECORD_DESCRIPTIONS.get(record_type, "DNS Record")
    }


def resolve_domain_records(
    domain: str,
    record_types: List[str],
    resolver_ip: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Resolves multiple selected record types for a given domain sequentially.
    """
    results = []
    for rtype in record_types:
        if rtype.upper() in SUPPORTED_RECORD_TYPES:
            res = resolve_single_record(domain, rtype.upper(), resolver_ip)
            results.append(res)
    return results


def compare_multiple_domains(
    domains_list: List[str],
    record_types: List[str],
    resolver_ip: Optional[str] = None
) -> Dict[str, Any]:
    """
    Executes DNS queries across multiple domains and selected record types.
    Calculates summary metrics: min, max, average response time, fastest domain,
    slowest domain, and structured table data.
    """
    # Enforce reasonable limit of up to 10 domains and valid record types
    cleaned_domains = []
    for d in domains_list[:10]:
        is_valid, cleaned, _ = clean_and_validate_domain(d)
        if is_valid and cleaned not in cleaned_domains:
            cleaned_domains.append(cleaned)

    valid_types = [t.upper() for t in record_types if t.upper() in SUPPORTED_RECORD_TYPES]
    if not valid_types:
        valid_types = ["A"]

    comparison_results: List[Dict[str, Any]] = []
    domain_summaries: Dict[str, Dict[str, Any]] = {}
    all_response_times: List[float] = []

    for domain in cleaned_domains:
        domain_times: List[float] = []
        domain_success = 0
        domain_failed = 0

        for rtype in valid_types:
            result = resolve_single_record(domain, rtype, resolver_ip)
            comparison_results.append(result)
            domain_times.append(result["response_time_ms"])
            all_response_times.append(result["response_time_ms"])

            if result["status"] == "SUCCESS":
                domain_success += 1
            else:
                domain_failed += 1

        avg_time = round(sum(domain_times) / len(domain_times), 2) if domain_times else 0.0
        min_time = round(min(domain_times), 2) if domain_times else 0.0
        max_time = round(max(domain_times), 2) if domain_times else 0.0

        domain_summaries[domain] = {
            "domain": domain,
            "min_time": min_time,
            "max_time": max_time,
            "avg_time": avg_time,
            "success_count": domain_success,
            "failed_count": domain_failed,
            "total_queries": len(domain_times)
        }

    # Determine fastest and slowest domain based on average response time
    fastest_domain = None
    slowest_domain = None
    if domain_summaries:
        sorted_by_avg = sorted(domain_summaries.values(), key=lambda x: x["avg_time"])
        fastest_domain = sorted_by_avg[0]
        slowest_domain = sorted_by_avg[-1]

    overall_avg = round(sum(all_response_times) / len(all_response_times), 2) if all_response_times else 0.0
    overall_min = round(min(all_response_times), 2) if all_response_times else 0.0
    overall_max = round(max(all_response_times), 2) if all_response_times else 0.0

    return {
        "domains": cleaned_domains,
        "record_types": valid_types,
        "results": comparison_results,
        "domain_summaries": list(domain_summaries.values()),
        "overall_min": overall_min,
        "overall_max": overall_max,
        "overall_avg": overall_avg,
        "fastest_domain": fastest_domain,
        "slowest_domain": slowest_domain,
        "total_queries_executed": len(comparison_results)
    }
