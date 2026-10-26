"""
Graph Service Module for DNS Query and Analysis Tool
Generates high-resolution Matplotlib charts on the Python Flask backend.
Charts are saved as PNG images into static/generated/ and rendered directly in Jinja2 templates.
"""

import os
from typing import Dict, Any, List
import matplotlib

# Set non-interactive Agg backend before importing pyplot for thread-safe headless web server
matplotlib.use("Agg")
import matplotlib.pyplot as plt

STATIC_GEN_DIR = os.path.join(os.path.dirname(__file__), "static", "generated")

# Theme styling constants
THEME_DARK_BLUE = "#0f2b48"
THEME_CYAN = "#00b4d8"
THEME_TEAL = "#06d6a0"
THEME_AMBER = "#f59e0b"
THEME_RED = "#ef4444"
THEME_BG = "#ffffff"
THEME_CARD_BG = "#f8fafc"
THEME_GRID = "#e2e8f0"
THEME_TEXT = "#1e293b"


def ensure_generated_dir() -> None:
    """Ensures that the static/generated directory exists."""
    os.makedirs(STATIC_GEN_DIR, exist_ok=True)


def _draw_empty_placeholder(filename: str, message: str = "No DNS Query Data Available Yet") -> str:
    """Draws a clean, styled placeholder image when insufficient data exists."""
    ensure_generated_dir()
    filepath = os.path.join(STATIC_GEN_DIR, filename)

    fig, ax = plt.subplots(figsize=(7, 4.2), dpi=130)
    fig.patch.set_facecolor(THEME_CARD_BG)
    ax.set_facecolor(THEME_CARD_BG)

    ax.text(
        0.5, 0.55, message,
        ha="center", va="center", fontsize=13, fontweight="bold",
        color=THEME_DARK_BLUE, transform=ax.transAxes
    )
    ax.text(
        0.5, 0.42, "Perform DNS queries on the Query or Dashboard page to populate this chart.",
        ha="center", va="center", fontsize=9.5, color="#64748b",
        transform=ax.transAxes
    )

    ax.set_xticks([])
    ax.set_yticks([])
    for spine in ax.spines.values():
        spine.set_visible(False)

    plt.tight_layout()
    plt.savefig(filepath, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close(fig)
    return filename


def generate_response_time_bar_chart(queries: List[Dict[str, Any]]) -> str:
    """
    1. Bar chart comparing DNS response times across domains / recent queries.
    """
    ensure_generated_dir()
    filename = "response_times_bar.png"
    filepath = os.path.join(STATIC_GEN_DIR, filename)

    if not queries:
        return _draw_empty_placeholder(filename, "No Query Response Time Data Yet")

    # Use the most recent 10-12 queries
    data = queries[-12:]
    labels = [f"{q['domain'][:14]}.. ({q['record_type']})" if len(q['domain']) > 14 else f"{q['domain']} ({q['record_type']})" for q in data]
    times = [q["response_time_ms"] for q in data]
    statuses = [q["status"] for q in data]

    # Semantic color coding based on status
    colors = []
    for s in statuses:
        if s == "SUCCESS":
            colors.append(THEME_CYAN)
        elif s == "NO_ANSWER":
            colors.append("#60a5fa")
        elif s == "NXDOMAIN":
            colors.append(THEME_AMBER)
        else:
            colors.append(THEME_RED)

    fig, ax = plt.subplots(figsize=(8.5, 4.6), dpi=130)
    fig.patch.set_facecolor(THEME_BG)
    ax.set_facecolor(THEME_BG)

    bars = ax.bar(range(len(labels)), times, color=colors, width=0.6, edgecolor=THEME_DARK_BLUE, linewidth=0.8, zorder=3)

    # Add numeric labels on top of bars
    for bar in bars:
        h = bar.get_height()
        ax.annotate(
            f"{h:.1f}ms",
            xy=(bar.get_x() + bar.get_width() / 2, h),
            xytext=(0, 4),
            textcoords="offset points",
            ha="center", va="bottom",
            fontsize=8.5, fontweight="600", color=THEME_TEXT
        )

    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=35, ha="right", fontsize=9, color=THEME_TEXT)
    ax.set_ylabel("Response Time (ms)", fontsize=10, fontweight="bold", color=THEME_DARK_BLUE)
    ax.set_title("DNS Response Time by Query (Recent)", fontsize=12, fontweight="bold", color=THEME_DARK_BLUE, pad=12)

    ax.grid(axis="y", linestyle="--", alpha=0.6, color=THEME_GRID, zorder=0)
    for spine in ["top", "right"]:
        ax.spines[spine].set_visible(False)
    ax.spines["left"].set_color(THEME_GRID)
    ax.spines["bottom"].set_color(THEME_GRID)

    plt.tight_layout()
    plt.savefig(filepath, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close(fig)
    return filename


def generate_response_time_line_chart(queries: List[Dict[str, Any]]) -> str:
    """
    2. Line graph showing response times across repeated/consecutive queries.
    """
    ensure_generated_dir()
    filename = "response_times_line.png"
    filepath = os.path.join(STATIC_GEN_DIR, filename)

    if not queries:
        return _draw_empty_placeholder(filename, "No Latency Trend Data Yet")

    data = queries[-20:]
    x_indices = list(range(1, len(data) + 1))
    times = [q["response_time_ms"] for q in data]
    avg_val = sum(times) / len(times) if times else 0.0

    fig, ax = plt.subplots(figsize=(8.5, 4.6), dpi=130)
    fig.patch.set_facecolor(THEME_BG)
    ax.set_facecolor(THEME_BG)

    # Line plot with markers
    ax.plot(
        x_indices, times,
        color=THEME_DARK_BLUE, linewidth=2.2, marker="o", markersize=6,
        markerfacecolor=THEME_CYAN, markeredgecolor=THEME_DARK_BLUE, markeredgewidth=1.5,
        label="Latency (ms)", zorder=4
    )

    # Fill area under curve
    ax.fill_between(x_indices, times, color=THEME_CYAN, alpha=0.18, zorder=2)

    # Average benchmark dashed line
    ax.axhline(avg_val, color=THEME_AMBER, linestyle="--", linewidth=1.5, label=f"Average ({avg_val:.1f}ms)", zorder=3)

    ax.set_xlabel("Query Sequence Index", fontsize=10, fontweight="bold", color=THEME_DARK_BLUE)
    ax.set_ylabel("Response Time (ms)", fontsize=10, fontweight="bold", color=THEME_DARK_BLUE)
    ax.set_title("Response Time Trend Over Consecutive Queries", fontsize=12, fontweight="bold", color=THEME_DARK_BLUE, pad=12)

    ax.grid(True, linestyle="--", alpha=0.6, color=THEME_GRID, zorder=0)
    ax.legend(frameon=True, facecolor=THEME_CARD_BG, edgecolor=THEME_GRID, fontsize=9)

    for spine in ["top", "right"]:
        ax.spines[spine].set_visible(False)
    ax.spines["left"].set_color(THEME_GRID)
    ax.spines["bottom"].set_color(THEME_GRID)

    plt.tight_layout()
    plt.savefig(filepath, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close(fig)
    return filename


def generate_success_rate_pie_chart(stats: Dict[str, Any]) -> str:
    """
    3. Donut / Pie chart showing successful and failed DNS queries.
    """
    ensure_generated_dir()
    filename = "success_rate_pie.png"
    filepath = os.path.join(STATIC_GEN_DIR, filename)

    total = stats.get("total_queries", 0)
    success = stats.get("successful_queries", 0)
    failed = stats.get("failed_queries", 0)

    if total == 0:
        return _draw_empty_placeholder(filename, "No Query Status Data Yet")

    labels = []
    sizes = []
    colors = []

    if success > 0:
        labels.append(f"Successful ({success})")
        sizes.append(success)
        colors.append(THEME_TEAL)

    if failed > 0:
        labels.append(f"Failed / Error ({failed})")
        sizes.append(failed)
        colors.append(THEME_RED)

    fig, ax = plt.subplots(figsize=(6.5, 4.6), dpi=130)
    fig.patch.set_facecolor(THEME_BG)
    ax.set_facecolor(THEME_BG)

    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, colors=colors, autopct="%1.1f%%",
        startangle=140, pctdistance=0.75,
        wedgeprops=dict(width=0.45, edgecolor=THEME_BG, linewidth=2),
        textprops=dict(color=THEME_TEXT, fontsize=9.5, fontweight="600")
    )

    for autotext in autotexts:
        autotext.set_color("white")
        autotext.set_fontsize(10)
        autotext.set_fontweight("bold")

    # Center label displaying total queries
    ax.text(
        0, 0, f"{total}\nTotal",
        ha="center", va="center", fontsize=12, fontweight="bold", color=THEME_DARK_BLUE
    )

    ax.set_title("DNS Query Success vs Failure Rate", fontsize=12, fontweight="bold", color=THEME_DARK_BLUE, pad=14)

    plt.tight_layout()
    plt.savefig(filepath, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close(fig)
    return filename


def generate_record_distribution_bar_chart(stats: Dict[str, Any]) -> str:
    """
    4. Bar chart displaying the number of records by type (A, AAAA, CNAME, MX).
    """
    ensure_generated_dir()
    filename = "record_distribution_bar.png"
    filepath = os.path.join(STATIC_GEN_DIR, filename)

    type_counts = stats.get("type_distribution", {})
    if not type_counts or sum(type_counts.values()) == 0:
        return _draw_empty_placeholder(filename, "No Record Distribution Data Yet")

    standard_types = ["A", "AAAA", "CNAME", "MX"]
    labels = []
    counts = []

    for t in standard_types:
        labels.append(t)
        counts.append(type_counts.get(t, 0))

    palette = [THEME_DARK_BLUE, THEME_CYAN, THEME_TEAL, THEME_AMBER]

    fig, ax = plt.subplots(figsize=(7, 4.6), dpi=130)
    fig.patch.set_facecolor(THEME_BG)
    ax.set_facecolor(THEME_BG)

    bars = ax.bar(labels, counts, color=palette, width=0.55, edgecolor=THEME_DARK_BLUE, linewidth=0.8, zorder=3)

    for bar in bars:
        h = bar.get_height()
        ax.annotate(
            f"{int(h)}",
            xy=(bar.get_x() + bar.get_width() / 2, h),
            xytext=(0, 4),
            textcoords="offset points",
            ha="center", va="bottom",
            fontsize=9.5, fontweight="bold", color=THEME_TEXT
        )

    ax.set_ylabel("Number of Queries", fontsize=10, fontweight="bold", color=THEME_DARK_BLUE)
    ax.set_title("DNS Queries by Record Type", fontsize=12, fontweight="bold", color=THEME_DARK_BLUE, pad=12)

    ax.grid(axis="y", linestyle="--", alpha=0.6, color=THEME_GRID, zorder=0)
    for spine in ["top", "right"]:
        ax.spines[spine].set_visible(False)
    ax.spines["left"].set_color(THEME_GRID)
    ax.spines["bottom"].set_color(THEME_GRID)

    plt.tight_layout()
    plt.savefig(filepath, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close(fig)
    return filename


def generate_comparison_chart(comparison_data: Dict[str, Any]) -> str:
    """
    Generates a horizontal bar chart comparing average response times of multiple domains.
    """
    ensure_generated_dir()
    filename = "domain_comparison.png"
    filepath = os.path.join(STATIC_GEN_DIR, filename)

    summaries = comparison_data.get("domain_summaries", [])
    if not summaries:
        return _draw_empty_placeholder(filename, "No Comparison Data Available")

    # Sort domains by average response time ascending (fastest at top)
    sorted_summaries = sorted(summaries, key=lambda x: x["avg_time"], reverse=True)
    domains = [s["domain"] for s in sorted_summaries]
    avg_times = [s["avg_time"] for s in sorted_summaries]

    fig, ax = plt.subplots(figsize=(8.5, max(3.8, len(domains) * 0.55)), dpi=130)
    fig.patch.set_facecolor(THEME_BG)
    ax.set_facecolor(THEME_BG)

    bars = ax.barh(domains, avg_times, color=THEME_CYAN, edgecolor=THEME_DARK_BLUE, height=0.55, zorder=3)

    for bar in bars:
        w = bar.get_width()
        ax.annotate(
            f"{w:.1f} ms",
            xy=(w, bar.get_y() + bar.get_height() / 2),
            xytext=(5, 0),
            textcoords="offset points",
            ha="left", va="center",
            fontsize=9, fontweight="bold", color=THEME_TEXT
        )

    ax.set_xlabel("Average Response Time (ms)", fontsize=10, fontweight="bold", color=THEME_DARK_BLUE)
    ax.set_title("Domain Average Latency Comparison", fontsize=12, fontweight="bold", color=THEME_DARK_BLUE, pad=12)

    ax.grid(axis="x", linestyle="--", alpha=0.6, color=THEME_GRID, zorder=0)
    for spine in ["top", "right"]:
        ax.spines[spine].set_visible(False)
    ax.spines["left"].set_color(THEME_GRID)
    ax.spines["bottom"].set_color(THEME_GRID)

    plt.tight_layout()
    plt.savefig(filepath, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close(fig)
    return filename


def generate_all_dashboard_graphs(stats: Dict[str, Any], recent_queries: List[Dict[str, Any]]) -> Dict[str, str]:
    """Generates all four required charts for the dashboard and graphs page."""
    return {
        "bar_chart": generate_response_time_bar_chart(recent_queries),
        "line_chart": generate_response_time_line_chart(recent_queries),
        "pie_chart": generate_success_rate_pie_chart(stats),
        "distribution_chart": generate_record_distribution_bar_chart(stats)
    }
