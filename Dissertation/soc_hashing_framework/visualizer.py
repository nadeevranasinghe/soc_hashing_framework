"""
Visualiser — Chart Generation & Reporting
==========================================
Generates comparative matplotlib charts for throughput, latency, CPU usage,
and integrity verification rates. Saves PNGs to the output/charts directory.
"""

import logging  # Standard logging for chart save confirmations
import os       # File path construction for saving charts and reports

import matplotlib                    # Core matplotlib library
matplotlib.use("Agg")               # Use non-interactive backend (no GUI window needed)
import matplotlib.pyplot as plt      # Pyplot interface for creating figures and axes
import matplotlib.ticker as mticker  # Custom tick formatting for axis labels

import config  # Centralised configuration (chart dir, algorithm display names)

logger = logging.getLogger(__name__)  # Create a module-level logger for this file

# ─── Colour palette (SOC-inspired dark theme) ────────────────────────
# Each algorithm gets a distinct colour for visual differentiation across all charts
_COLOURS = {
    "md5":      "#e74c3c",   # red — intentionally signals "less secure"
    "sha256":   "#3498db",   # blue
    "sha3_256": "#2ecc71",   # green
    "blake2b":  "#9b59b6",   # purple
    "blake3":   "#f39c12",   # orange — fast modern algorithm
}

_BG      = "#1e1e2f"  # Dark background colour for all charts
_FG      = "#ecf0f1"  # Light foreground colour for text and labels
_GRID    = "#3d3d56"  # Subtle grid line colour


def _apply_style(ax, title: str, ylabel: str):
    """Apply consistent dark-theme styling to an axes."""
    ax.set_facecolor(_BG)                # Set the plot area background colour
    ax.figure.patch.set_facecolor(_BG)   # Set the figure (outer) background colour
    ax.set_title(title, color=_FG, fontsize=14, fontweight="bold", pad=12)  # Chart title
    ax.set_ylabel(ylabel, color=_FG, fontsize=11)  # Y-axis label
    ax.tick_params(colors=_FG, labelsize=10)        # Style tick labels in foreground colour
    # Format y-axis values with comma separators and one decimal place
    ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda x, _: f"{x:,.1f}"))
    ax.grid(axis="y", color=_GRID, linewidth=0.5, alpha=0.6)  # Add subtle horizontal grid
    for spine in ax.spines.values():
        spine.set_visible(False)  # Remove the box border around the plot area


def _save(fig, name: str) -> str:
    """Save a figure to the charts directory as a PNG and close it."""
    path = os.path.join(config.CHART_DIR, f"{name}.png")  # Build the output file path
    fig.savefig(path, dpi=150, bbox_inches="tight", facecolor=_BG)  # Save at 150 DPI
    plt.close(fig)  # Close the figure to free memory
    logger.info("Chart saved → %s", path)
    return path  # Return the saved file path


# ─── Public chart generators ─────────────────────────────────────────

def chart_throughput(reports: list[dict]) -> str:
    """Bar chart of throughput (hashes / second) per algorithm."""
    fig, ax = plt.subplots(figsize=(8, 5))  # Create a new figure and axes
    names = [r["display_name"] for r in reports]  # Extract algorithm display names
    # Get throughput values (prefer mean_throughput from benchmark, fall back to profile)
    vals  = [r.get("mean_throughput_hps") or r.get("throughput_hps", 0) for r in reports]
    colours = [_COLOURS.get(r["algorithm"], "#95a5a6") for r in reports]  # Per-algorithm colour

    # Draw the bars with white edges for visual separation
    bars = ax.bar(names, vals, color=colours, edgecolor="white", linewidth=0.5, width=0.55)
    # Add value labels above each bar
    for bar, v in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(vals) * 0.02,
                f"{v:,.0f}", ha="center", va="bottom", color=_FG, fontsize=10, fontweight="bold")

    _apply_style(ax, "Hashing Throughput Comparison", "Hashes / second")
    return _save(fig, "throughput_comparison")


def chart_latency(reports: list[dict]) -> str:
    """Bar chart of average latency (µs) per algorithm."""
    fig, ax = plt.subplots(figsize=(8, 5))  # Create figure
    names = [r["display_name"] for r in reports]  # Algorithm names
    # Get latency values (prefer mean from benchmark, fall back to profile average)
    vals  = [r.get("mean_latency_us") or r.get("avg_latency_us", 0) for r in reports]
    colours = [_COLOURS.get(r["algorithm"], "#95a5a6") for r in reports]

    bars = ax.bar(names, vals, color=colours, edgecolor="white", linewidth=0.5, width=0.55)
    for bar, v in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(vals) * 0.02,
                f"{v:.1f}", ha="center", va="bottom", color=_FG, fontsize=10, fontweight="bold")

    _apply_style(ax, "Average Hashing Latency", "Latency (µs)")
    return _save(fig, "latency_comparison")


def chart_cpu(reports: list[dict]) -> str:
    """Bar chart of CPU utilisation (%) per algorithm."""
    fig, ax = plt.subplots(figsize=(8, 5))
    names = [r["display_name"] for r in reports]
    vals  = [r.get("cpu_percent", 0) for r in reports]  # CPU percentage from profiler
    colours = [_COLOURS.get(r["algorithm"], "#95a5a6") for r in reports]

    bars = ax.bar(names, vals, color=colours, edgecolor="white", linewidth=0.5, width=0.55)
    for bar, v in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(vals) * 0.02 if max(vals) > 0 else 0.5,
                f"{v:.1f}%", ha="center", va="bottom", color=_FG, fontsize=10, fontweight="bold")

    _apply_style(ax, "CPU Utilisation During Hashing", "CPU (%)")
    return _save(fig, "cpu_comparison")


def chart_integrity(tamper_results: dict[str, dict]) -> str:
    """Grouped bar chart showing tamper detection rates per algorithm."""
    fig, ax = plt.subplots(figsize=(8, 5))
    algorithms = list(tamper_results.keys())  # All algorithm identifiers
    names = [config.ALGORITHM_DISPLAY_NAMES.get(a, a) for a in algorithms]
    # Convert detection rate from decimal (0-1) to percentage (0-100)
    rates = [tamper_results[a]["detection_rate"] * 100 for a in algorithms]
    colours = [_COLOURS.get(a, "#95a5a6") for a in algorithms]

    bars = ax.bar(names, rates, color=colours, edgecolor="white", linewidth=0.5, width=0.55)
    for bar, v in zip(bars, rates):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                f"{v:.1f}%", ha="center", va="bottom", color=_FG, fontsize=10, fontweight="bold")

    ax.set_ylim(0, 115)  # Set y-axis limit to accommodate 100% labels
    _apply_style(ax, "Tamper Detection Rate by Algorithm", "Detection Rate (%)")
    return _save(fig, "integrity_comparison")


def chart_p95_latency(reports: list[dict]) -> str:
    """Bar chart of p95 latency per algorithm."""
    fig, ax = plt.subplots(figsize=(8, 5))
    names = [r["display_name"] for r in reports]
    vals  = [r.get("p95_latency_us", 0) for r in reports]  # 95th percentile latency
    colours = [_COLOURS.get(r["algorithm"], "#95a5a6") for r in reports]

    bars = ax.bar(names, vals, color=colours, edgecolor="white", linewidth=0.5, width=0.55)
    for bar, v in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(vals) * 0.02,
                f"{v:.1f}", ha="center", va="bottom", color=_FG, fontsize=10, fontweight="bold")

    _apply_style(ax, "P95 Hashing Latency", "Latency (µs)")
    return _save(fig, "p95_latency_comparison")


def chart_memory(reports: list[dict]) -> str:
    """Bar chart of memory usage (before / after / delta) per algorithm."""
    fig, ax = plt.subplots(figsize=(10, 5))
    names = [r["display_name"] for r in reports]
    before = [r.get("mem_before_mb", 0) for r in reports]  # RSS before hashing
    after  = [r.get("mem_after_mb", 0) for r in reports]   # RSS after hashing
    delta  = [r.get("mem_delta_mb", 0) for r in reports]   # Memory change

    x = range(len(names))  # X positions for grouped bars
    w = 0.25               # Width of each bar in the group
    # Draw three bar groups side by side: Before, After, Delta
    bars1 = ax.bar([i - w for i in x], before, w, label="Before", color="#3498db", edgecolor="white", linewidth=0.5)
    bars2 = ax.bar(list(x), after, w, label="After", color="#e74c3c", edgecolor="white", linewidth=0.5)
    bars3 = ax.bar([i + w for i in x], delta, w, label="Delta", color="#2ecc71", edgecolor="white", linewidth=0.5)
    ax.set_xticks(list(x))       # Position x-ticks at the centre of each group
    ax.set_xticklabels(names)    # Label x-ticks with algorithm names
    ax.legend(facecolor=_BG, edgecolor=_GRID, labelcolor=_FG)  # Add legend with dark theme
    _apply_style(ax, "Memory Usage During Hashing", "Memory (MB)")
    return _save(fig, "memory_comparison")


def chart_ingestion_impact(impact_results: list[dict]) -> str:
    """Grouped bar chart: baseline vs hashed ingestion rate per algorithm."""
    fig, ax = plt.subplots(figsize=(10, 5))
    names     = [r["display_name"] for r in impact_results]
    baseline  = [r["baseline_rate_eps"] for r in impact_results]  # No-hash rate
    hashed    = [r["hashed_rate_eps"] for r in impact_results]    # With-hash rate

    x = range(len(names))
    w = 0.3  # Bar width
    # Grey bars for baseline, coloured bars for hashed
    bars1 = ax.bar([i - w/2 for i in x], baseline, w, label="Baseline (no hash)",
                   color="#95a5a6", edgecolor="white", linewidth=0.5)
    bars2 = ax.bar([i + w/2 for i in x], hashed, w, label="With Hashing",
                   color=[_COLOURS.get(r["algorithm"], "#3498db") for r in impact_results],
                   edgecolor="white", linewidth=0.5)

    # Add value labels above baseline bars
    for bar, v in zip(bars1, baseline):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(baseline)*0.01,
                f"{v:,.0f}", ha="center", va="bottom", color=_FG, fontsize=8)
    # Add value labels above hashed bars
    for bar, v in zip(bars2, hashed):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(baseline)*0.01,
                f"{v:,.0f}", ha="center", va="bottom", color=_FG, fontsize=8)

    ax.set_xticks(list(x))
    ax.set_xticklabels(names)
    ax.legend(facecolor=_BG, edgecolor=_GRID, labelcolor=_FG)
    _apply_style(ax, "Ingestion Rate: Baseline vs Hashed", "Entries / second")
    return _save(fig, "ingestion_impact")


def chart_tamper_response_time(tamper_results: dict[str, dict]) -> str:
    """Bar chart of mean tamper detection response time per algorithm."""
    fig, ax = plt.subplots(figsize=(8, 5))
    algorithms = list(tamper_results.keys())
    names = [config.ALGORITHM_DISPLAY_NAMES.get(a, a) for a in algorithms]
    vals  = [tamper_results[a].get("mean_response_us", 0) for a in algorithms]  # Mean µs
    colours = [_COLOURS.get(a, "#95a5a6") for a in algorithms]

    bars = ax.bar(names, vals, color=colours, edgecolor="white", linewidth=0.5, width=0.55)
    for bar, v in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(vals) * 0.02 if max(vals) > 0 else 0.5,
                f"{v:.1f}", ha="center", va="bottom", color=_FG, fontsize=10, fontweight="bold")

    _apply_style(ax, "Tamper Detection Response Time", "Response Time (\u00b5s)")
    return _save(fig, "tamper_response_time")


def generate_all_charts(
    benchmark_reports: list[dict],
    perf_reports: list[dict],
    tamper_results: dict[str, dict],
    impact_results: list[dict] | None = None,
) -> list[str]:
    """Generate all charts and return list of file paths."""
    # Always generate the three core benchmark charts
    paths = [
        chart_throughput(benchmark_reports),    # Throughput comparison (H/s)
        chart_latency(benchmark_reports),       # Average latency comparison (µs)
        chart_p95_latency(benchmark_reports),   # P95 latency comparison (µs)
    ]
    # Only generate CPU chart if profiling data contains non-zero CPU readings
    if perf_reports and any(r.get("cpu_percent", 0) > 0 for r in perf_reports):
        paths.append(chart_cpu(perf_reports))
    # Generate memory chart if profiling data is available
    if perf_reports:
        paths.append(chart_memory(perf_reports))
    # Generate tamper detection charts if tamper test was run
    if tamper_results:
        paths.append(chart_integrity(tamper_results))  # Detection rate chart
        # Only generate response time chart if response times were recorded
        if any(tamper_results[a].get("mean_response_us", 0) > 0 for a in tamper_results):
            paths.append(chart_tamper_response_time(tamper_results))
    # Generate ingestion impact chart if impact analysis was run
    if impact_results:
        paths.append(chart_ingestion_impact(impact_results))
    return paths  # Return all chart file paths


# ─── Text summary report ─────────────────────────────────────────────

def write_summary_report(
    benchmark_reports: list[dict],
    perf_reports: list[dict],
    integrity_summary: dict,
    tamper_results: dict,
    impact_results: list[dict] | None = None,
    filepath: str | None = None,
) -> str:
    """Write a plain-text summary report."""
    filepath = filepath or os.path.join(config.OUTPUT_DIR, "summary_report.txt")
    # Build the report as a list of lines
    lines = [
        "=" * 70,
        "  SOC CRYPTOGRAPHIC HASHING FRAMEWORK \u2014 SUMMARY REPORT",
        "=" * 70,
        "",
        "BENCHMARK RESULTS",
        "-" * 40,
    ]
    # Add a line for each algorithm's benchmark statistics
    for r in benchmark_reports:
        lines.append(f"  {r['display_name']:10s}  "
                      f"throughput={r['mean_throughput_hps']:>10,.0f} H/s  "
                      f"avg_latency={r['mean_latency_us']:>8.1f} \u00b5s  "
                      f"p95={r['p95_latency_us']:>8.1f} \u00b5s")

    # Performance profiling section
    lines += ["", "PERFORMANCE PROFILING", "-" * 40]
    for r in perf_reports:
        lines.append(f"  {r['display_name']:10s}  "
                      f"throughput={r['throughput_hps']:>10,.0f} H/s  "
                      f"CPU={r['cpu_percent']:>5.1f}%  "
                      f"mem_delta={r['mem_delta_mb']:>+.4f} MB")

    # Integrity verification section
    lines += ["", "INTEGRITY VERIFICATION", "-" * 40]
    for alg, s in integrity_summary.items():
        name = config.ALGORITHM_DISPLAY_NAMES.get(alg, alg)
        lines.append(f"  {name:10s}  passed={s['passed']}  failed={s['failed']}  total={s['total']}")

    # Tamper detection section with confusion matrix
    lines += ["", "TAMPER DETECTION", "-" * 40]
    _first_alg = next(iter(tamper_results), None)
    if _first_alg:
        _d = tamper_results[_first_alg]
        lines.append(f"  Methodology: {_d['tampered_count']}/{_d['total']} entries "
                     f"tampered ({_d['tamper_rate_pct']}%) \u2014 remainder left clean")
    for alg, t in tamper_results.items():
        name = config.ALGORITHM_DISPLAY_NAMES.get(alg, alg)
        lines.append(f"  {name:10s}  TP={t['tp']}  TN={t['tn']}  FP={t['fp']}  FN={t['fn']}  "
                      f"Acc={t['accuracy']:.2%}  Prec={t['precision']:.2%}  "
                      f"Rec={t['recall']:.2%}  F1={t['f1_score']:.4f}  "
                      f"mean_resp={t.get('mean_response_us', 0):.1f} \u00b5s  "
                      f"p95_resp={t.get('p95_response_us', 0):.1f} \u00b5s")

    # Ingestion impact section (optional)
    if impact_results:
        lines += ["", "INGESTION IMPACT ANALYSIS", "-" * 40]
        for r in impact_results:
            lines.append(
                f"  {r['display_name']:10s}  "
                f"baseline={r['baseline_rate_eps']:>10,.0f} eps  "
                f"hashed={r['hashed_rate_eps']:>10,.0f} eps  "
                f"overhead={r['rate_overhead_pct']:>+.1f}%"
            )

    lines += ["", "=" * 70]

    # Write all lines to the output file
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    logger.info("Summary report saved \u2192 %s", filepath)
    return filepath

def generate_word_report(
    benchmark_reports: list[dict],
    perf_reports: list[dict],
    integrity_summary: dict,
    tamper_results: dict,
    dataset_name: str,
    entry_count: int,
    iterations: int,
    impact_results: list[dict] | None = None,
    filepath: str | None = None,
) -> str:
    """Generate a professional Word document (.docx) summary of results."""
    from docx import Document                     # python-docx library for Word document creation
    from docx.shared import Inches                # Inch-based sizing for images in the document
    from docx.enum.text import WD_ALIGN_PARAGRAPH # Paragraph alignment constants

    filepath = filepath or config.WORD_REPORT_PATH  # Default to config path
    doc = Document()  # Create a new blank Word document
    
    # Title — centred heading at the top of the document
    title = doc.add_heading('SOC Hashing Framework - Test Results Walkthrough', 0)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER

    # 1. Execution Summary — key parameters of this test run
    doc.add_heading('1. Execution Summary', level=1)
    summary_items = [
        f"Dataset Used: {dataset_name}",
        f"Entries Collected: {entry_count}",
        f"Iterations: {iterations}",
        "Platform: Windows (Force UTF-8)"
    ]
    for item in summary_items:
        doc.add_paragraph(item, style='List Bullet')  # Add each item as a bullet point

    # 2. Benchmark Results — statistical table of algorithm performance
    doc.add_heading('2. Benchmark Results', level=1)
    doc.add_paragraph("The following table shows the statistical breakdown of algorithm performance.")

    # Create a table with headers and one row per algorithm
    table = doc.add_table(rows=1, cols=6)
    table.style = 'Table Grid'  # Use a grid style for visible cell borders
    headers = ["Algorithm", "Throughput (H/s)", "Avg Latency (us)", "Median (us)", "P95 (us)", "Std Dev (us)"]
    hdr_cells = table.rows[0].cells
    for i, h in enumerate(headers):
        hdr_cells[i].text = h  # Populate the header row

    # Add a data row for each algorithm's benchmark results
    for r in benchmark_reports:
        row_cells = table.add_row().cells
        row_cells[0].text = r["display_name"]
        row_cells[1].text = f"{r['mean_throughput_hps']:,.2f}"
        row_cells[2].text = f"{r['mean_latency_us']:.2f}"
        row_cells[3].text = f"{r['median_latency_us']:.2f}"
        row_cells[4].text = f"{r['p95_latency_us']:.2f}"
        row_cells[5].text = f"{r['stdev_latency_us']:.2f}"

    # 3. Visual Comparisons — embed PNG charts into the document
    doc.add_heading('3. Visual Comparisons', level=1)
    
    # List of chart labels and their corresponding PNG filenames
    charts = [
        ("Throughput Comparison", "throughput_comparison.png"),
        ("Latency Comparison", "latency_comparison.png"),
        ("P95 Latency", "p95_latency_comparison.png"),
        ("Resource Utilization (CPU)", "cpu_comparison.png"),
        ("Memory Usage", "memory_comparison.png"),
        ("Integrity & Security Verification", "integrity_comparison.png"),
        ("Tamper Detection Response Time", "tamper_response_time.png"),
        ("Ingestion Impact (Baseline vs Hashed)", "ingestion_impact.png"),
    ]

    # Only embed charts that were actually generated (file exists on disk)
    for label, filename in charts:
        full_path = os.path.join(config.CHART_DIR, filename)
        if os.path.exists(full_path):
            doc.add_heading(label, level=2)            # Sub-heading for the chart
            doc.add_picture(full_path, width=Inches(6)) # Embed the chart image at 6" width
            doc.add_paragraph("")                       # Add spacing after the image

    # 4. Integrity Verification Result — pass/fail summary per algorithm
    doc.add_heading('4. Integrity Verification', level=1)
    for alg, s in integrity_summary.items():
        name = config.ALGORITHM_DISPLAY_NAMES.get(alg, alg)
        status = "PASSED" if s['failed'] == 0 else "FAILED"
        doc.add_paragraph(f"{name}: {status} ({s['passed']}/{s['total']} passed)", style='List Bullet')

    # 5. Tamper Detection Rate & Response Times
    doc.add_heading('5. Tamper Detection', level=1)
    _first_alg_w = next(iter(tamper_results), None)
    if _first_alg_w:
        _dw = tamper_results[_first_alg_w]
        # Add a paragraph explaining the tamper methodology
        doc.add_paragraph(
            f"{_dw['tampered_count']} of {_dw['total']} collected entries "
            f"({_dw['tamper_rate_pct']}%) were randomly selected and deliberately "
            f"tampered by mutating the domain field. The remaining "
            f"{_dw['total'] - _dw['tampered_count']} entries were left intact "
            f"to test for false positives."
        )

    # Confusion matrix table
    t_table = doc.add_table(rows=1, cols=9)
    t_table.style = 'Table Grid'
    t_headers = ["Algorithm", "TP", "TN", "FP", "FN",
                 "Accuracy", "Precision", "Recall", "F1"]
    t_hdr = t_table.rows[0].cells
    for i, h in enumerate(t_headers):
        t_hdr[i].text = h
    for alg, t in tamper_results.items():
        name = config.ALGORITHM_DISPLAY_NAMES.get(alg, alg)
        row = t_table.add_row().cells
        row[0].text = name
        row[1].text = str(t["tp"])
        row[2].text = str(t["tn"])
        row[3].text = str(t["fp"])
        row[4].text = str(t["fn"])
        row[5].text = f"{t['accuracy']:.2%}"
        row[6].text = f"{t['precision']:.2%}"
        row[7].text = f"{t['recall']:.2%}"
        row[8].text = f"{t['f1_score']:.4f}"

    # Response time sub-table
    doc.add_heading('Response Times', level=2)
    rt_table = doc.add_table(rows=1, cols=4)
    rt_table.style = 'Table Grid'
    rt_headers = ["Algorithm", "Mean (\u00b5s)", "Median (\u00b5s)", "P95 (\u00b5s)"]
    rt_hdr = rt_table.rows[0].cells
    for i, h in enumerate(rt_headers):
        rt_hdr[i].text = h
    for alg, t in tamper_results.items():
        name = config.ALGORITHM_DISPLAY_NAMES.get(alg, alg)
        row = rt_table.add_row().cells
        row[0].text = name
        row[1].text = f"{t.get('mean_response_us', 0):.2f}"
        row[2].text = f"{t.get('median_response_us', 0):.2f}"
        row[3].text = f"{t.get('p95_response_us', 0):.2f}"

    # 6. Ingestion Impact Analysis (optional section)
    if impact_results:
        doc.add_heading('6. Ingestion Impact Analysis', level=1)
        doc.add_paragraph(
            "Comparison of baseline log ingestion rate (serialise-only) "
            "against hashed ingestion rate for each algorithm."
        )
        i_table = doc.add_table(rows=1, cols=5)
        i_table.style = 'Table Grid'
        i_headers = ["Algorithm", "Baseline (eps)", "Hashed (eps)", "Rate Overhead %", "Latency Overhead %"]
        i_hdr = i_table.rows[0].cells
        for i, h in enumerate(i_headers):
            i_hdr[i].text = h
        for r in impact_results:
            row = i_table.add_row().cells
            row[0].text = r["display_name"]
            row[1].text = f"{r['baseline_rate_eps']:,.0f}"
            row[2].text = f"{r['hashed_rate_eps']:,.0f}"
            row[3].text = f"{r['rate_overhead_pct']:.1f}%"
            row[4].text = f"{r['latency_overhead_pct']:.1f}%"

    # Save the completed Word document to disk
    doc.save(filepath)
    logger.info("Word report saved \u2192 %s", filepath)
    return filepath  # Return the path to the saved document
