"""
SOC Cryptographic Hashing Framework - Main Orchestrator
=========================================================
CLI entry point that chains: data ingestion -> hashing -> integrity
verification -> benchmarking -> visualisation.

Usage
-----
  python main.py --demo           # simulated data, prompts for entries/iterations
  python main.py --live           # live Certstream, prompts for dataset/entries/iterations
  python main.py --demo --entries 1000 --iterations 10   # skip prompts via CLI flags
"""

import argparse  # Command-line argument parsing for --live, --demo, --entries, etc.
import io        # Used to wrap stdout/stderr with UTF-8 encoding on Windows
import logging   # Standard logging configuration for the entire framework
import sys       # System-level access for stdout/stderr streams and exit codes

# Force UTF-8 output on Windows to prevent encoding errors with special characters (e.g., µ, →)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import config  # Centralised configuration (defaults, paths, algorithm names)
# Import the benchmark runner and ingestion impact analyser from the benchmark module
from benchmark import BenchmarkRunner, IngestionImpactRunner
# Import all four data collectors and the simulated data generator
from data_ingestion import (
    CertstreamCollector, URLhausCollector, OTXCollector, CISAAISCollector,
    generate_simulated_entries
)
from hashing_engine import HashingEngine          # Core hashing engine for computing digests
from integrity_verifier import IntegrityVerifier  # Hash registry and tamper detection module
from performance_monitor import profile_all_algorithms  # CPU/memory/throughput profiler
# Import chart generation and report writing functions from the visualiser
from visualizer import generate_all_charts, write_summary_report, generate_word_report

# --- Logging setup ---
# Configure the root logger with the format and level defined in config.py
logging.basicConfig(format=config.LOG_FORMAT, level=config.LOG_LEVEL, stream=sys.stderr)
logger = logging.getLogger("soc_framework")  # Create the main application logger


def _print_table(benchmark_results: list[dict]):
    """Pretty-print a comparison table to the console."""
    try:
        from tabulate import tabulate  # Optional dependency for formatted tables
    except ImportError:
        # Fallback: print a simple formatted table if tabulate is not installed
        for r in benchmark_results:
            print(f"  {r['display_name']:10s}  "
                  f"{r['mean_throughput_hps']:>10,.0f} H/s  "
                  f"{r['mean_latency_us']:>8.1f} us avg  "
                  f"{r['p95_latency_us']:>8.1f} us p95")
        return

    # Define the column headers for the tabulate output
    headers = [
        "Algorithm",
        "Throughput (H/s)",
        "Avg Latency (us)",
        "Median (us)",
        "P95 (us)",
        "Std Dev (us)",
    ]
    # Build the data rows from the benchmark results
    rows = [
        [
            r["display_name"],                       # Algorithm name
            f'{r["mean_throughput_hps"]:,.0f}',       # Formatted throughput
            f'{r["mean_latency_us"]:.2f}',            # Average latency
            f'{r["median_latency_us"]:.2f}',          # Median latency
            f'{r["p95_latency_us"]:.2f}',             # 95th percentile latency
            f'{r["stdev_latency_us"]:.2f}',           # Standard deviation
        ]
        for r in benchmark_results
    ]
    print()
    print(tabulate(rows, headers=headers, tablefmt="fancy_grid"))  # Print formatted table
    print()


def main():
    # Set up the command-line argument parser with a description of the framework
    parser = argparse.ArgumentParser(
        description="SOC Cryptographic Hashing Framework - "
                    "compare MD5, SHA-256, SHA3-256, BLAKE2b on Certstream data",
    )
    # Create a mutually exclusive group: user must choose either --live or --demo
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--live", action="store_true",
                      help="Ingest live data from Certstream")  # Use real-time threat feeds
    mode.add_argument("--demo", action="store_true",
                      help="Use simulated Certstream data (offline)")  # Use generated data

    # Optional CLI arguments with defaults from config.py
    parser.add_argument("--entries", type=int, default=config.DEFAULT_BATCH_SIZE,
                        help=f"Number of log entries (default {config.DEFAULT_BATCH_SIZE})")
    parser.add_argument("--duration", type=int, default=config.DEFAULT_COLLECTION_DURATION_SEC,
                        help=f"Live collection duration in seconds (default {config.DEFAULT_COLLECTION_DURATION_SEC})")
    parser.add_argument("--iterations", type=int, default=config.BENCHMARK_ITERATIONS,
                        help=f"Benchmark iterations (default {config.BENCHMARK_ITERATIONS})")
    parser.add_argument("--tamper-rate", type=int, default=config.DEFAULT_TAMPER_RATE,
                        help=f"Percentage of entries to tamper (default {config.DEFAULT_TAMPER_RATE})")

    args = parser.parse_args()  # Parse the command-line arguments

    # Print the framework banner to the console
    print("=" * 70)
    print("  SOC CRYPTOGRAPHIC HASHING FRAMEWORK")
    print("  Certstream Log Pipeline - Algorithm Comparison")
    print("=" * 70)

    # ── Interactive parameter prompts ────────────────────────────────────
    # Only prompt if the user did NOT explicitly supply the flag on the CLI.
    # We detect this by comparing against the argparse defaults.
    def _prompt_int(prompt_text: str, default: int, min_val: int = 1) -> int:
        """Ask the user for an integer, returning `default` on empty input."""
        while True:
            raw = input(f"  {prompt_text} [default: {default}]: ").strip()
            if raw == "":
                return default  # User pressed Enter without typing — use the default value
            try:
                val = int(raw)  # Attempt to parse the user's input as an integer
                if val < min_val:
                    print(f"  Please enter a value >= {min_val}.")
                    continue  # Re-prompt if the value is below the minimum
                return val  # Valid input — return the parsed integer
            except ValueError:
                print("  Invalid input — please enter a whole number.")  # Non-numeric input
        return default  # unreachable; satisfies type checker

    # -- Step 1: Data Ingestion --
    print("\n>> STEP 1 - Data Ingestion")
    dataset_name = "Simulated Certstream"  # Default dataset name (overridden if --live)
    if args.live:
        # Display the interactive dataset selection menu for live mode
        print("  Select Dataset for Live Ingestion:")
        print("  [1] Certstream (Certificate Transparency)")
        print("  [2] URLhaus (Malware URLs)")
        print("  [3] AlienVault OTX (Threat Pulses)")
        print("  [4] CISA AIS (Simulated STIX)")
        choice = input("  Enter choice (1-4) [default: 1]: ").strip()

        # Look up the human-readable dataset name from the user's menu choice
        dataset_name = config.DATASET_NAMES_SHORT.get(choice, "Certstream")

    # Prompt for entries if not set via CLI (i.e., still at the default value)
    if args.entries == config.DEFAULT_BATCH_SIZE:
        print()
        args.entries = _prompt_int(
            f"Number of log entries to collect",
            default=config.DEFAULT_BATCH_SIZE,
        )

    # Prompt for iterations if not set via CLI
    if args.iterations == config.BENCHMARK_ITERATIONS:
        args.iterations = _prompt_int(
            f"Benchmark iterations to run",
            default=config.BENCHMARK_ITERATIONS,
        )

    # Prompt for tamper rate if not set via CLI
    tamper_rate = getattr(args, "tamper_rate", config.DEFAULT_TAMPER_RATE)
    if tamper_rate == config.DEFAULT_TAMPER_RATE:
        tamper_rate = _prompt_int(
            f"Tamper rate (% of entries to tamper)",
            default=config.DEFAULT_TAMPER_RATE,
            min_val=1,
        )
        tamper_rate = min(tamper_rate, 100)  # Cap at 100% to prevent invalid percentages
    print()

    # Instantiate the appropriate collector based on the user's dataset choice
    if args.live:
        if choice == "2":
            collector = URLhausCollector(max_entries=args.entries, duration_sec=args.duration)
        elif choice == "3":
            collector = OTXCollector(max_entries=args.entries, duration_sec=args.duration)
        elif choice == "4":
            collector = CISAAISCollector(max_entries=args.entries, duration_sec=args.duration)
        else:
            # Default to Certstream for choice "1" or any unrecognised input
            collector = CertstreamCollector(max_entries=args.entries, duration_sec=args.duration)

        try:
            entries = collector.collect()  # Attempt live data collection
        except Exception as e:
            # If live collection fails, gracefully fall back to simulated data
            logger.error("Live ingestion failed: %s - falling back to simulated data.", e)
            entries = generate_simulated_entries(args.entries)
    else:
        # Demo mode: generate simulated Certstream entries (no network required)
        entries = generate_simulated_entries(args.entries)

    # Exit if no entries were collected (critical failure)
    if not entries:
        logger.error("No entries collected. Exiting.")
        sys.exit(1)

    print(f"  [OK] {len(entries)} log entries ready\n")

    # -- Step 2: Hashing Engine --
    print(">> STEP 2 - Hashing All Entries")
    engine = HashingEngine()  # Create the hashing engine with all five algorithms
    # Hash every entry with every algorithm — returns dict[algorithm -> list[results]]
    all_hashes = engine.hash_batch_all(entries)
    # Print a summary for each algorithm showing count and a sample digest
    for alg, results in all_hashes.items():
        display = config.ALGORITHM_DISPLAY_NAMES.get(alg, alg)
        print(f"  [OK] {display}: {len(results)} hashes computed  "
              f"(sample: {results[0]['digest'][:24]}...)")
    print()

    # -- Step 3: Integrity Verification --
    print(">> STEP 3 - Integrity Verification")
    verifier = IntegrityVerifier(engine)  # Create verifier with the same engine instance
    verifier.register_batch(entries)       # Register all entries (store baseline hashes)
    # Verify all entries against their stored baselines — should all pass before tampering
    integrity_summary = verifier.verify_batch(entries)
    for alg, s in integrity_summary.items():
        display = config.ALGORITHM_DISPLAY_NAMES.get(alg, alg)
        # Display pass/fail status for each algorithm
        status = "[OK] ALL PASSED" if s["failed"] == 0 else f"[FAIL] {s['failed']} FAILED"
        print(f"  {display}: {status} ({s['passed']}/{s['total']})")
    print()

    # -- Step 4: Tamper Detection --
    print(">> STEP 4 - Tamper Detection Test")
    # Run the batch tamper test with the user-specified tamper rate
    tamper_results = verifier.tamper_test_batch(entries, tamper_rate_pct=tamper_rate)
    # Print methodology summary (how many entries were tampered)
    _first = next(iter(tamper_results.values()))  # Get results from the first algorithm
    n_tampered = _first["tampered_count"]  # Number of deliberately tampered entries
    n_total    = _first["total"]           # Total entries in the batch
    pct        = _first["tamper_rate_pct"] # Actual tamper percentage applied
    print(f"  Tampered: {n_tampered}/{n_total} entries ({pct}%) — remainder left clean")
    # Print confusion matrix and response time for each algorithm
    for alg, t in tamper_results.items():
        display = config.ALGORITHM_DISPLAY_NAMES.get(alg, alg)
        print(f"  {display}: TP={t['tp']}  TN={t['tn']}  FP={t['fp']}  FN={t['fn']}  "
              f"Accuracy={t['accuracy']:.2%}  Precision={t['precision']:.2%}  "
              f"Recall={t['recall']:.2%}  F1={t['f1_score']:.4f}  "
              f"resp: mean {t.get('mean_response_us', 0):.1f} µs, "
              f"p95 {t.get('p95_response_us', 0):.1f} µs")
    print()

    # -- Step 5: Performance Profiling --
    print(">> STEP 5 - Performance Profiling")
    # Profile each algorithm for CPU, memory, and throughput using psutil
    perf_reports = profile_all_algorithms(engine, entries)
    for r in perf_reports:
        print(f"  {r['display_name']:10s}  {r['throughput_hps']:>10,.0f} H/s  "
              f"CPU {r['cpu_percent']:.1f}%  mem delta {r['mem_delta_mb']:+.4f} MB")
    print()

    # -- Step 6: Statistical Benchmarking --
    print(">> STEP 6 - Statistical Benchmark")
    # Run the multi-iteration benchmark with warmup to produce statistically robust results
    runner = BenchmarkRunner(entries, engine, iterations=args.iterations)
    benchmark_results = runner.run()         # Execute the benchmark
    csv_path = runner.export_csv(benchmark_results)  # Export results to CSV
    print(f"  [OK] CSV exported -> {csv_path}")
    _print_table(benchmark_results)          # Display formatted results table

    # -- Step 7: Ingestion-Impact Analysis --
    print(">> STEP 7 - Ingestion-Impact Analysis")
    # Compare baseline (no-hash) ingestion rate against hashed ingestion rate
    impact_runner = IngestionImpactRunner(entries, engine, iterations=args.iterations)
    impact_results = impact_runner.run()     # Execute the impact analysis
    for r in impact_results:
        print(f"  {r['display_name']:10s}  "
              f"baseline {r['baseline_rate_eps']:>10,.0f} eps  "
              f"hashed {r['hashed_rate_eps']:>10,.0f} eps  "
              f"overhead {r['rate_overhead_pct']:>+.1f}%")
    print()

    # -- Step 8: Visualisation --
    print(">> STEP 8 - Generating Charts")
    # Generate all PNG charts (throughput, latency, CPU, memory, integrity, impact)
    chart_paths = generate_all_charts(
        benchmark_results, perf_reports, tamper_results,
        impact_results=impact_results,
    )
    for p in chart_paths:
        print(f"  [OK] {p}")  # Print the path of each generated chart

    # Generate the plain-text summary report
    report_path = write_summary_report(
        benchmark_results, perf_reports, integrity_summary, tamper_results,
        impact_results=impact_results,
    )
    print(f"  [OK] Summary report -> {report_path}")

    # Generate the professional Word document (.docx) report
    word_path = generate_word_report(
        benchmark_results, perf_reports, integrity_summary, tamper_results,
        dataset_name=dataset_name,
        entry_count=len(entries),
        iterations=args.iterations,
        impact_results=impact_results,
    )
    print(f"  [OK] Word report -> {word_path}")

    # Print the final completion banner
    print("\n" + "=" * 70)
    print("  DONE - All results saved to:", config.OUTPUT_DIR)
    print("=" * 70)


# Standard Python entry point — only runs main() when executed directly
if __name__ == "__main__":
    main()
