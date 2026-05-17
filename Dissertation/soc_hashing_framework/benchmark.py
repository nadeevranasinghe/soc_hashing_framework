"""
Benchmark — Statistical Comparison of Hashing Algorithms
==========================================================
Runs multiple iterations of the hashing pipeline and computes statistical
summaries (mean, median, std dev, p95 latency) for each algorithm.
Exports results to CSV.
"""

import csv      # CSV file writing for exporting benchmark results
import logging  # Standard logging for benchmark progress messages
import math     # Square root function needed for standard deviation calculation
import os       # File path construction for CSV output
import time     # High-resolution timing for per-hash and per-iteration measurements

import config                      # Centralised configuration (iterations, warmup, output paths)
from hashing_engine import HashingEngine  # Cryptographic hashing engine for running benchmarks
from data_ingestion import serialise_entry  # Deterministic JSON serialiser for pre-serialisation

logger = logging.getLogger(__name__)  # Create a module-level logger for this file


def _mean(vals: list[float]) -> float:
    """Compute the arithmetic mean (average) of a list of float values."""
    # Return 0.0 for empty lists to avoid division by zero
    return sum(vals) / len(vals) if vals else 0.0


def _median(vals: list[float]) -> float:
    """Compute the median (middle value) of a list of float values."""
    if not vals:
        return 0.0  # Return 0.0 for empty lists
    s = sorted(vals)  # Sort the values in ascending order
    n = len(s)        # Total number of values
    mid = n // 2      # Index of the middle element (integer division)
    # If even count: average the two middle values; if odd: take the middle value
    return (s[mid - 1] + s[mid]) / 2 if n % 2 == 0 else s[mid]


def _stdev(vals: list[float]) -> float:
    """Compute the sample standard deviation using Bessel's correction (n-1)."""
    if len(vals) < 2:
        return 0.0  # Standard deviation is undefined for fewer than 2 values
    m = _mean(vals)  # Compute the mean first
    # Calculate the variance: sum of squared differences from the mean, divided by (n-1)
    # Using (n-1) instead of n provides Bessel's correction for sample standard deviation
    variance = sum((v - m) ** 2 for v in vals) / (len(vals) - 1)
    return math.sqrt(variance)  # Standard deviation is the square root of variance


def _percentile(vals: list[float], pct: float) -> float:
    """Compute the given percentile (e.g., 95 for P95) from a list of values."""
    if not vals:
        return 0.0  # Return 0.0 for empty lists
    s = sorted(vals)  # Sort values in ascending order for percentile lookup
    # Calculate the index corresponding to the requested percentile
    idx = int(len(s) * pct / 100)
    # Clamp the index to the valid range to prevent IndexError
    return s[min(idx, len(s) - 1)]


class BenchmarkRunner:
    """
    Execute configurable benchmark iterations across all algorithms
    and produce statistical summaries.
    """

    def __init__(
        self,
        entries: list[dict],
        engine: HashingEngine | None = None,
        iterations: int = config.BENCHMARK_ITERATIONS,
        warmup: int = config.WARMUP_ITERATIONS,
    ):
        self.entries = entries            # The dataset of log entries to benchmark against
        self.engine = engine or HashingEngine()  # Hashing engine (default: all algorithms)
        self.iterations = iterations      # Number of measured iterations (after warmup)
        self.warmup = warmup              # Number of warmup iterations to discard

    def run(self) -> list[dict]:
        """
        Run the full benchmark and return a list of per-algorithm result dicts.
        """
        logger.info(
            "Starting benchmark: %d entries × %d iterations (%d warmup) × %d algorithms",
            len(self.entries), self.iterations, self.warmup, len(self.engine.algorithms),
        )

        all_results: list[dict] = []  # Will hold one result dict per algorithm

        # Iterate over each configured hashing algorithm
        for alg in self.engine.algorithms:
            display = config.ALGORITHM_DISPLAY_NAMES.get(alg, alg)  # Human-readable name
            logger.info("Benchmarking %s …", display)

            # Pre-serialise all entries once so we measure only hashing time, not JSON serialisation
            # This isolates the independent variable (algorithm) from the serialisation cost
            payloads = [serialise_entry(e) for e in self.entries]

            iteration_throughputs: list[float] = []  # Throughput (H/s) per measured iteration
            all_latencies_us: list[float] = []       # Per-hash latencies in µs across all iterations

            # Run warmup + measured iterations (warmup results are discarded)
            for i in range(self.warmup + self.iterations):
                per_hash_times_ns: list[int] = []  # Per-hash timing for this iteration

                start = time.perf_counter()  # Start wall-clock timer for this iteration
                for payload in payloads:
                    t0 = time.perf_counter_ns()  # Start nanosecond timer for this single hash
                    self.engine.hash_raw(payload, alg)  # Hash the pre-serialised payload
                    per_hash_times_ns.append(time.perf_counter_ns() - t0)  # Record elapsed ns
                wall = time.perf_counter() - start  # Total wall-clock time for this iteration

                # Only record results from measured iterations (skip warmup)
                if i >= self.warmup:
                    # Calculate throughput: hashes per second for this iteration
                    throughput = len(payloads) / wall if wall > 0 else 0
                    iteration_throughputs.append(throughput)
                    # Convert all per-hash times from nanoseconds to microseconds and accumulate
                    all_latencies_us.extend(t / 1_000 for t in per_hash_times_ns)

            # Compile the statistical summary for this algorithm
            result = {
                "algorithm": alg,                    # Internal algorithm identifier
                "display_name": display,             # Human-readable algorithm name
                "entry_count": len(self.entries),     # Number of entries per iteration
                "iterations": self.iterations,       # Number of measured iterations (excl. warmup)
                "mean_throughput_hps": round(_mean(iteration_throughputs), 2),    # Mean H/s
                "median_throughput_hps": round(_median(iteration_throughputs), 2),# Median H/s
                "stdev_throughput_hps": round(_stdev(iteration_throughputs), 2),  # Std dev of H/s
                "mean_latency_us": round(_mean(all_latencies_us), 3),       # Mean per-hash latency
                "median_latency_us": round(_median(all_latencies_us), 3),   # Median per-hash latency
                "stdev_latency_us": round(_stdev(all_latencies_us), 3),     # Std dev of latency
                "p95_latency_us": round(_percentile(all_latencies_us, 95), 3),  # 95th percentile
                "min_latency_us": round(min(all_latencies_us) if all_latencies_us else 0, 3),  # Min
                "max_latency_us": round(max(all_latencies_us) if all_latencies_us else 0, 3),  # Max
            }
            all_results.append(result)  # Add this algorithm's results to the overall list

            # Log a human-readable summary for this algorithm
            logger.info(
                "  %s — mean %.0f hashes/s, avg latency %.1f µs, p95 %.1f µs",
                display, result["mean_throughput_hps"],
                result["mean_latency_us"], result["p95_latency_us"],
            )

        return all_results  # Return the list of per-algorithm result dictionaries

    @staticmethod
    def export_csv(results: list[dict], filepath: str | None = None) -> str:
        """Write benchmark results to a CSV file."""
        # Use default CSV path from config if no custom path is provided
        filepath = filepath or os.path.join(config.CSV_DIR, "benchmark_results.csv")
        # Extract column headers from the keys of the first result dict
        fieldnames = list(results[0].keys()) if results else []
        # Open the CSV file for writing with UTF-8 encoding
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)  # Create a CSV dict writer
            writer.writeheader()    # Write the header row with column names
            writer.writerows(results)  # Write all result rows
        logger.info("Benchmark CSV saved → %s", filepath)
        return filepath  # Return the path to the saved CSV file


# ─── Ingestion-Impact Analysis ───────────────────────────────────────

class IngestionImpactRunner:
    """
    Compare baseline log ingestion (serialise-only) against
    serialise+hash for each algorithm.  Reports rates, latencies,
    CPU %, and memory deltas so the dissertation can quantify
    the overhead introduced by each hashing algorithm.
    """

    def __init__(
        self,
        entries: list[dict],
        engine: HashingEngine | None = None,
        iterations: int = config.BENCHMARK_ITERATIONS,
    ):
        self.entries = entries            # The dataset of log entries to test against
        self.engine = engine or HashingEngine()  # Hashing engine (default: all algorithms)
        self.iterations = iterations      # Number of iterations for each measurement

    def run(self) -> list[dict]:
        """Run the ingestion impact analysis and return per-algorithm overhead metrics."""
        import psutil, os  # psutil for CPU/memory; os for process ID
        proc = psutil.Process(os.getpid())  # Handle to the current Python process
        # Pre-serialise all entries once (shared between baseline and hashed measurements)
        payloads = [serialise_entry(e) for e in self.entries]

        # --- baseline: serialise only (no hashing) ---
        baseline_rates: list[float] = []          # Events/second for baseline iterations
        baseline_latencies_us: list[float] = []   # Per-event latencies for baseline
        proc.cpu_percent(interval=None)           # Prime the CPU counter (first call returns 0)
        # Record memory usage before baseline measurement
        mem_before_base = proc.memory_info().rss / (1024 * 1024)  # Convert bytes to MB

        for _ in range(self.iterations):
            per_ns: list[int] = []  # Per-event timing in nanoseconds
            t0 = time.perf_counter()  # Start wall-clock timer for this iteration
            for p in payloads:
                s = time.perf_counter_ns()  # Start per-event timer
                _ = len(p)  # simulate "touch" without hashing — minimal operation on the payload
                per_ns.append(time.perf_counter_ns() - s)  # Record elapsed nanoseconds
            wall = time.perf_counter() - t0  # Total wall time for this iteration
            # Calculate baseline ingestion rate (events per second)
            baseline_rates.append(len(payloads) / wall if wall > 0 else 0)
            # Convert per-event times to microseconds and accumulate
            baseline_latencies_us.extend(t / 1_000 for t in per_ns)

        baseline_cpu = proc.cpu_percent(interval=None)  # CPU usage during baseline
        # Record memory usage after baseline measurement
        mem_after_base = proc.memory_info().rss / (1024 * 1024)  # Convert bytes to MB

        # Compile baseline statistics into a dictionary
        baseline = {
            "rate_eps": round(_mean(baseline_rates), 2),                # Mean events/second
            "latency_us": round(_mean(baseline_latencies_us), 3),      # Mean latency in µs
            "cpu_percent": round(baseline_cpu, 2),                      # CPU utilisation %
            "mem_delta_mb": round(mem_after_base - mem_before_base, 4), # Memory change in MB
        }

        # --- per-algorithm: serialise + hash ---
        results: list[dict] = []  # Will hold one result dict per algorithm
        for alg in self.engine.algorithms:
            display = config.ALGORITHM_DISPLAY_NAMES.get(alg, alg)  # Human-readable name
            alg_rates: list[float] = []          # Events/second per iteration for this algorithm
            alg_latencies_us: list[float] = []   # Per-event latencies for this algorithm
            proc.cpu_percent(interval=None)      # Prime CPU counter before measurement
            # Record memory before hashing with this algorithm
            mem_before = proc.memory_info().rss / (1024 * 1024)  # Convert bytes to MB

            for _ in range(self.iterations):
                per_ns: list[int] = []  # Per-event timing in nanoseconds
                t0 = time.perf_counter()  # Start wall-clock timer for this iteration
                for p in payloads:
                    s = time.perf_counter_ns()  # Start per-event timer
                    self.engine.hash_raw(p, alg)  # Hash the payload with this algorithm
                    per_ns.append(time.perf_counter_ns() - s)  # Record elapsed nanoseconds
                wall = time.perf_counter() - t0  # Total wall time for this iteration
                # Calculate hashed ingestion rate (events per second)
                alg_rates.append(len(payloads) / wall if wall > 0 else 0)
                # Convert per-event times to microseconds and accumulate
                alg_latencies_us.extend(t / 1_000 for t in per_ns)

            alg_cpu = proc.cpu_percent(interval=None)  # CPU usage during hashing
            # Record memory after hashing with this algorithm
            mem_after = proc.memory_info().rss / (1024 * 1024)  # Convert bytes to MB

            hashed_rate = _mean(alg_rates)          # Mean events/second with hashing
            hashed_latency = _mean(alg_latencies_us)  # Mean per-event latency with hashing

            # Compile the comparison metrics for this algorithm
            results.append({
                "algorithm": alg,                    # Internal algorithm identifier
                "display_name": display,             # Human-readable algorithm name
                "baseline_rate_eps": baseline["rate_eps"],  # Baseline events/second (no hashing)
                "hashed_rate_eps": round(hashed_rate, 2),   # Hashed events/second
                # Rate overhead: percentage reduction in throughput due to hashing
                "rate_overhead_pct": round(
                    (1 - hashed_rate / baseline["rate_eps"]) * 100
                    if baseline["rate_eps"] > 0 else 0, 2),
                "baseline_latency_us": baseline["latency_us"],  # Baseline per-event latency
                "hashed_latency_us": round(hashed_latency, 3), # Hashed per-event latency
                # Latency overhead: percentage increase in per-event latency due to hashing
                "latency_overhead_pct": round(
                    ((hashed_latency - baseline["latency_us"]) / baseline["latency_us"]) * 100
                    if baseline["latency_us"] > 0 else 0, 2),
                "cpu_baseline": baseline["cpu_percent"],        # Baseline CPU usage
                "cpu_hashed": round(alg_cpu, 2),                # CPU usage with hashing
                "mem_delta_baseline_mb": baseline["mem_delta_mb"],  # Baseline memory change
                "mem_delta_hashed_mb": round(mem_after - mem_before, 4),  # Hashing memory change
            })

            # Log a human-readable summary of the overhead for this algorithm
            logger.info(
                "  %s — baseline %.0f eps → hashed %.0f eps (%.1f%% overhead)",
                display, baseline["rate_eps"], hashed_rate,
                results[-1]["rate_overhead_pct"],
            )

        return results  # Return the list of per-algorithm ingestion impact results
