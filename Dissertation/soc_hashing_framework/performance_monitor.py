"""
Performance Monitor — Resource & Throughput Metrics
====================================================
Context-manager based monitor that captures CPU utilisation, memory usage,
and wall-clock time around hashing operations. Designed to be composable
with the HashingEngine for per-algorithm profiling.
"""

import logging  # Standard logging for diagnostic messages
import os       # Used to get the current process ID for psutil
import time     # High-resolution timing via perf_counter for wall-clock measurements

import psutil   # Cross-platform library for real-time CPU and memory monitoring

import config   # Centralised configuration (algorithm display names)

logger = logging.getLogger(__name__)  # Create a module-level logger for this file

# Get a handle to the current Python process for CPU and memory measurements
_PROCESS = psutil.Process(os.getpid())


class PerformanceMonitor:
    """
    Usage::

        mon = PerformanceMonitor("sha256")
        with mon:
            engine.hash_batch(entries, "sha256")
        print(mon.report())
    """

    def __init__(self, algorithm: str, entry_count: int = 0):
        self.algorithm = algorithm      # The algorithm being profiled in this monitor instance
        self.entry_count = entry_count  # Number of entries hashed (set before or after context)

        # These attributes are populated after the context manager exits
        self.wall_time_sec: float = 0.0   # Total elapsed wall-clock time in seconds
        self.cpu_percent: float = 0.0     # CPU utilisation percentage during the operation
        self.mem_before_mb: float = 0.0   # Process RSS memory before hashing (megabytes)
        self.mem_after_mb: float = 0.0    # Process RSS memory after hashing (megabytes)
        self.peak_mem_mb: float = 0.0     # Peak memory observed (max of before and after)

        # Internal timing state (not part of the public API)
        self._start: float = 0.0          # perf_counter timestamp at context entry
        self._cpu_times_start = None      # CPU times snapshot at context entry

    # ── context manager ──

    def __enter__(self):
        # Prime the CPU percent counter — first call always returns 0.0 (psutil behaviour)
        _PROCESS.cpu_percent(interval=None)
        # Capture RSS memory usage before the hashing operation begins
        self.mem_before_mb = _PROCESS.memory_info().rss / (1024 * 1024)  # Convert bytes to MB
        # Record CPU times at the start for potential fine-grained CPU accounting
        self._cpu_times_start = _PROCESS.cpu_times()
        # Record the high-resolution start timestamp for wall-clock measurement
        self._start = time.perf_counter()
        return self  # Allow usage as: with PerformanceMonitor(...) as mon:

    def __exit__(self, *exc):
        # Calculate total wall-clock elapsed time in seconds
        self.wall_time_sec = time.perf_counter() - self._start
        # Capture CPU percent since the last call in __enter__ (measures the hashing window)
        self.cpu_percent = _PROCESS.cpu_percent(interval=None)
        # Capture RSS memory usage after the hashing operation completes
        mem_info = _PROCESS.memory_info()
        self.mem_after_mb = mem_info.rss / (1024 * 1024)  # Convert bytes to MB
        # Peak memory is the higher of before and after (conservative estimate)
        self.peak_mem_mb = max(self.mem_before_mb, self.mem_after_mb)

    # ── derived metrics ──

    @property
    def throughput(self) -> float:
        """Hashes per second."""
        if self.wall_time_sec <= 0:
            return 0.0  # Avoid division by zero if the operation was instantaneous
        # Throughput = total entries hashed / total wall-clock seconds elapsed
        return self.entry_count / self.wall_time_sec

    @property
    def avg_latency_us(self) -> float:
        """Average latency in microseconds per hash."""
        if self.entry_count <= 0:
            return 0.0  # Avoid division by zero if no entries were hashed
        # Convert wall time to microseconds, then divide by entry count for per-hash average
        return (self.wall_time_sec * 1_000_000) / self.entry_count

    @property
    def mem_delta_mb(self) -> float:
        """Memory change (MB) during the hashing operation (after minus before)."""
        return self.mem_after_mb - self.mem_before_mb

    # ── reporting ──

    def report(self) -> dict:
        """Build a dictionary containing all profiling metrics for this algorithm."""
        return {
            "algorithm": self.algorithm,         # Internal algorithm identifier
            "display_name": config.ALGORITHM_DISPLAY_NAMES.get(self.algorithm, self.algorithm),
            "entry_count": self.entry_count,     # Total entries hashed in this profiling run
            "wall_time_sec": round(self.wall_time_sec, 6),   # Wall-clock time in seconds
            "throughput_hps": round(self.throughput, 2),      # Hashes per second
            "avg_latency_us": round(self.avg_latency_us, 3), # Average latency in microseconds
            "cpu_percent": round(self.cpu_percent, 2),        # CPU utilisation percentage
            "mem_before_mb": round(self.mem_before_mb, 2),   # Memory before hashing (MB)
            "mem_after_mb": round(self.mem_after_mb, 2),     # Memory after hashing (MB)
            "peak_mem_mb": round(self.peak_mem_mb, 2),       # Peak memory observed (MB)
            "mem_delta_mb": round(self.mem_delta_mb, 4),     # Memory change during hashing (MB)
        }


def profile_algorithm(engine, entries: list[dict], algorithm: str) -> dict:
    """
    Convenience function: hash a batch with *algorithm* and return a
    performance report dict.
    To prevent wildly inaccurate CPU measurements caused by the Windows task
    timer resolution (typically ~15.6ms) we loop the workload until at least
    0.3 seconds have elapsed.
    """
    # Create a monitor instance — entry_count will be updated after the loop completes
    mon = PerformanceMonitor(algorithm, entry_count=0)
    iterations = 0   # Track how many times we hashed the full batch
    results = []     # Will hold hash results from the last iteration

    with mon:
        while True:
            # Hash the entire batch with the specified algorithm
            # We save only the last iteration's results to compute per-hash stats
            results = engine.hash_batch(entries, algorithm)
            iterations += 1  # Increment the iteration counter
            # Keep looping until at least 0.3 seconds have elapsed (ensures reliable CPU readings)
            if time.perf_counter() - mon._start >= 0.3:
                break

    # Total entries hashed = entries per batch × number of loop iterations
    mon.entry_count = iterations * len(entries)
    report = mon.report()  # Generate the profiling report dict

    # Compute per-hash timing statistics from the final loop's results
    # (using the last iteration avoids cold-start bias from early iterations)
    times_ns = [r["time_ns"] for r in results]  # Extract nanosecond timings from hash results
    if times_ns:
        times_us = [t / 1_000 for t in times_ns]  # Convert nanoseconds to microseconds
        times_us.sort()  # Sort for percentile calculations
        report["min_latency_us"] = round(times_us[0], 3)     # Fastest single hash in µs
        report["max_latency_us"] = round(times_us[-1], 3)    # Slowest single hash in µs
        # Median: the middle value of the sorted latency list
        report["median_latency_us"] = round(
            times_us[len(times_us) // 2], 3
        )
        # P95: the value below which 95% of per-hash latencies fall
        p95_idx = int(len(times_us) * 0.95)
        report["p95_latency_us"] = round(times_us[min(p95_idx, len(times_us) - 1)], 3)

    return report  # Return the complete profiling report dictionary


def profile_all_algorithms(engine, entries: list[dict]) -> list[dict]:
    """Profile every configured algorithm and return list of reports."""
    reports = []  # Accumulate per-algorithm profiling reports
    for alg in engine.algorithms:
        r = profile_algorithm(engine, entries, alg)  # Profile this specific algorithm
        reports.append(r)  # Add the report to the results list
        # Log a summary line for each algorithm's performance
        logger.info(
            "%s — %s hashes/s, avg %.1f µs, CPU %.1f%%",
            r["display_name"], f'{r["throughput_hps"]:,.0f}',
            r["avg_latency_us"], r["cpu_percent"],
        )
    return reports  # Return all profiling reports as a list of dicts
