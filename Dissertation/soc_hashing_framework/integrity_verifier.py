"""
Integrity Verifier — Evidence Tampering Detection
===================================================
Stores original hashes in a registry and re-verifies on demand.
Provides a tamper-test that deliberately mutates data to prove each
algorithm detects modifications.
"""

import copy     # Used for deep-copying entries before mutation (prevents modifying originals)
import logging  # Standard logging for diagnostic messages
import random   # Random selection of entries to tamper and generation of mutation characters
import string   # Provides ascii_lowercase for generating random tamper suffixes
import time     # Nanosecond-precision timing for measuring tamper detection response time

import config                      # Centralised configuration (algorithm display names)
from data_ingestion import serialise_entry  # Deterministic JSON serialiser for log entries
from hashing_engine import HashingEngine    # Cryptographic hashing engine for computing digests

logger = logging.getLogger(__name__)  # Create a module-level logger for this file


class IntegrityVerifier:
    """
    Maintains a hash registry mapping (entry_id, algorithm) → digest.
    Supports verification and deliberate tamper-testing.
    """

    def __init__(self, engine: HashingEngine | None = None):
        # Use the provided hashing engine, or create a default one with all algorithms
        self.engine = engine or HashingEngine()
        # Internal registry: nested dict mapping entry_id → { algorithm → digest }
        # This stores the "ground truth" hash for each entry so we can detect changes later
        self._registry: dict[str, dict[str, str]] = {}

    # ── registration ──

    def register(self, entry: dict) -> dict[str, str]:
        """
        Hash *entry* with every algorithm and store the digests.

        Returns
        -------
        dict  mapping algorithm → digest
        """
        results = self.engine.hash_entry_all(entry)  # Hash the entry with all five algorithms
        # Extract just the algorithm name and digest from each result dict
        digests = {r["algorithm"]: r["digest"] for r in results}
        # Store the digests in the registry, keyed by the entry's unique ID
        self._registry[entry["entry_id"]] = digests
        return digests  # Return the digests so the caller can inspect them if needed

    def register_batch(self, entries: list[dict]) -> int:
        """Register many entries. Returns the count registered."""
        for entry in entries:
            self.register(entry)  # Register each entry individually
        return len(entries)  # Return total number of entries registered

    # ── verification ──

    def verify(self, entry: dict, algorithm: str) -> bool:
        """
        Recompute the hash of *entry* with *algorithm* and compare to the
        stored digest. Returns True if they match.
        """
        eid = entry["entry_id"]  # Extract the unique identifier for this entry
        # Look up the stored digest for this entry and algorithm; returns None if not found
        stored = self._registry.get(eid, {}).get(algorithm)
        if stored is None:
            # No baseline hash exists — cannot verify integrity
            logger.warning("No stored hash for entry %s / %s", eid, algorithm)
            return False
        # Recompute the hash from the current entry data
        recomputed = self.engine.hash_entry(entry, algorithm)["digest"]
        # Compare recomputed hash against the stored baseline — match means integrity is intact
        return recomputed == stored

    def verify_all(self, entry: dict) -> dict[str, bool]:
        """Verify *entry* against every stored algorithm."""
        # Returns a dict mapping each algorithm name to True (passed) or False (failed)
        return {alg: self.verify(entry, alg) for alg in self.engine.algorithms}

    def verify_batch(self, entries: list[dict]) -> dict[str, dict]:
        """
        Verify a batch of entries. Returns per-algorithm summary:
        { algorithm: { "passed": int, "failed": int, "total": int } }
        """
        # Initialise counters for each algorithm: passed, failed, and total checks
        summary: dict[str, dict] = {
            alg: {"passed": 0, "failed": 0, "total": 0}
            for alg in self.engine.algorithms
        }
        for entry in entries:
            for alg in self.engine.algorithms:
                ok = self.verify(entry, alg)  # Verify this entry with this algorithm
                summary[alg]["total"] += 1    # Increment the total counter
                # Increment either the passed or failed counter based on the verification result
                summary[alg]["passed" if ok else "failed"] += 1
        return summary  # Return the aggregated pass/fail counts per algorithm

    # ── tamper testing ──

    @staticmethod
    def _tamper(entry: dict) -> dict:
        """Return a slightly mutated copy of *entry*."""
        tampered = copy.deepcopy(entry)  # Create a full independent copy to avoid side effects
        # Generate a random 4-character suffix to append to the domain field
        suffix = "".join(random.choices(string.ascii_lowercase, k=4))
        # Mutate the domain field — this simulates an attacker modifying log evidence
        tampered["domain"] = tampered["domain"] + suffix
        return tampered  # Return the mutated copy (original entry remains unchanged)

    def tamper_test(self, entry: dict) -> dict[str, dict]:
        """
        For each algorithm, verify the original entry passes and a tampered
        copy fails.  Now also measures the wall-clock *response time* of
        the detection step (re-hash + comparison).
        """
        results: dict[str, dict] = {}  # Will hold per-algorithm test results
        tampered = self._tamper(entry)  # Create a tampered copy of the entry

        for alg in self.engine.algorithms:
            # First, verify that the original (unmodified) entry still passes verification
            original_ok = self.verify(entry, alg)

            # --- timed detection ---
            # Measure how long it takes to detect the tamper (re-hash + digest comparison)
            t0 = time.perf_counter_ns()  # Start the high-resolution timer
            # Hash the tampered entry to get its (different) digest
            tampered_digest = self.engine.hash_entry(tampered, alg)["digest"]
            # Retrieve the original stored digest from the registry for comparison
            original_digest = self._registry.get(entry["entry_id"], {}).get(alg, "")
            # If digests differ, tampering has been detected (avalanche effect)
            tamper_detected = tampered_digest != original_digest
            response_ns = time.perf_counter_ns() - t0  # Calculate detection response time

            results[alg] = {
                "original_valid": original_ok,     # Whether the original entry passed verification
                "tamper_detected": tamper_detected, # Whether the tampered copy was correctly flagged
                "response_ns": response_ns,         # Detection time in nanoseconds
                "original_digest": original_digest[:16] + "\u2026",  # Truncated digest for display
                "tampered_digest": tampered_digest[:16] + "\u2026",  # Truncated tampered digest
            }
        return results  # Return the per-algorithm detection results

    def tamper_test_batch(
        self,
        entries: list[dict],
        tamper_rate_pct: float = 20.0,
    ) -> dict[str, dict]:
        """
        Realistic tamper-detection test.

        A random *tamper_rate_pct* % of entries are deliberately mutated;
        the rest are left intact.  For each algorithm every entry is
        re-verified, producing a full confusion matrix:

        * **TP** — tampered entry correctly flagged
        * **TN** — clean entry correctly passed
        * **FP** — clean entry wrongly flagged  (should be 0 for crypto hashes)
        * **FN** — tampered entry missed         (should be 0 for crypto hashes)

        Also computes accuracy, precision, recall, F1, and response-time
        statistics (mean / median / p95 in µs).
        """
        n_total = len(entries)  # Total number of entries in the test batch
        # Calculate how many entries to tamper (at least 1, even for very small batches)
        n_tamper = max(1, int(n_total * tamper_rate_pct / 100))
        # Randomly select which entry indices will be tampered (without replacement)
        tamper_indices = set(random.sample(range(n_total), n_tamper))

        # Initialise per-algorithm aggregation dictionaries with confusion matrix counters
        agg: dict[str, dict] = {
            alg: {
                "total": n_total,          # Total entries in the batch
                "tampered_count": n_tamper, # Number of entries that were deliberately tampered
                "tamper_rate_pct": round(n_tamper / n_total * 100, 1),  # Actual tamper percentage
                "tp": 0, "tn": 0, "fp": 0, "fn": 0,  # Confusion matrix counters (start at zero)
                "_times_ns": [],  # Private list to accumulate per-entry detection times
            }
            for alg in self.engine.algorithms
        }

        # Iterate through every entry in the batch
        for idx, entry in enumerate(entries):
            is_tampered = idx in tamper_indices  # Check if this entry was selected for tampering
            # If tampered, create a mutated copy; otherwise use the original entry unchanged
            test_entry = self._tamper(entry) if is_tampered else entry

            # Test this entry against every algorithm
            for alg in self.engine.algorithms:
                # Retrieve the original stored digest from the registry
                stored = self._registry.get(entry["entry_id"], {}).get(alg, "")

                t0 = time.perf_counter_ns()  # Start timing the detection operation
                # Recompute the hash of the (possibly tampered) test entry
                recomputed = self.engine.hash_entry(test_entry, alg)["digest"]
                # Check if the recomputed hash differs from the stored baseline
                mismatch = recomputed != stored
                elapsed = time.perf_counter_ns() - t0  # Calculate detection time

                # Record the detection time for later statistical analysis
                agg[alg]["_times_ns"].append(elapsed)

                # Classify the result into one of four confusion matrix categories
                if is_tampered and mismatch:
                    agg[alg]["tp"] += 1      # True Positive: correctly detected tamper
                elif is_tampered and not mismatch:
                    agg[alg]["fn"] += 1      # False Negative: missed tamper (should never happen)
                elif not is_tampered and not mismatch:
                    agg[alg]["tn"] += 1      # True Negative: correctly passed clean entry
                else:  # not tampered but flagged
                    agg[alg]["fp"] += 1      # False Positive: false alarm (should never happen)

        # Compute derived metrics for each algorithm from the confusion matrix counters
        for alg in agg:
            d = agg[alg]  # Shorthand reference to this algorithm's data dict
            tp, tn, fp, fn = d["tp"], d["tn"], d["fp"], d["fn"]  # Extract confusion matrix values
            total = tp + tn + fp + fn  # Total number of classifications made

            # Accuracy: proportion of all predictions that were correct
            d["accuracy"] = round((tp + tn) / total, 4) if total else 0.0
            # Precision: of entries flagged as tampered, how many actually were
            d["precision"] = round(tp / (tp + fp), 4) if (tp + fp) else 0.0
            # Recall: of entries that were tampered, how many were correctly detected
            d["recall"] = round(tp / (tp + fn), 4) if (tp + fn) else 0.0
            # F1-score: harmonic mean of precision and recall (balances both metrics)
            if d["precision"] + d["recall"] > 0:
                d["f1_score"] = round(
                    2 * d["precision"] * d["recall"] / (d["precision"] + d["recall"]), 4
                )
            else:
                d["f1_score"] = 0.0  # Avoid division by zero when both are 0

            # Keep detection_rate for backwards compat (= recall)
            d["detection_rate"] = d["recall"]  # Alias for recall for legacy code compatibility
            d["detected"] = tp                  # Count of correctly detected tampering events
            d["tested"] = d["tampered_count"]   # Count of entries that were tampered

            # Response-time stats — convert nanoseconds to microseconds and sort for percentiles
            times_us = sorted(t / 1_000 for t in d.pop("_times_ns"))  # Pop removes the raw list
            if times_us:
                n = len(times_us)               # Number of timing measurements
                mean = sum(times_us) / n        # Arithmetic mean of detection times
                mid = n // 2                    # Index of the middle element for median
                # Median: average of two middle values if even count, else the middle value
                median = (times_us[mid - 1] + times_us[mid]) / 2 if n % 2 == 0 else times_us[mid]
                # P95 index: the value below which 95% of observations fall
                p95_idx = min(int(n * 0.95), n - 1)
                d["mean_response_us"] = round(mean, 3)              # Mean response time in µs
                d["median_response_us"] = round(median, 3)          # Median response time in µs
                d["p95_response_us"] = round(times_us[p95_idx], 3)  # 95th percentile in µs
            else:
                # No timing data available — set all response time stats to zero
                d["mean_response_us"] = 0.0
                d["median_response_us"] = 0.0
                d["p95_response_us"] = 0.0

        return agg  # Return the full confusion matrix and response time stats per algorithm
