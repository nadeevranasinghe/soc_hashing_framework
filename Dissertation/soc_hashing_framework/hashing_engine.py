"""
Hashing Engine — Modular Cryptographic Hashing Pipeline
========================================================
Provides a unified interface to hash SOC log entries with MD5, SHA-256,
SHA3-256, and BLAKE2b. Each call returns the digest together with
high-resolution timing so the performance monitor can aggregate metrics.
"""

import hashlib  # Python standard library providing access to MD5, SHA-256, SHA3-256, BLAKE2b
import time     # Used for nanosecond-precision timing of each hash operation
from typing import Optional  # Type hint support for optional parameters

import blake3 as _blake3_mod  # Third-party Rust-backed BLAKE3 implementation (not in stdlib)

import config                      # Centralised configuration (algorithm list, display names)
from data_ingestion import serialise_entry  # Deterministic JSON serialiser for log entries


# ─── Individual hasher functions ─────────────────────────────────────
# Each function takes raw bytes and returns the hexadecimal digest string.
# These are thin wrappers around the underlying C/Rust implementations.

def _hash_md5(data: bytes) -> str:
    """Compute MD5 digest of the input bytes (128-bit, legacy algorithm)."""
    return hashlib.md5(data).hexdigest()  # Returns 32-character hex string


def _hash_sha256(data: bytes) -> str:
    """Compute SHA-256 digest of the input bytes (256-bit, NIST standard)."""
    return hashlib.sha256(data).hexdigest()  # Returns 64-character hex string


def _hash_sha3_256(data: bytes) -> str:
    """Compute SHA3-256 digest of the input bytes (256-bit, Keccak-based)."""
    return hashlib.sha3_256(data).hexdigest()  # Returns 64-character hex string


def _hash_blake2b(data: bytes) -> str:
    """Compute BLAKE2b digest of the input bytes (512-bit default output)."""
    return hashlib.blake2b(data).hexdigest()  # Returns 128-character hex string (64 bytes)


def _hash_blake3(data: bytes) -> str:
    """Compute BLAKE3 digest using the external Rust-backed blake3 package."""
    return _blake3_mod.blake3(data).hexdigest()  # Returns 64-character hex string (32 bytes)


# Lookup table mapping algorithm name strings to their corresponding hash functions
# This enables the engine to dynamically select a hasher at runtime by name
_HASHERS = {
    "md5":      _hash_md5,       # Legacy — included for comparative benchmarking
    "sha256":   _hash_sha256,    # Industry standard — OpenSSL-backed C extension
    "sha3_256": _hash_sha3_256,  # Keccak sponge construction — different internal design to SHA-2
    "blake2b":  _hash_blake2b,   # BLAKE family — optimised for 64-bit platforms
    "blake3":   _hash_blake3,    # Latest BLAKE variant — supports parallelism via Merkle tree
}


# ─── Public API ──────────────────────────────────────────────────────

class HashingEngine:
    """
    Pluggable hashing engine that applies one or more algorithms to
    serialised log entries and records per-hash timing.
    """

    def __init__(self, algorithms: Optional[list[str]] = None):
        # Use the provided algorithm list, or default to all configured algorithms
        self.algorithms = algorithms or list(config.HASH_ALGORITHMS)
        # Validate that every requested algorithm has a registered hasher function
        for alg in self.algorithms:
            if alg not in _HASHERS:
                raise ValueError(f"Unsupported algorithm: {alg}")  # Fail fast on invalid config

    # ── single entry, single algorithm ──
    def hash_entry(self, entry: dict, algorithm: str) -> dict:
        """
        Hash a single log entry with the given algorithm.

        Returns
        -------
        dict  with keys: algorithm, digest, time_ns
        """
        data = serialise_entry(entry)          # Convert dict to deterministic JSON byte string
        start = time.perf_counter_ns()         # Record start time in nanoseconds
        digest = _HASHERS[algorithm](data)     # Invoke the appropriate hash function
        elapsed = time.perf_counter_ns() - start  # Calculate elapsed time in nanoseconds
        return {
            "algorithm": algorithm,  # Which algorithm was used
            "digest": digest,        # The resulting hexadecimal hash digest
            "time_ns": elapsed,      # Time taken in nanoseconds for this single hash
        }

    # ── single entry, all algorithms ──
    def hash_entry_all(self, entry: dict) -> list[dict]:
        """Hash one log entry with every configured algorithm."""
        # List comprehension iterates over all algorithms, returning a result dict for each
        return [self.hash_entry(entry, alg) for alg in self.algorithms]

    # ── batch, single algorithm ──
    def hash_batch(self, entries: list[dict], algorithm: str) -> list[dict]:
        """Hash a list of log entries with a single algorithm."""
        # Applies hash_entry to every entry in the batch using the specified algorithm
        return [self.hash_entry(e, algorithm) for e in entries]

    # ── batch, all algorithms ──
    def hash_batch_all(self, entries: list[dict]) -> dict[str, list[dict]]:
        """
        Hash every entry with every algorithm.

        Returns
        -------
        dict  mapping algorithm name → list of result dicts
        """
        # Produces a dictionary where each key is an algorithm name and each value
        # is a list of hash results for all entries processed with that algorithm
        return {alg: self.hash_batch(entries, alg) for alg in self.algorithms}

    # ── raw bytes convenience ──
    @staticmethod
    def hash_raw(data: bytes, algorithm: str) -> dict:
        """Hash arbitrary bytes (useful for integrity re-verification)."""
        start = time.perf_counter_ns()         # Record start time in nanoseconds
        digest = _HASHERS[algorithm](data)     # Hash the raw byte payload directly
        elapsed = time.perf_counter_ns() - start  # Calculate elapsed nanoseconds
        return {"algorithm": algorithm, "digest": digest, "time_ns": elapsed}
