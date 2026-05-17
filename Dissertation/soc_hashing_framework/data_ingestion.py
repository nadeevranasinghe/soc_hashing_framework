"""
Data Ingestion Module — Certstream Real-Time Feed
==================================================
Connects to the Certstream WebSocket API to collect certificate transparency
log events. Normalises each event into a structured LogEntry dict suitable
for the hashing pipeline. Falls back to simulated data when the live feed
is unavailable.
"""

import abc             # Abstract Base Class support for the Collector interface
import json            # JSON parsing for WebSocket messages and API responses
import logging         # Standard logging for diagnostic and progress messages
import random          # Random generation for simulated data and domain names
import string          # Provides character sets (ascii_lowercase) for random string generation
import threading       # Threading for WebSocket timeout timers and concurrent collection
import time            # Timestamps and timing for log entry generation
import uuid            # UUID generation for unique entry identifiers
import urllib.request  # HTTP request handling for REST API data sources
import urllib.error    # HTTP error handling for REST API failures
from datetime import datetime, timezone  # UTC-aware timestamps for log entries

import config  # Centralised configuration (URLs, batch sizes, timeouts)

logger = logging.getLogger(__name__)  # Create a module-level logger for this file


# ─── LogEntry helper ─────────────────────────────────────────────────

def _make_log_entry(
    domain: str,
    san_domains: list,
    fingerprint: str,
    serial_number: str,
    issuer: str,
    not_before: float,
    not_after: float,
    source_name: str,
    source_url: str,
    seen: float,
    cert_index: int,
) -> dict:
    """Build a normalised SOC log entry from raw Certstream fields."""
    return {
        "entry_id": str(uuid.uuid4()),                       # Unique identifier for this log entry
        "timestamp": datetime.now(timezone.utc).isoformat(),  # ISO 8601 UTC timestamp of ingestion
        "domain": domain,                # Primary domain from the certificate (key field for tampering)
        "san_domains": san_domains,      # Subject Alternative Names listed on the certificate
        "fingerprint": fingerprint,      # Certificate fingerprint (SHA-256 hash of the cert)
        "serial_number": serial_number,  # Certificate serial number (unique per CA)
        "issuer": issuer,                # Certificate Authority that issued the certificate
        "not_before": not_before,        # Certificate validity start time (epoch seconds)
        "not_after": not_after,          # Certificate validity end time (epoch seconds)
        "source_name": source_name,      # Name of the CT log source that reported this certificate
        "source_url": source_url,        # URL of the CT log source
        "seen": seen,                    # Timestamp when the certificate was first observed
        "cert_index": cert_index,        # Index position within the CT log
    }


def serialise_entry(entry: dict) -> bytes:
    """Deterministic JSON serialisation for hashing."""
    # sort_keys=True ensures consistent key ordering across runs
    # separators=(",", ":") removes whitespace for byte-identical output regardless of platform
    # .encode("utf-8") converts the JSON string to bytes for the hash function input
    return json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")


# --- Collector Interface ---

class Collector(abc.ABC):
    """Abstract base class for all real-time data ingestion collectors."""

    def __init__(self, max_entries: int = config.DEFAULT_BATCH_SIZE,
                 duration_sec: int = config.DEFAULT_COLLECTION_DURATION_SEC):
        self.max_entries = max_entries    # Maximum number of entries to collect before stopping
        self.duration_sec = duration_sec  # Maximum collection duration in seconds
        self.entries: list[dict] = []     # Accumulated log entries collected so far

    @abc.abstractmethod
    def collect(self) -> list[dict]:
        """Collect and return a list of normalised LogEntry dictionaries."""
        pass  # Subclasses must implement this method


# --- 1. Certstream Collector ---

class CertstreamCollector(Collector):
    """Collect live Certstream events directly via websocket-client."""

    _WS_URL = config.CERTSTREAM_URL  # WebSocket URL from centralised config

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)  # Initialise base Collector with max_entries and duration
        self._lock = threading.Lock()  # Thread lock to protect shared self.entries list
        self._ws = None                # Will hold the active WebSocket connection object

    def _on_open(self, ws):
        """Callback invoked when the WebSocket connection is successfully established."""
        self._ws = ws  # Store the WebSocket reference for later use (e.g., closing)
        logger.info("Certstream WebSocket opened.")

    def _on_message(self, ws, raw):
        """Callback invoked for each message received from the Certstream WebSocket."""
        logger.debug("Received raw message of length %d", len(raw))
        try:
            message = json.loads(raw)  # Parse the raw WebSocket message as JSON
        except Exception as exc:
            # If JSON parsing fails, log the error and skip this message
            logger.debug("Failed to parse JSON: %s. Raw snippet: %s", exc, raw[:100])
            return

        # Only process certificate_update messages; ignore heartbeats and other types
        if message.get("message_type") != "certificate_update":
            logger.debug("Ignoring message type: %s", message.get("message_type"))
            return

        # Extract nested data structures from the Certstream message payload
        data = message.get("data", {})           # Top-level data object
        leaf = data.get("leaf_cert", {})          # The leaf (end-entity) certificate details
        subject = leaf.get("subject", {})         # Certificate subject fields (e.g., CN)
        all_domains = leaf.get("all_domains", []) # All domains covered by this certificate
        source = data.get("source", {})           # CT log source metadata

        # Use the first domain as the primary domain; fall back to Common Name or "unknown"
        domain = all_domains[0] if all_domains else (subject.get("CN") or "unknown")
        # Remaining domains become Subject Alternative Names (SANs)
        san_domains = all_domains[1:] if len(all_domains) > 1 else []

        # Build a normalised log entry from the extracted certificate fields
        entry = _make_log_entry(
            domain=domain,
            san_domains=san_domains,
            fingerprint=leaf.get("fingerprint", ""),       # Certificate fingerprint hash
            serial_number=leaf.get("serial_number", ""),   # Certificate serial number
            issuer=subject.get("aggregated", ""),           # Aggregated issuer string
            not_before=leaf.get("not_before", 0.0),        # Validity start (epoch)
            not_after=leaf.get("not_after", 0.0),          # Validity end (epoch)
            source_name=source.get("name", ""),             # CT log source name
            source_url=source.get("url", ""),               # CT log source URL
            seen=data.get("seen", 0.0),                     # When the cert was first seen
            cert_index=data.get("cert_index", 0),           # Index in the CT log
        )

        # Thread-safe append to the shared entries list
        with self._lock:
            if len(self.entries) < self.max_entries:
                self.entries.append(entry)  # Add the new entry to the collection
                count = len(self.entries)
                # Log progress every 50 entries to show collection is proceeding
                if count % 50 == 0:
                    logger.info("Collected %d / %d entries", count, self.max_entries)
            # If we've reached the target count, close the WebSocket to stop collection
            if len(self.entries) >= self.max_entries:
                logger.info("Reached max_entries=%d — closing connection.", self.max_entries)
                ws.close()

    def _on_error(self, ws, error):
        """Callback invoked when a WebSocket error occurs."""
        logger.warning("Certstream WebSocket error: %s", error)

    def _on_close(self, ws, close_status_code, close_msg):
        """Callback invoked when the WebSocket connection closes."""
        logger.info("Certstream WebSocket closed.")

    def collect(self) -> list[dict]:
        """Connect to Certstream and collect entries until max or timeout."""
        import websocket as _websocket  # Imported here to avoid hard dependency at module level

        logger.info(
            "Connecting to Certstream (%s) - collecting up to %d entries for %d s ...",
            self._WS_URL, self.max_entries, self.duration_sec,
        )

        # Create the WebSocket application with all four event callbacks
        ws = _websocket.WebSocketApp(
            self._WS_URL,
            on_open=self._on_open,       # Called when connection opens
            on_message=self._on_message, # Called for each incoming message
            on_error=self._on_error,     # Called on connection errors
            on_close=self._on_close,     # Called when connection closes
        )

        def _timeout():
            """Timer callback: force-close the WebSocket after duration_sec seconds."""
            logger.info("Collection timeout reached - closing WebSocket.")
            ws.close()

        # Start a daemon timer that will close the WebSocket after the configured duration
        timer = threading.Timer(self.duration_sec, _timeout)
        timer.daemon = True  # Daemon thread won't block program exit
        timer.start()

        try:
            ws.run_forever()  # Block until WebSocket closes (from timeout or max_entries)
        finally:
            timer.cancel()  # Cancel the timer if we finished before timeout

        logger.info("Certstream collection finished - %d entries captured.", len(self.entries))
        return self.entries  # Return all collected entries


# --- 2. URLhaus Collector ---

class URLhausCollector(Collector):
    """Collects recent malware payload URLs from the Abuse.ch URLhaus API."""

    def collect(self) -> list[dict]:
        """Fetch malware URL data from URLhaus REST API and normalise into log entries."""
        import ssl  # SSL context needed to handle certificate verification
        logger.info("Fetching recent malware payloads from URLhaus (%s) ...", config.URLHAUS_URL)
        # Build HTTP request with a custom User-Agent header to identify the framework
        req = urllib.request.Request(config.URLHAUS_URL, headers={'User-Agent': 'SOC-Hashing-Framework/1.0'})
        # Create an SSL context that skips certificate verification (some feeds have cert issues)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False       # Disable hostname verification
        ctx.verify_mode = ssl.CERT_NONE  # Disable certificate verification entirely
        
        try:
            # Send the HTTP GET request with a 10-second timeout
            with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
                if response.status != 200:
                    logger.error("URLhaus returned HTTP %d", response.status)
                    return []  # Return empty list on non-200 responses
                # Parse the JSON response body into a Python dictionary
                data = json.loads(response.read().decode("utf-8"))
        except urllib.error.URLError as e:
            logger.error("Failed to connect to URLhaus: %s", e)
            return []  # Return empty list on connection failure

        # The public JSON endpoint returns a dict mapping UUID to a list of records ( usually 1 element )
        # We flatten all lists of payloads into one massive list
        all_payloads = []  # Will hold all payload records across all UUIDs
        for payload_list in data.values():
            all_payloads.extend(payload_list)  # Flatten nested lists into a single list

        logger.info("Received %d payload records from URLhaus.", len(all_payloads))

        now = time.time()  # Current epoch timestamp for log entry fields
        # Process up to max_entries payloads from the flattened list
        for idx, payload in enumerate(all_payloads[:self.max_entries]):
            # Use urllib.parse to safely extract the domain if 'url' is the only thing we have reliably
            from urllib.parse import urlparse  # Import here to avoid overhead if not needed
            
            raw_url = payload.get("url", "")        # Get the malware URL string
            domain = urlparse(raw_url).netloc or "unknown"  # Extract domain from URL
            # Fallback: if urlparse couldn't extract a domain, try the 'urlhost' field
            if not domain and "urlhost" in payload:
                domain = payload.get("urlhost")

            # Build a normalised log entry from the URLhaus payload fields
            entry = _make_log_entry(
                domain=domain,                                 # Extracted domain from the URL
                san_domains=[],                                # URLhaus payloads have no SANs
                fingerprint=payload.get("sha256_hash", ""),    # SHA-256 hash of the payload file
                serial_number=payload.get("id", ""),           # URLhaus internal record ID
                issuer="URLhaus",                              # Static issuer identifying the source
                not_before=now,                                # Use current time as placeholder
                not_after=now,                                 # Use current time as placeholder
                source_name=payload.get("reporter", "unknown"),# Who reported this URL
                source_url=payload.get("urlhaus_link", ""),    # Link to the URLhaus entry page
                seen=now,                                      # Timestamp of ingestion
                cert_index=idx,                                # Sequential index in this batch
            )
            self.entries.append(entry)  # Add the normalised entry to the collection

        logger.info("URLhaus collection finished - %d entries captured.", len(self.entries))
        return self.entries  # Return all collected entries


# --- 3. AlienVault OTX Collector ---

class OTXCollector(Collector):
    """
    Collects recent Pulse indicators from AlienVault OTX Activity API.
    Requires an API Key; falls back to simulated threat data if missing/failed.
    """

    def collect(self) -> list[dict]:
        """Fetch threat intelligence pulses from OTX API, or simulate if unavailable."""
        import ssl  # SSL context for API request
        # Check if an API key is configured; if not, fall back to simulated data immediately
        if not config.OTX_API_KEY:
            logger.warning("No OTX API Key provided. Falling back to simulated OTX data.")
            return self._simulate_otx_data()

        logger.info("Fetching recent Pulses from AlienVault OTX (%s) ...", config.OTX_URL)
        # Build HTTP request with the OTX API key in the header for authentication
        req = urllib.request.Request(config.OTX_URL, headers={
            'X-OTX-API-KEY': config.OTX_API_KEY,              # Authentication header
            'User-Agent': 'SOC-Hashing-Framework/1.0'          # Identify the framework
        })
        # Create an SSL context (skipping verification for compatibility)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False       # Disable hostname verification
        ctx.verify_mode = ssl.CERT_NONE  # Disable certificate verification

        try:
            # Send authenticated GET request to the OTX Activity API
            with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
                data = json.loads(response.read().decode("utf-8"))  # Parse JSON response
                pulses = data.get("results", [])  # Extract the list of threat intelligence pulses
                logger.info("Received %d pulses from OTX.", len(pulses))
                
                now = time.time()  # Current epoch timestamp for log entry fields
                idx = 0  # Sequential counter for entries across all pulses
                # Iterate through each pulse (a curated threat report)
                for pulse in pulses:
                    if len(self.entries) >= self.max_entries:
                        break  # Stop if we've reached the target entry count
                    
                    author = pulse.get("author_name", "unknown")  # Who created this pulse
                    # Each pulse contains multiple indicators (IPs, domains, hashes, etc.)
                    for indicator in pulse.get("indicators", []):
                        if len(self.entries) >= self.max_entries:
                            break  # Stop if we've reached the target entry count
                        
                        # Build a normalised log entry from the OTX indicator fields
                        entry = _make_log_entry(
                            domain=indicator.get("indicator", "unknown"),  # The threat indicator value
                            san_domains=[],                                # OTX indicators have no SANs
                            fingerprint="",                                # No fingerprint for indicators
                            serial_number=str(indicator.get("id", "")),    # OTX indicator ID
                            issuer="AlienVault OTX",                       # Static source identifier
                            not_before=now,                                # Timestamp placeholder
                            not_after=now,                                 # Timestamp placeholder
                            source_name=author,                            # Pulse author name
                            source_url=pulse.get("id", ""),                # Pulse ID for reference
                            seen=now,                                      # Ingestion timestamp
                            cert_index=idx,                                # Sequential index
                        )
                        self.entries.append(entry)  # Add the entry to the collection
                        idx += 1  # Increment the sequential counter
                        
        except urllib.error.URLError as e:
            # If the API request fails, fall back to simulated data
            logger.error("Failed to connect to OTX API: %s. Falling back to simulated OTX data.", e)
            return self._simulate_otx_data()

        # If no entries were collected (e.g., empty API response), fall back to simulation
        if not self.entries:
            return self._simulate_otx_data()

        logger.info("OTX collection finished - %d entries captured.", len(self.entries))
        return self.entries  # Return all collected entries

    def _simulate_otx_data(self) -> list[dict]:
        """Provides simulated OTX threat indicators if API is unavailable."""
        logger.info("Generating %d simulated OTX threat indicators...", self.max_entries)
        now = time.time()  # Current epoch timestamp for simulated entries
        for i in range(self.max_entries):
            # Generate a realistic-looking malicious domain name with a random numeric suffix
            entry = _make_log_entry(
                domain=f"malicious-domain-{random.randint(1000, 9999)}.evil",  # Random evil domain
                san_domains=[],                                # No SANs for simulated data
                fingerprint="",                                # No fingerprint for simulated data
                serial_number=str(uuid.uuid4()),               # Random UUID as serial number
                issuer="AlienVault OTX (Simulated)",            # Mark as simulated in the issuer
                not_before=now,                                # Current time as validity start
                not_after=now,                                 # Current time as validity end
                source_name=random.choice(["AlienVault", "CrowdStrike", "ThreatConnect"]),  # Random source
                source_url=f"pulse_{random.randint(100, 999)}",# Simulated pulse ID
                seen=now,                                      # Ingestion timestamp
                cert_index=i,                                  # Sequential index
            )
            self.entries.append(entry)  # Add simulated entry to the collection
        return self.entries  # Return all simulated entries


# --- 4. CISA AIS Collector (Simulated) ---

class CISAAISCollector(Collector):
    """
    Simulated Automated Indicator Sharing (AIS) by CISA.
    Real AIS requires heavily privileged TAXII feeds, PKI certificates, and DHS
    approval, so we generate highly accurate mocked STIX/TAXII-like parameters.
    """

    def collect(self) -> list[dict]:
        """Generate simulated CISA AIS STIX/TAXII indicator objects."""
        logger.info("Generating %d simulated CISA AIS (STIX/TAXII) objects...", self.max_entries)
        now = time.time()  # Current epoch timestamp for simulated entries
        for i in range(self.max_entries):
            # Generate a STIX-compliant indicator ID (format: indicator--<UUID>)
            stix_id = f"indicator--{uuid.uuid4()}"
            # Build a simulated government-grade threat indicator entry
            entry = _make_log_entry(
                domain=f"{_random_hex(6)}.apt-c2.net",  # Simulated APT command-and-control domain
                san_domains=[],                          # No SANs for STIX indicator objects
                fingerprint=_random_hex(64),             # Simulated 256-bit file hash (64 hex chars)
                serial_number=stix_id,                   # Use the STIX ID as the serial number
                issuer="CISA AIS (Simulated)",           # Mark as simulated government source
                not_before=now,                          # Indicator validity start time
                not_after=now + 86400 * 30,              # Indicator valid for 30 days
                source_name=random.choice(["NCCIC", "FBI", "DHS"]),  # Random US government agency
                source_url="taxii2_collection",          # Simulated TAXII collection endpoint
                seen=now,                                # Timestamp when indicator was "observed"
                cert_index=i,                            # Sequential index in the batch
            )
            self.entries.append(entry)  # Add the simulated entry to the collection
        
        logger.info("CISA AIS collection finished - %d entries captured.", len(self.entries))
        return self.entries  # Return all simulated entries




# ─── Simulated data (demo / offline mode) ────────────────────────────

# List of realistic top-level domains for generating random domain names
_DEMO_TLDS = [".com", ".org", ".net", ".io", ".co.uk", ".dev", ".edu"]
# List of realistic Certificate Authority names for simulated certificates
_DEMO_ISSUERS = [
    "Let's Encrypt Authority X3",
    "DigiCert SHA2 Extended Validation Server CA",
    "Comodo RSA Domain Validation Secure Server CA",
    "GlobalSign CloudSSL CA - SHA256 - G3",
    "Amazon Root CA 1",
]
# List of realistic CT log source names and URLs for simulated entries
_DEMO_SOURCES = [
    ("Google 'Argon2024' log", "ct.googleapis.com/logs/argon2024"),
    ("Cloudflare 'Nimbus2024'", "ct.cloudflare.com/logs/nimbus2024"),
    ("Comodo 'Sabre' CT log", "sabre.ct.comodo.com"),
    ("DigiCert Yeti2024 Log", "yeti2024.ct.digicert.com/log"),
]


def _random_domain() -> str:
    """Generate a random domain name with a realistic TLD."""
    name_len = random.randint(5, 15)  # Random length between 5 and 15 characters
    # Generate a random string of lowercase letters as the domain name
    name = "".join(random.choices(string.ascii_lowercase, k=name_len))
    tld = random.choice(_DEMO_TLDS)  # Pick a random top-level domain
    return name + tld  # Concatenate name and TLD (e.g., "abcdefgh.com")


def _random_hex(length: int) -> str:
    """Generate a random hexadecimal string of the specified length."""
    # Produces a string of random hex characters (0-9, a-f) of the given length
    return "".join(random.choices("0123456789abcdef", k=length))


def generate_simulated_entries(count: int = config.DEFAULT_BATCH_SIZE) -> list[dict]:
    """
    Generate *count* realistic-looking SOC log entries that mimic the
    structure of live Certstream events — useful for offline benchmarking.
    """
    logger.info("Generating %d simulated Certstream log entries …", count)
    entries = []          # List to accumulate all generated entries
    now = time.time()     # Current epoch timestamp as the base for all simulated times

    for i in range(count):
        domain = _random_domain()  # Generate a random primary domain
        san_count = random.randint(0, 4)  # Random number of Subject Alternative Names (0-4)
        # Generate random SAN domains (each is an independently generated random domain)
        sans = [_random_domain() for _ in range(san_count)]
        src = random.choice(_DEMO_SOURCES)  # Pick a random CT log source

        # Build a complete simulated log entry with realistic field values
        entry = _make_log_entry(
            domain=domain,
            san_domains=sans,
            # Generate a colon-separated fingerprint (20 pairs of hex digits, like a real cert)
            fingerprint=":".join(_random_hex(2).upper() for _ in range(20)),
            serial_number=_random_hex(34),  # 34-character hex serial number
            issuer=random.choice(_DEMO_ISSUERS),  # Random Certificate Authority
            # not_before: random time within the past year
            not_before=now - random.uniform(0, 86400 * 365),
            # not_after: random time between 30 days and 2 years in the future
            not_after=now + random.uniform(86400 * 30, 86400 * 730),
            source_name=src[0],  # CT log source display name
            source_url=src[1],   # CT log source URL
            # seen: random time within the last 60 seconds (simulates near-real-time observation)
            seen=now - random.uniform(0, 60),
            # cert_index: random large number simulating a position in a real CT log
            cert_index=random.randint(10_000_000, 99_999_999),
        )
        entries.append(entry)  # Add the generated entry to the list

    logger.info("Simulated data generation complete — %d entries.", len(entries))
    return entries  # Return all generated entries
