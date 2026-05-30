# detector.py
"""Rule‑based detection module for NIDS.
Implements five simple threshold‑based attacks using per‑IP counters.
Does NOT import Flask, database, ML, or sniffer modules.
"""

# Standard library imports – required for counters and timestamps
import collections  # defaultdict for per‑IP data structures
import time        # time.time() for current epoch seconds

# ---------------------------------------------------------------------------
# Global dictionaries to store recent event timestamps for each source IP.
# Each dict maps src_ip -> list of timestamps (or (ts, port) tuples).
# ---------------------------------------------------------------------------

# DoS detection – track every packet timestamp per IP
_packet_times = collections.defaultdict(list)

# Port‑scan detection – track (timestamp, dst_port) per IP
_port_records = collections.defaultdict(list)

# SYN‑flood detection – track SYN packet timestamps per IP
_syn_times = collections.defaultdict(list)

# ICMP‑flood detection – track ICMP packet timestamps per IP
_icmp_times = collections.defaultdict(list)

# Brute‑force detection – track RST packet timestamps per IP
_rst_times = collections.defaultdict(list)

# ---------------------------------------------------------------------------
# Helper: remove timestamps older than the given time window (seconds).
# Works on a list of timestamps (or (ts, ...) tuples) in‑place.
# ---------------------------------------------------------------------------
def _clean(timestamps, window):
    """Prune entries older than *window* seconds.
    *timestamps* is a list where the first element is the timestamp.
    Returns the cleaned list (the same object)."""
    now = time.time()
    # Keep only entries where now - ts <= window
    # For plain timestamps use the value directly; for tuples use first element.
    while timestamps and (now - (timestamps[0][0] if isinstance(timestamps[0], (list, tuple)) else timestamps[0])) > window:
        timestamps.pop(0)
    return timestamps

# ---------------------------------------------------------------------------
# Individual rule checks – each returns an alert dict or None.
# ---------------------------------------------------------------------------

def check_dos(src_ip):
    """Detect DoS if >100 packets/sec from *src_ip*.
    Severity: High, method: Rule‑Based."""
    now = time.time()
    # Record current packet time
    _packet_times[src_ip].append(now)
    # Remove old timestamps outside 1‑second window
    _clean(_packet_times[src_ip], 1)
    if len(_packet_times[src_ip]) > 100:
        return {
            "src_ip": src_ip,
            "attack_type": "DoS",
            "severity": "High",
            "method": "Rule-Based",
            "detail": f"{len(_packet_times[src_ip])} packets in 1 s"
        }
    return None

def check_port_scan(src_ip, dst_port):
    """Detect port‑scan if >20 unique ports in 10 seconds.
    Severity: Medium."""
    if dst_port is None:
        return None
    now = time.time()
    # Store (timestamp, port) tuple
    _port_records[src_ip].append((now, dst_port))
    # Clean old entries outside 10‑second window
    _clean(_port_records[src_ip], 10)
    # Determine unique ports within the window
    recent_ports = {port for (_, port) in _port_records[src_ip]}
    if len(recent_ports) > 20:
        return {
            "src_ip": src_ip,
            "attack_type": "Port Scan",
            "severity": "Medium",
            "method": "Rule-Based",
            "detail": f"{len(recent_ports)} ports in 10 s"
        }
    return None

def check_syn_flood(src_ip, flags):
    """Detect SYN‑flood if >200 SYN packets in 10 seconds.
    *flags* should contain the string 'SYN'.
    Severity: High."""
    if not flags or "SYN" not in flags.upper():
        return None
    now = time.time()
    _syn_times[src_ip].append(now)
    _clean(_syn_times[src_ip], 10)
    if len(_syn_times[src_ip]) > 200:
        return {
            "src_ip": src_ip,
            "attack_type": "SYN Flood",
            "severity": "High",
            "method": "Rule-Based",
            "detail": f"{len(_syn_times[src_ip])} SYNs in 10 s"
        }
    return None

def check_icmp_flood(src_ip, protocol):
    """Detect ICMP‑flood if >50 ICMP packets in 5 seconds.
    Severity: Medium."""
    if protocol.upper() != "ICMP":
        return None
    now = time.time()
    _icmp_times[src_ip].append(now)
    _clean(_icmp_times[src_ip], 5)
    if len(_icmp_times[src_ip]) > 50:
        return {
            "src_ip": src_ip,
            "attack_type": "ICMP Flood",
            "severity": "Medium",
            "method": "Rule-Based",
            "detail": f"{len(_icmp_times[src_ip])} ICMPs in 5 s"
        }
    return None

def check_brute_force(src_ip, flags):
    """Detect brute‑force if >5 RST packets in 30 seconds.
    *flags* should contain 'RST'.
    Severity: High."""
    if not flags or "RST" not in flags.upper():
        return None
    now = time.time()
    _rst_times[src_ip].append(now)
    _clean(_rst_times[src_ip], 30)
    if len(_rst_times[src_ip]) > 5:
        return {
            "src_ip": src_ip,
            "attack_type": "Brute Force",
            "severity": "High",
            "method": "Rule‑Based",
            "detail": f"{len(_rst_times[src_ip])} RSTs in 30 s"
        }
    return None

# ---------------------------------------------------------------------------
# Master function – runs all rules and returns a list of alerts (may be empty).
# ---------------------------------------------------------------------------

def run_all_rules(src_ip, dst_port, flags, protocol):
    """Execute every rule for the supplied packet data.
    Returns a list of alert dictionaries (empty list if none)."""
    alerts = []
    # Each check returns either an alert dict or None.
    for checker in [
        lambda: check_dos(src_ip),
        lambda: check_port_scan(src_ip, dst_port),
        lambda: check_syn_flood(src_ip, flags),
        lambda: check_icmp_flood(src_ip, protocol),
        lambda: check_brute_force(src_ip, flags),
    ]:
        result = checker()
        if result:
            alerts.append(result)
    return alerts if alerts else []

# End of detector.py
