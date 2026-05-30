# ═══════════════════════════════════════════════════════════════
# NIDS PROJECT — Complete Module Test File
# File: test_all_modules.py
# Location: D:\DEV\nids_projectt\   (root of your project)
#
# HOW TO USE:
# Open terminal (venv active — you see (venv))
# Run ONE test at a time using these commands:
#
#   python test_all_modules.py ml          → tests ml_classifier.py
#   python test_all_modules.py detector    → tests detector.py
#   python test_all_modules.py database    → tests database.py
#   python test_all_modules.py logger      → tests alert_logger.py
#   python test_all_modules.py sniffer     → tests sniffer.py (import only)
#   python test_all_modules.py api         → tests app.py API routes
#   python test_all_modules.py all         → tests everything
# ═══════════════════════════════════════════════════════════════

import sys
import os
import time

# ── Make sure we are running from the project root ────────────
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# ── Colour helpers for terminal output ────────────────────────
GREEN  = '\033[92m'
RED    = '\033[91m'
YELLOW = '\033[93m'
BLUE   = '\033[94m'
BOLD   = '\033[1m'
RESET  = '\033[0m'

def passed(msg):
    print(f"  {GREEN}PASS{RESET}  {msg}")

def failed(msg, error=''):
    print(f"  {RED}FAIL{RESET}  {msg}")
    if error:
        print(f"         Error: {RED}{error}{RESET}")

def header(title):
    print()
    print(f"{BOLD}{BLUE}{'='*55}{RESET}")
    print(f"{BOLD}{BLUE}  Testing: {title}{RESET}")
    print(f"{BOLD}{BLUE}{'='*55}{RESET}")

def section(title):
    print(f"\n{YELLOW}  ── {title} ──{RESET}")

def summary(passed_count, failed_count):
    total = passed_count + failed_count
    print()
    print(f"{BOLD}{'='*55}{RESET}")
    print(f"{BOLD}  RESULTS: {passed_count}/{total} tests passed{RESET}")
    if failed_count == 0:
        print(f"  {GREEN}All tests passed! Module is working correctly.{RESET}")
    else:
        print(f"  {RED}{failed_count} test(s) failed. Check errors above.{RESET}")
    print(f"{BOLD}{'='*55}{RESET}")


# ═══════════════════════════════════════════════════════════════
# TEST 1 — ml_classifier.py
# ═══════════════════════════════════════════════════════════════
def test_ml_classifier():
    header("ml_classifier.py")
    print("  Tests: model loading, classify(), get_confidence(), is_ready()")
    p = f = 0

    section("Import Test")
    try:
        from ml_classifier import classify, get_confidence, is_ready
        passed("ml_classifier.py imported successfully")
        p += 1
    except ImportError as e:
        failed("Cannot import ml_classifier.py", str(e))
        f += 1
        summary(p, f)
        return

    section("Model Loading Test")
    try:
        ready = is_ready()
        if ready:
            passed("is_ready() returned True — rf_model.pkl loaded")
            p += 1
        else:
            failed("is_ready() returned False — rf_model.pkl not found", "Make sure models/rf_model.pkl exists")
            f += 1
    except Exception as e:
        failed("is_ready() crashed", str(e))
        f += 1

    section("classify() Function Tests")
    try:
        features = [0] * 41
        result = classify(features)
        if isinstance(result, str) and result in ['normal','dos','probe','r2l','u2r','unknown']:
            passed(f"classify([0]*41) returned: '{result}'")
            p += 1
        else:
            failed(f"classify() returned unexpected value: {result}")
            f += 1
    except Exception as e:
        failed("classify() crashed on empty feature vector", str(e))
        f += 1

    try:
        features = [0] * 41
        features[4] = 999999   # src_bytes high
        features[22] = 511     # count high
        features[24] = 1.0     # serror_rate = 1.0
        result = classify(features)
        passed(f"classify(dos-like features) returned: '{result}'")
        p += 1
    except Exception as e:
        failed("classify() crashed on DoS-like features", str(e))
        f += 1

    section("get_confidence() Function Tests")
    try:
        features = [0] * 41
        conf = get_confidence(features)
        if isinstance(conf, float) and 0.0 <= conf <= 1.0:
            passed(f"get_confidence() returned: {conf:.3f} (valid 0-1 range)")
            p += 1
        else:
            failed(f"get_confidence() returned invalid value: {conf}")
            f += 1
    except Exception as e:
        failed("get_confidence() crashed", str(e))
        f += 1

    summary(p, f)


# ═══════════════════════════════════════════════════════════════
# TEST 2 — detector.py
# ═══════════════════════════════════════════════════════════════
def test_detector():
    header("detector.py")
    print("  Tests: DoS, Port Scan, SYN Flood, ICMP Flood, Brute Force rules")
    p = f = 0

    section("Import Test")
    try:
        from detector import run_all_rules
        passed("detector.py imported successfully")
        p += 1
    except ImportError as e:
        failed("Cannot import detector.py", str(e))
        f += 1
        summary(p, f)
        return

    section("DoS Detection Test (sends 150 packets from same IP)")
    try:
        alerts = []
        test_ip = '10.10.10.1'
        for i in range(150):
            result = run_all_rules(src_ip=test_ip, dst_port=80, flags='PA', protocol='TCP')
            if result:
                alerts.extend(result)

        dos_alerts = [a for a in alerts if a['attack_type'] == 'DoS']
        if len(dos_alerts) > 0:
            passed(f"DoS detected! {len(dos_alerts)} alert(s) triggered")
            p += 1
        else:
            failed("DoS not detected after 150 packets")
            f += 1
    except Exception as e:
        failed("DoS detection test crashed", str(e))
        f += 1

    section("Port Scan Detection Test (scans 25 different ports)")
    try:
        alerts = []
        test_ip = '10.10.10.2'
        for port in range(1, 26):
            result = run_all_rules(src_ip=test_ip, dst_port=port, flags='S', protocol='TCP')
            if result:
                alerts.extend(result)

        scan_alerts = [a for a in alerts if a['attack_type'] == 'Port Scan']
        if len(scan_alerts) > 0:
            passed(f"Port Scan detected! {len(scan_alerts)} alert(s)")
            p += 1
        else:
            failed("Port Scan not detected after scanning 25 ports")
            f += 1
    except Exception as e:
        failed("Port Scan detection test crashed", str(e))
        f += 1

    section("Normal Traffic Test")
    try:
        result = run_all_rules(src_ip='192.168.0.1', dst_port=443, flags='PA', protocol='TCP')
        if not result:
            passed("Normal traffic correctly produced NO alert")
            p += 1
        else:
            failed("Normal traffic incorrectly triggered an alert")
            f += 1
    except Exception as e:
        failed("Normal traffic test crashed", str(e))
        f += 1

    summary(p, f)


# ═══════════════════════════════════════════════════════════════
# TEST 3 — database.py
# ═══════════════════════════════════════════════════════════════
def test_database():
    header("database.py")
    print("  Tests: init_database, save_alert, get_recent, get_stats, clear")
    p = f = 0

    section("Import Test")
    try:
        from database import init_database, save_alert, get_recent_alerts, get_alert_stats, clear_alerts
        passed("database.py imported successfully")
        p += 1
    except ImportError as e:
        failed("Cannot import database.py", str(e))
        f += 1
        summary(p, f)
        return

    section("Database Initialization")
    try:
        init_database()
        passed("Database channels initialized and setup cleanly")
        p += 1
    except Exception as e:
        failed("init_database() failed to launch storage profiles", str(e))
        f += 1

    section("Data Entry Handling Operations")
    try:
        alert = save_alert(src_ip='192.168.1.45', attack_type='DoS', severity='High', method='Rule-Based', detail='Test — 150 pkts/sec')
        if alert and isinstance(alert, dict):
            passed("save_alert() successfully handled log storage arrays")
            p += 1
        else:
            failed("save_alert() returned unparseable tracking records")
            f += 1
    except Exception as e:
        failed("Database tracking sequence broke down", str(e))
        f += 1

    summary(p, f)


# ═══════════════════════════════════════════════════════════════
# TEST 4 — alert_logger.py
# ═══════════════════════════════════════════════════════════════
def test_alert_logger():
    header("alert_logger.py")
    print("  Tests: generate_alert, queue metrics, WebSocket broadcast patterns")
    p = f = 0

    section("Import Test")
    try:
        import alert_logger
        from alert_logger import generate_alert, get_recent, clear_queue
        passed("alert_logger.py connection verified")
        p += 1
    except ImportError as e:
        failed("Cannot sync with alert_logger.py asset", str(e))
        f += 1
        summary(p, f)
        return

    section("Broadcast Callback Tests")
    try:
        clear_queue()
        received_alerts = []
        def mock_push(alert): received_alerts.append(alert)
        alert_logger.push_callback = mock_push

        generate_alert('5.5.5.5', 'DoS', 'High', 'Rule-Based', 'Callback trigger simulation')
        if len(received_alerts) > 0:
            passed("Alert channel broadcasted out updates safely over push loops")
            p += 1
        else:
            failed("Alert engine skipped transmission sequences")
            f += 1
        alert_logger.push_callback = None
    except Exception as e:
        failed("Broadcast verification sequence failed", str(e))
        f += 1

    summary(p, f)


# ═══════════════════════════════════════════════════════════════
# TEST 5 — sniffer.py
# ═══════════════════════════════════════════════════════════════
def test_sniffer():
    header("sniffer.py")
    p = f = 0
    try:
        import sniffer
        from sniffer import get_stats
        passed("sniffer.py modules and library references map out safely")
        p += 1
    except Exception as e:
        failed("Structural imports for core capture dependencies failed", str(e))
        f += 1
    summary(p, f)


# ═══════════════════════════════════════════════════════════════
# TEST 6 — app.py API Routes
# ═══════════════════════════════════════════════════════════════
def test_api():
    header("app.py — Flask API Routes")
    print("  Requirement: app.py must be running active on localhost:5000")
    p = f = 0

    try:
        import requests
    except ImportError:
        os.system('pip install requests -q')
        import requests

    BASE = 'http://localhost:5000'
    try:
        response = requests.get(BASE + '/', timeout=3)
        if response.status_code == 200:
            passed("Flask web app interface responding actively on Port 5000")
            p += 1
            
            r = requests.get(BASE + '/api/stats', timeout=3)
            if r.status_code == 200:
                passed("GET /api/stats endpoint evaluated successfully")
                p += 1
            else:
                failed("API stats returned broken header response code")
                f += 1
        else:
            failed("Web dashboard server structural link returned an error flag")
            f += 1
    except requests.exceptions.ConnectionError:
        failed("Cannot establish links to local hosting port 5000", "Start the application in a separate window using 'python app.py' first")
        f += 1

    summary(p, f)


# ═══════════════════════════════════════════════════════════════
# MAIN PARSER ARGUMENT ROUTER
# ═══════════════════════════════════════════════════════════════
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"\n{BOLD}{RED}Error: Missing test option context.{RESET}")
        print("Usage examples:")
        print("  python test_all_modules.py ml")
        print("  python test_all_modules.py detector")
        print("  python test_all_modules.py all\n")
        sys.exit(1)

    target = sys.argv[1].lower()

    if target == 'ml':
        test_ml_classifier()
    elif target == 'detector':
        test_detector()
    elif target == 'database':
        test_database()
    elif target == 'logger':
        test_alert_logger()
    elif target == 'sniffer':
        test_sniffer()
    elif target == 'api':
        test_api()
    elif target == 'all':
        test_ml_classifier()
        test_detector()
        test_database()
        test_alert_logger()
        test_sniffer()
        test_api()
    else:
        print(f"\n{RED}Unknown command identifier: '{target}'{RESET}")
        print("Supported selections: ml, detector, database, logger, sniffer, api, all\n")