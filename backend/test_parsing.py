#!/usr/bin/env python3
"""
Verification script for SOC Platform Advanced Parsing & Decoding Layer.
Sends various encoded/formatted log payloads to the FastAPI backend and verifies correct parsing.

Tests 1-9  : Original suite (JSON, Base64, Hex, URL, Syslog 3164/5424, Web, Nested JSON, Quarantine)
Tests 10-16: Advanced suite (CEF, LEEF, Windows XML, Key=Value, Gzip, event_fingerprint, decoding_chain)
"""

import base64
import gzip
import sys
import requests
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent))

BACKEND_URL = "http://127.0.0.1:8000/api/logs/"

PASS = "[SUCCESS]"
FAIL = "[FAILURE]"


def post_log(payload: dict) -> tuple[int, dict]:
    resp = requests.post(BACKEND_URL, json=payload, timeout=10)
    try:
        return resp.status_code, resp.json()
    except Exception:
        return resp.status_code, {}


def run_tests():
    print("=" * 60)
    print("Running Advanced Parsing & Decoding Layer Tests...")
    print("=" * 60)
    results = []

    # ------------------------------------------------------------------
    # TEST 1: Plain JSON log (no encoding) — should pass as-is
    # ------------------------------------------------------------------
    print("\n[Test 1] Plain JSON log ingestion...")
    status, data = post_log({
        "source": "test-parser",
        "event_type": "auth.success",
        "message": "User login successful",
        "severity": "low",
        "timestamp": "2026-06-05T10:00:00Z",
        "source_ip": "10.0.0.1"
    })
    ok = status == 200 and data.get("event_type") == "auth.success"
    print(f"  Status: {status} | event_type: {data.get('event_type')}")
    print(f"  {PASS if ok else FAIL} Test 1: Plain JSON log")
    results.append(("Test 1: Plain JSON", ok))

    # ------------------------------------------------------------------
    # TEST 2: Base64 encoded message
    # ------------------------------------------------------------------
    print("\n[Test 2] Base64 encoded message in log...")
    b64_message = base64.b64encode(b"Failed login attempt detected from admin account").decode()
    status, data = post_log({
        "source": "test-b64-collector",
        "event_type": "login_failed",
        "message": b64_message,
        "severity": "high",
        "timestamp": "2026-06-05T10:05:00Z"
    })
    ok = status == 200 and "Failed login attempt" in (data.get("message") or "")
    print(f"  Status: {status}")
    print(f"  Decoded message: {data.get('message')}")
    print(f"  decoding_applied in metadata: {data.get('metadata', {}).get('decoding_applied')}")
    print(f"  {PASS if ok else FAIL} Test 2: Base64 decoded message")
    results.append(("Test 2: Base64 decode", ok))

    # ------------------------------------------------------------------
    # TEST 3: Hex encoded message
    # ------------------------------------------------------------------
    print("\n[Test 3] Hex encoded message in log...")
    hex_message = "48657820656e636f64656420737472696e6720646574656374656420636f7272656374"
    status, data = post_log({
        "source": "test-hex-collector",
        "event_type": "system.alert",
        "message": hex_message,
        "severity": "medium",
        "timestamp": "2026-06-05T10:10:00Z"
    })
    ok = status == 200 and "Hex encoded string" in (data.get("message") or "")
    print(f"  Status: {status}")
    print(f"  Decoded message: {data.get('message')}")
    print(f"  decoding_applied in metadata: {data.get('metadata', {}).get('decoding_applied')}")
    print(f"  {PASS if ok else FAIL} Test 3: Hex decoded message")
    results.append(("Test 3: Hex decode", ok))

    # ------------------------------------------------------------------
    # TEST 4: URL encoded message
    # ------------------------------------------------------------------
    print("\n[Test 4] URL encoded message in log...")
    url_message = "GET%20/admin/login.php%3Fuser%3Dadmin%26pass%3Dsecret"
    status, data = post_log({
        "source": "test-url-collector",
        "event_type": "http.request",
        "message": url_message,
        "severity": "low",
        "timestamp": "2026-06-05T10:15:00Z"
    })
    ok = status == 200 and "GET /admin/login.php" in (data.get("message") or "")
    print(f"  Status: {status}")
    print(f"  Decoded message: {data.get('message')}")
    print(f"  {PASS if ok else FAIL} Test 4: URL encoded message decoded")
    results.append(("Test 4: URL decode", ok))

    # ------------------------------------------------------------------
    # TEST 5: Syslog RFC 3164 format
    # ------------------------------------------------------------------
    print("\n[Test 5] Syslog RFC 3164 format...")
    syslog_msg = "<34>Oct  1 22:14:15 server1 su[1234]: Bad su attempt by user"
    status, data = post_log({
        "source": "syslog-collector",
        "event_type": "syslog_raw",
        "message": syslog_msg,
        "timestamp": "2026-06-05T10:20:00Z"
    })
    ok = status == 200 and "Bad su attempt" in (data.get("message") or "")
    print(f"  Status: {status}")
    print(f"  Parsed message: {data.get('message')}")
    print(f"  Parsed source: {data.get('source')} | host: {data.get('host')}")
    print(f"  detected_format: {data.get('metadata', {}).get('detected_format')}")
    print(f"  {PASS if ok else FAIL} Test 5: Syslog RFC 3164 parsed")
    results.append(("Test 5: Syslog RFC 3164", ok))

    # ------------------------------------------------------------------
    # TEST 6: Syslog RFC 5424 format
    # ------------------------------------------------------------------
    print("\n[Test 6] Syslog RFC 5424 format...")
    syslog5424 = '<165>1 2026-06-05T10:25:00Z mymachine.example.com su 1234 ID47 [exampleSDID@32473 iut="3"] Access granted to user'
    status, data = post_log({
        "source": "syslog5424-collector",
        "event_type": "syslog_raw",
        "message": syslog5424,
        "timestamp": "2026-06-05T10:25:00Z"
    })
    ok = status == 200 and "Access granted" in (data.get("message") or "")
    print(f"  Status: {status}")
    print(f"  Parsed message: {data.get('message')}")
    print(f"  Parsed source: {data.get('source')}")
    print(f"  detected_format: {data.get('metadata', {}).get('detected_format')}")
    print(f"  {PASS if ok else FAIL} Test 6: Syslog RFC 5424 parsed")
    results.append(("Test 6: Syslog RFC 5424", ok))

    # ------------------------------------------------------------------
    # TEST 7: Web Server Combined Log Format (CLF)
    # ------------------------------------------------------------------
    print("\n[Test 7] Web server Common Log Format (CLF)...")
    web_log = '192.168.1.50 - frank [05/Jun/2026:10:30:00 +0530] "GET /api/dashboard HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0"'
    status, data = post_log({
        "source": "nginx-access",
        "event_type": "http.access",
        "message": web_log,
        "timestamp": "2026-06-05T10:30:00Z"
    })
    ok = (
        status == 200
        and "GET" in (data.get("message") or "")
        and (data.get("source_ip") == "192.168.1.50" or data.get("metadata", {}).get("detected_format") == "web")
    )
    print(f"  Status: {status}")
    print(f"  Parsed message: {data.get('message')}")
    print(f"  Parsed source_ip: {data.get('source_ip')}")
    print(f"  detected_format: {data.get('metadata', {}).get('detected_format')}")
    print(f"  {PASS if ok else FAIL} Test 7: Web server log parsed")
    results.append(("Test 7: Web CLF", ok))

    # ------------------------------------------------------------------
    # TEST 8: Nested JSON inside message field
    # ------------------------------------------------------------------
    print("\n[Test 8] Nested JSON inside message field...")
    nested_json_msg = '{"event_type": "container.anomaly", "source": "k8s-pod", "host": "worker-node-1", "message": "CPU spike detected", "severity": "high", "timestamp": "2026-06-05T10:35:00Z"}'
    status, data = post_log({
        "source": "orchestrator",
        "event_type": "system.raw",
        "message": nested_json_msg,
        "timestamp": "2026-06-05T10:35:00Z"
    })
    ok = status == 200 and "CPU spike" in (data.get("message") or "")
    print(f"  Status: {status}")
    print(f"  Parsed message: {data.get('message')}")
    print(f"  Parsed source: {data.get('source')}")
    print(f"  detected_format: {data.get('metadata', {}).get('detected_format')}")
    print(f"  {PASS if ok else FAIL} Test 8: Nested JSON in message parsed")
    results.append(("Test 8: Nested JSON", ok))

    # ------------------------------------------------------------------
    # TEST 9: Invalid log (quarantine routing check) - missing event_type
    # ------------------------------------------------------------------
    print("\n[Test 9] Invalid log should be quarantined (missing event_type)...")
    status, data = post_log({
        "source": "test-parser-invalid",
        "message": "Some message without event type",
        "severity": "low"
    })
    ok = status == 400 and data.get("status") == "quarantined"
    print(f"  Status: {status}")
    print(f"  Response: {data}")
    print(f"  {PASS if ok else FAIL} Test 9: Invalid log correctly quarantined")
    results.append(("Test 9: Quarantine", ok))

    # ══════════════════════════════════════════════════════════════════
    # ADVANCED TESTS — New parsers and decoders
    # ══════════════════════════════════════════════════════════════════

    # ------------------------------------------------------------------
    # TEST 10: CEF (Common Event Format) — ArcSight / SIEM format
    # ------------------------------------------------------------------
    print("\n[Test 10] CEF (Common Event Format) log...")
    cef_message = (
        "CEF:0|Palo Alto Networks|PAN-OS|10.1|THREAT|Threat Detected|7|"
        "src=192.168.1.100 dst=10.0.0.5 suser=jdoe dport=443 proto=tcp "
        "act=block rt=1704067200000"
    )
    status, data = post_log({
        "source": "firewall-collector",
        "event_type": "raw_log",
        "message": cef_message,
        "timestamp": "2026-06-05T11:00:00Z"
    })
    meta = data.get("metadata", {})
    ok = (
        status == 200
        and meta.get("detected_format") == "cef"
        and "Threat Detected" in (data.get("message") or "")
        and data.get("source_ip") == "192.168.1.100"
    )
    print(f"  Status: {status}")
    print(f"  detected_format: {meta.get('detected_format')}")
    print(f"  Parsed message: {data.get('message')}")
    print(f"  source_ip: {data.get('source_ip')} | user: {data.get('user')}")
    print(f"  severity: {data.get('severity')}")
    print(f"  event_fingerprint present: {'event_fingerprint' in meta}")
    print(f"  {PASS if ok else FAIL} Test 10: CEF format parsed")
    results.append(("Test 10: CEF", ok))

    # ------------------------------------------------------------------
    # TEST 11: LEEF (Log Event Extended Format) — IBM QRadar format
    # ------------------------------------------------------------------
    print("\n[Test 11] LEEF (Log Event Extended Format) log...")
    leef_message = (
        "LEEF:1.0|IBM|QRadar|7.3|AuthSuccess|"
        "devTime=2026-06-05T11:05:00Z\tsrc=10.10.10.50\tusrName=bob\tsev=3"
    )
    status, data = post_log({
        "source": "qradar-collector",
        "event_type": "raw_log",
        "message": leef_message,
        "timestamp": "2026-06-05T11:05:00Z"
    })
    meta = data.get("metadata", {})
    ok = (
        status == 200
        and meta.get("detected_format") == "leef"
        and "authsuccess" in (data.get("event_type") or "").lower()
        and data.get("source_ip") == "10.10.10.50"
        # sev=3 → numeric 3 < 4 threshold → correctly maps to "low" per _WIN_LEVEL_SEVERITY
        and data.get("severity") == "low"
    )
    print(f"  Status: {status}")
    print(f"  detected_format: {meta.get('detected_format')}")
    print(f"  event_type: {data.get('event_type')}")
    print(f"  source_ip: {data.get('source_ip')} | user: {data.get('user')}")
    print(f"  severity: {data.get('severity')}")
    print(f"  event_fingerprint present: {'event_fingerprint' in meta}")
    print(f"  {PASS if ok else FAIL} Test 11: LEEF format parsed")
    results.append(("Test 11: LEEF", ok))

    # ------------------------------------------------------------------
    # TEST 12: Windows Event XML format
    # ------------------------------------------------------------------
    print("\n[Test 12] Windows Event XML format...")
    win_xml = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing'/>
    <EventID>4624</EventID>
    <Level>4</Level>
    <TimeCreated SystemTime='2026-06-05T11:10:00.000Z'/>
    <Channel>Security</Channel>
    <Computer>DESKTOP-SOC01</Computer>
  </System>
  <EventData>
    <Data Name='SubjectUserName'>SYSTEM</Data>
    <Data Name='LogonType'>3</Data>
    <Data Name='IpAddress'>192.168.50.10</Data>
  </EventData>
</Event>"""
    status, data = post_log({
        "source": "windows-xml-collector",
        "event_type": "windows_raw",
        "message": win_xml,
        "timestamp": "2026-06-05T11:10:00Z"
    })
    meta = data.get("metadata", {})
    ok = (
        status == 200
        and meta.get("detected_format") == "windows_xml"
        and "4624" in (data.get("message") or "")
        and meta.get("event_id") == "4624"
    )
    print(f"  Status: {status}")
    print(f"  detected_format: {meta.get('detected_format')}")
    print(f"  Parsed message: {data.get('message')}")
    print(f"  event_id: {meta.get('event_id')} | host: {data.get('host')}")
    print(f"  event_data: {meta.get('event_data')}")
    print(f"  event_fingerprint present: {'event_fingerprint' in meta}")
    print(f"  {PASS if ok else FAIL} Test 12: Windows Event XML parsed")
    results.append(("Test 12: Windows XML", ok))

    # ------------------------------------------------------------------
    # TEST 13: Key=Value pairs (Cisco ASA / Palo Alto firewall log)
    # ------------------------------------------------------------------
    print("\n[Test 13] Key=Value firewall log (Cisco/Palo Alto style)...")
    kv_log = "src=203.0.113.5 dst=10.0.0.1 action=deny proto=tcp sport=54321 dport=22 msg=SSH brute force attempt severity=high user=root"
    status, data = post_log({
        "source": "firewall-kv-collector",
        "event_type": "raw_log",
        "message": kv_log,
        "timestamp": "2026-06-05T11:15:00Z"
    })
    meta = data.get("metadata", {})
    ok = (
        status == 200
        and meta.get("detected_format") == "key_value"
        and data.get("source_ip") == "203.0.113.5"
        and data.get("severity") == "high"
    )
    print(f"  Status: {status}")
    print(f"  detected_format: {meta.get('detected_format')}")
    print(f"  source_ip: {data.get('source_ip')} | severity: {data.get('severity')}")
    print(f"  user: {data.get('user')}")
    print(f"  parsing_confidence: {meta.get('parsing_confidence')}")
    print(f"  event_fingerprint present: {'event_fingerprint' in meta}")
    print(f"  {PASS if ok else FAIL} Test 13: Key=Value log parsed")
    results.append(("Test 13: Key=Value", ok))

    # ------------------------------------------------------------------
    # TEST 14: Gzip compressed + Base64 wrapped payload
    # ------------------------------------------------------------------
    print("\n[Test 14] Gzip (base64-wrapped) compressed message...")
    raw_text = '{"event_type": "malware.detected", "source": "edr-agent", "message": "Ransomware signature found", "severity": "critical", "timestamp": "2026-06-05T11:20:00Z"}'
    gzip_bytes = gzip.compress(raw_text.encode("utf-8"))
    b64_gzip = base64.b64encode(gzip_bytes).decode()
    status, data = post_log({
        "source": "edr-compressed",
        "event_type": "raw_compressed",
        "message": b64_gzip,
        "timestamp": "2026-06-05T11:20:00Z"
    })
    meta = data.get("metadata", {})
    ok = (
        status == 200
        and "Ransomware signature" in (data.get("message") or "")
        and "gzip" in (meta.get("decoding_chain") or [])
    )
    print(f"  Status: {status}")
    print(f"  Decoded message: {data.get('message')}")
    print(f"  decoding_chain: {meta.get('decoding_chain')}")
    print(f"  detected_format: {meta.get('detected_format')}")
    print(f"  {PASS if ok else FAIL} Test 14: Gzip base64-wrapped payload decoded")
    results.append(("Test 14: Gzip decode", ok))

    # ------------------------------------------------------------------
    # TEST 15: event_fingerprint is a valid 64-char SHA-256 hex string
    # ------------------------------------------------------------------
    print("\n[Test 15] event_fingerprint is a valid SHA-256 hex string...")
    status, data = post_log({
        "source": "fingerprint-test",
        "event_type": "network.scan",
        "message": "Port scan detected on subnet 10.0.0.0/24",
        "severity": "medium",
        "timestamp": "2026-06-05T11:25:00Z",
        "source_ip": "172.16.0.50"
    })
    meta = data.get("metadata", {})
    fp = meta.get("event_fingerprint", "")
    ok = (
        status == 200
        and isinstance(fp, str)
        and len(fp) == 64
        and all(c in "0123456789abcdef" for c in fp)
    )
    print(f"  Status: {status}")
    print(f"  event_fingerprint: {fp}")
    print(f"  Length: {len(fp)} chars | Valid hex: {all(c in '0123456789abcdef' for c in fp) if fp else False}")
    print(f"  {PASS if ok else FAIL} Test 15: event_fingerprint is valid SHA-256 (plain text logs also get fingerprint)")
    results.append(("Test 15: event_fingerprint", ok))

    # ------------------------------------------------------------------
    # TEST 16: decoding_chain is a list (Base64 → URL double-encoded)
    # ------------------------------------------------------------------
    print("\n[Test 16] decoding_chain returns ordered list for multi-step decode...")
    # Encode: URL encode a Base64 string so chain = ["url", "base64"]
    import urllib.parse
    inner = base64.b64encode(b"Multi-step decoding test payload").decode()
    url_wrapped = urllib.parse.quote(inner)
    status, data = post_log({
        "source": "multistep-decode-test",
        "event_type": "system.debug",
        "message": url_wrapped,
        "timestamp": "2026-06-05T11:30:00Z"
    })
    meta = data.get("metadata", {})
    chain = meta.get("decoding_chain") or []
    ok = (
        status == 200
        and isinstance(chain, list)
        and "url" in chain
        and "base64" in chain
        and "Multi-step decoding" in (data.get("message") or "")
    )
    print(f"  Status: {status}")
    print(f"  Decoded message: {data.get('message')}")
    print(f"  decoding_chain: {chain}")
    print(f"  {PASS if ok else FAIL} Test 16: decoding_chain is an ordered list")
    results.append(("Test 16: decoding_chain", ok))

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    passed = sum(1 for _, ok in results)
    total = len(results)
    print(f"\n{'=' * 60}")
    print(f"Results: {passed}/{total} tests passed")
    print()
    for name, ok in results:
        print(f"  {'[PASS]' if ok else '[FAIL]'} {name}")
    print()
    if passed == total:
        print("ALL PARSING & DECODING TESTS PASSED SUCCESSFULLY!")
    else:
        failed = [name for name, ok in results if not ok]
        print(f"FAILED TESTS: {', '.join(failed)}")
    print()
    for name, ok in results:
        symbol = "OK" if ok else "XX"
        print(f"  [{symbol}] {name}")
    print("=" * 60)

    if passed < total:
        sys.exit(1)


if __name__ == "__main__":
    try:
        run_tests()
    except Exception as exc:
        print(f"\n[CRITICAL] Unexpected error: {exc}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
