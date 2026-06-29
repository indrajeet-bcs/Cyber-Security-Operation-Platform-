import sys
from pathlib import Path

# Add backend directory to path
sys.path.append(str(Path(__file__).resolve().parent))

from app.schemas.log import RawLogIngest
from app.services.log_service import log_service


def run_tests():
    print("Starting SOC Platform Threat Detection Tests...")

    # Test 1: Suspicious login from blacklisted IP
    # Expected: is_suspicious=True, severity="high", reason="Login failure from blacklisted IP"
    test_1_input = RawLogIngest(
        host="linux-server-1",
        event_type="login_failed",  # Maps from "type"
        message="Failed SSH login attempt",  # Maps from "msg"
        severity="warning",  # Maps from "level"
        source_ip="192.168.1.10",  # Maps from "ip"
        user="root",  # Maps from "username"
    )
    res1 = log_service.ingest_log(test_1_input)
    print(f"\n[Test 1] Suspicious Login from Blacklisted IP:")
    print(f"  - Input IP: {res1.source_ip}, Event Type: {res1.event_type}")
    print(f"  - Is Suspicious: {res1.detection.is_suspicious}")
    print(f"  - Severity: {res1.detection.severity}")
    print(f"  - Reason: {res1.detection.reason}")
    assert res1.detection.is_suspicious is True
    assert res1.detection.severity == "high"
    assert res1.detection.reason == "Login failure from blacklisted IP"

    # Test 2: Login failed from non-blacklisted IP
    # Expected: is_suspicious=False, severity="low", reason=None
    test_2_input = RawLogIngest(
        host="linux-server-2",
        event_type="login_failed",
        message="Failed SSH login attempt",
        severity="warning",
        source_ip="172.16.0.50",
        user="admin",
    )
    res2 = log_service.ingest_log(test_2_input)
    print(f"\n[Test 2] Login Failed from Non-Blacklisted IP:")
    print(f"  - Input IP: {res2.source_ip}, Event Type: {res2.event_type}")
    print(f"  - Is Suspicious: {res2.detection.is_suspicious}")
    print(f"  - Severity: {res2.detection.severity}")
    print(f"  - Reason: {res2.detection.reason}")
    assert res2.detection.is_suspicious is False
    assert res2.detection.severity == "low"
    assert res2.detection.reason is None

    # Test 3: Normal web access from blacklisted IP
    # Expected: is_suspicious=False, severity="low", reason=None
    test_3_input = RawLogIngest(
        source="nginx-server",
        event_type="http_access",
        message="GET /index.html 200 OK",
        severity="info",
        source_ip="192.168.1.10",
    )
    res3 = log_service.ingest_log(test_3_input)
    print(f"\n[Test 3] Normal Web Access from Blacklisted IP:")
    print(f"  - Input IP: {res3.source_ip}, Event Type: {res3.event_type}")
    print(f"  - Is Suspicious: {res3.detection.is_suspicious}")
    print(f"  - Severity: {res3.detection.severity}")
    print(f"  - Reason: {res3.detection.reason}")
    assert res3.detection.is_suspicious is False
    assert res3.detection.severity == "low"
    assert res3.detection.reason is None

    # Test 4: Malware detected event
    # Expected: is_suspicious=True, severity="high", reason="Malware activity detected"
    test_4_input = RawLogIngest(
        source="edr-agent",
        event_type="malware.detected",
        message="Trojan horse Win32/Sirefef detected in temp dir",
        severity="high",
        source_ip="192.168.1.55",
    )
    res4 = log_service.ingest_log(test_4_input)
    print(f"\n[Test 4] Malware Detected Event:")
    print(f"  - Event Type: {res4.event_type}, Severity: {res4.severity}")
    print(f"  - Is Suspicious: {res4.detection.is_suspicious}")
    print(f"  - Severity: {res4.detection.severity}")
    print(f"  - Reason: {res4.detection.reason}")
    assert res4.detection.is_suspicious is True
    assert res4.detection.severity == "high"
    assert res4.detection.reason == "Malware activity detected"

    # Test 5: Critical severity log event
    # Expected: is_suspicious=True, severity="critical", reason="Critical severity log event"
    test_5_input = RawLogIngest(
        source="firewall",
        event_type="system.failure",
        message="Critical power supply failure detected",
        severity="critical",
    )
    res5 = log_service.ingest_log(test_5_input)
    print(f"\n[Test 5] Critical Severity Log Event:")
    print(f"  - Event Type: {res5.event_type}, Severity: {res5.severity}")
    print(f"  - Is Suspicious: {res5.detection.is_suspicious}")
    print(f"  - Severity: {res5.detection.severity}")
    print(f"  - Reason: {res5.detection.reason}")
    assert res5.detection.is_suspicious is True
    assert res5.detection.severity == "critical"
    assert res5.detection.reason == "Critical severity log event"

    # Test 6: Unauthorized access event
    # Expected: is_suspicious=True, severity="high", reason="Unauthorized access attempt"
    test_6_input = RawLogIngest(
        source="auth-gateway",
        event_type="unauthorized_access",
        message="Access denied to resource /admin/settings",
        severity="medium",
    )
    res6 = log_service.ingest_log(test_6_input)
    print(f"\n[Test 6] Unauthorized Access Event:")
    print(f"  - Event Type: {res6.event_type}, Severity: {res6.severity}")
    print(f"  - Is Suspicious: {res6.detection.is_suspicious}")
    print(f"  - Severity: {res6.detection.severity}")
    print(f"  - Reason: {res6.detection.reason}")
    assert res6.detection.is_suspicious is True
    assert res6.detection.severity == "high"
    assert res6.detection.reason == "Unauthorized access attempt"

    print("\nAll threat detection tests passed successfully!")


if __name__ == "__main__":
    run_tests()
