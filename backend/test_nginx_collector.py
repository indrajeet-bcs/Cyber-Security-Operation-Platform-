"""
Offline verification tests for nginx_log_collector.py
Runs without a backend or live NGINX instance.
All string labels are pure ASCII for Windows cp1252 console compatibility.
"""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import importlib.util

spec = importlib.util.spec_from_file_location(
    "nginx_log_collector",
    os.path.join(os.path.dirname(__file__), "collectors", "nginx_log_collector.py"),
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

errors = []


def check(label, condition, detail=""):
    if condition:
        print(f"  [OK]   {label}")
    else:
        msg = f"  [FAIL] {label}" + (f" -- {detail}" if detail else "")
        print(msg)
        errors.append(msg)


# ─────────────────────────────────────────────────────────────────────────────
print("\n[1/8] Module symbol verification")
check("NginxLogCollector exists",      hasattr(mod, "NginxLogCollector"))
check("NginxFileEventHandler exists",  hasattr(mod, "NginxFileEventHandler"))
check("ACCESS_LOG_EXTENDED_RE exists", hasattr(mod, "ACCESS_LOG_EXTENDED_RE"))
check("ACCESS_LOG_COMBINED_RE exists", hasattr(mod, "ACCESS_LOG_COMBINED_RE"))
check("ERROR_LOG_RE exists",           hasattr(mod, "ERROR_LOG_RE"))
check("MONITORED_APPLICATIONS exists", hasattr(mod, "MONITORED_APPLICATIONS"))
check("OFFSET_FILE exists",            hasattr(mod, "OFFSET_FILE"))

c = mod.NginxLogCollector(monitored_logs=[], monitored_applications=[])
check("NginxLogCollector instantiates", c is not None)

# ─────────────────────────────────────────────────────────────────────────────
print("\n[2/8] Combined Log Format parsing")
line = (
    '127.0.0.1 - frank [03/Jul/2026:11:00:00 +0530] '
    '"GET /api/test?q=1 HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
)
p = c._parse_access_line(line)
check("Parsed successfully",                             p is not None)
check("http_method == GET",                              p and p["http_method"]  == "GET")
check("request_uri == /api/test",                        p and p["request_uri"]  == "/api/test")
check("query_string == q=1",                             p and p["query_string"] == "q=1")
check("status_code == 200",                              p and p["status_code"]  == "200")
check("bytes_sent == 512",                               p and p["bytes_sent"]   == "512")
check("client_ip == 127.0.0.1",                          p and p["client_ip"]    == "127.0.0.1")
check("upstream_port is None (Combined has no upstream)",p and p["upstream_port"] is None)

# ─────────────────────────────────────────────────────────────────────────────
print("\n[3/8] Extended Log Format parsing (upstream + host fields)")
line2 = (
    '127.0.0.1 - - [03/Jul/2026:11:00:00 +0530] '
    '"POST /hr/login HTTP/1.1" 401 128 "-" "curl/7.68" '
    '"hr.company.com" "127.0.0.1:8080" "0.045"'
)
p2 = c._parse_access_line(line2)
check("Parsed successfully",                p2 is not None)
check("http_method == POST",                p2 and p2["http_method"]    == "POST")
check("request_uri == /hr/login",           p2 and p2["request_uri"]    == "/hr/login")
check("status_code == 401",                 p2 and p2["status_code"]    == "401")
check("upstream_port == 8080",              p2 and p2["upstream_port"]  == "8080")
check("upstream_addr == 127.0.0.1:8080",   p2 and p2["upstream_addr"]  == "127.0.0.1:8080")
check("host == hr.company.com",             p2 and p2["host"]           == "hr.company.com")
check("response_time == 0.045",             p2 and p2["response_time"]  == "0.045")

# ─────────────────────────────────────────────────────────────────────────────
print("\n[4/8] JSON Log Format parsing")
jline = json.dumps({
    "time":            "2026-07-03T11:00:00+05:30",
    "remote_addr":     "10.0.0.1",
    "request":         "DELETE /crm/record HTTP/1.1",
    "status":          204,
    "body_bytes_sent": 0,
    "http_referer":    "-",
    "http_user_agent": "Mozilla/5.0",
    "http_host":       "crm.company.com",
    "upstream_addr":   "127.0.0.1:9000",
    "request_time":    "0.021",
})
jp = c._parse_access_line(jline)
check("Parsed successfully",          jp is not None)
check("http_method == DELETE",        jp and jp["http_method"]   == "DELETE")
check("request_uri == /crm/record",   jp and jp["request_uri"]   == "/crm/record")
check("status_code == 204",           jp and jp["status_code"]   == "204")
check("upstream_port == 9000",        jp and jp["upstream_port"] == "9000")
check("host == crm.company.com",      jp and jp["host"]          == "crm.company.com")

# ─────────────────────────────────────────────────────────────────────────────
print("\n[5/8] Error Log Format parsing")
eline = (
    '2026/07/03 11:00:00 [error] 1234#0: *5 connect() failed (111: Connection refused), '
    'client: 1.2.3.4, server: hr.company.com, '
    'request: "GET /api HTTP/1.1", upstream: "http://127.0.0.1:8080/api", '
    'host: "hr.company.com"'
)
ep = c._parse_error_line(eline)
check("Parsed successfully",       ep is not None)
check("error_level == error",      ep and ep["error_level"]   == "error")
check("upstream_port == 8080",     ep and ep["upstream_port"] == "8080")
check("host == hr.company.com",    ep and ep["host"]          == "hr.company.com")
check("client_ip == 1.2.3.4",     ep and ep["client_ip"]     == "1.2.3.4")
check("http_method == GET",        ep and ep["http_method"]   == "GET")
check("pid == 1234",               ep and ep["pid"]           == "1234")

# ─────────────────────────────────────────────────────────────────────────────
print("\n[6/8] Dual-mode application filter (_match_application)")
c2 = mod.NginxLogCollector(monitored_logs=[], monitored_applications=mod.MONITORED_APPLICATIONS)

# Port match
m = c2._match_application({"upstream_port": "8080", "host": "other.com", "server_name": None})
check("Port 8080 -> HR (port match)",             m is not None and m["name"] == "HR",      str(m))

# Host match
m2 = c2._match_application({"upstream_port": None, "host": "crm.company.com", "server_name": None})
check("Host crm.company.com -> CRM (host match)", m2 is not None and m2["name"] == "CRM",   str(m2))

# server_name match
m3 = c2._match_application({"upstream_port": None, "host": None, "server_name": "finance.company.com"})
check("server_name finance -> Finance",           m3 is not None and m3["name"] == "Finance",str(m3))

# OR: port wins even when host does not match
m4 = c2._match_application({"upstream_port": "9000", "host": "random.com", "server_name": None})
check("Port 9000 wins over wrong host -> CRM",    m4 is not None and m4["name"] == "CRM",   str(m4))

# No match
m5 = c2._match_application({"upstream_port": "9999", "host": "unknown.com", "server_name": None})
check("Unknown port+host -> None (discard)",      m5 is None,                                str(m5))

# Wildcard (empty list)
c3 = mod.NginxLogCollector(monitored_logs=[], monitored_applications=[])
m6 = c3._match_application({"upstream_port": "9999", "host": "anything.com", "server_name": None})
check("Empty MONITORED_APPLICATIONS -> wildcard 'all'", m6 is not None and m6["name"] == "all", str(m6))

# ─────────────────────────────────────────────────────────────────────────────
print("\n[7/8] Severity mapping")
check("500 -> high",          c._determine_severity({"status_code": "500"}, "access") == "high")
check("503 -> high",          c._determine_severity({"status_code": "503"}, "access") == "high")
check("403 -> medium",        c._determine_severity({"status_code": "403"}, "access") == "medium")
check("401 -> medium",        c._determine_severity({"status_code": "401"}, "access") == "medium")
check("404 -> low",           c._determine_severity({"status_code": "404"}, "access") == "low")
check("400 -> low",           c._determine_severity({"status_code": "400"}, "access") == "low")
check("200 -> info",          c._determine_severity({"status_code": "200"}, "access") == "info")
check("301 -> info",          c._determine_severity({"status_code": "301"}, "access") == "info")
check("error level -> high",  c._determine_severity({"error_level": "error"}, "error") == "high")
check("crit level -> high",   c._determine_severity({"error_level": "crit"},  "error") == "high")
check("warn level -> medium",  c._determine_severity({"error_level": "warn"},  "error") == "medium")
check("info level -> info",   c._determine_severity({"error_level": "info"},  "error") == "info")

# ─────────────────────────────────────────────────────────────────────────────
print("\n[8/8] Payload construction (_to_payload)")
app_hr = {"name": "HR", "upstream_port": "8080", "server_name": "hr.company.com"}
payload = c._to_payload(p2, "access", app_hr)

check("source == nginx",                        payload["source"]               == "nginx")
check("event_type == nginx.access",             payload["event_type"]           == "nginx.access")
check("severity == medium (401 status)",        payload["severity"]             == "medium")
check("source_ip == 127.0.0.1",                 payload["source_ip"]            == "127.0.0.1")
check("metadata.application == HR",             payload["metadata"].get("application") == "HR")
check("metadata.upstream_port == 8080",         payload["metadata"]["upstream_port"]   == "8080")
check("metadata.host == hr.company.com",        payload["metadata"]["host"]            == "hr.company.com")
check("message contains POST",                  "POST" in payload["message"])

# Wildcard payload must NOT have 'application' in metadata
payload2 = c3._to_payload(p2, "access", {"name": "all"})
check("Wildcard: no 'application' key in metadata", "application" not in payload2["metadata"])

# Error payload has error-specific metadata fields
payload3 = c._to_payload(ep, "error", app_hr)
check("Error event_type == nginx.error",        payload3["event_type"]                  == "nginx.error")
check("Error metadata.error_level == error",    payload3["metadata"].get("error_level") == "error")
check("Error metadata.pid == 1234",             payload3["metadata"].get("pid")         == "1234")

# ─────────────────────────────────────────────────────────────────────────────
print()
print("=" * 58)
if errors:
    print(f"  {len(errors)} CHECK(S) FAILED:")
    for e in errors:
        print(f"    {e}")
    sys.exit(1)
else:
    print("  ALL CHECKS PASSED -- nginx_log_collector.py verified")
print("=" * 58)
