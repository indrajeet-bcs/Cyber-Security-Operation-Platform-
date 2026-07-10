import requests
import time
import uuid

BASE_URL = "http://localhost/loginapp/"
LOGIN_URL = f"{BASE_URL}login"
DASHBOARD_URL = f"{BASE_URL}dashboard"
LOGOUT_URL = f"{BASE_URL}logout"

# Add a slight delay between tests to keep logs readable
DELAY = 1

def print_result(scenario, method, url, status, expected):
    print(f"[{scenario}]")
    print(f"Method: {method}")
    print(f"Request URL: {url}")
    print(f"Status Code: {status}")
    print(f"Expected SOC Detection: {expected}")
    print("-" * 50)
    time.sleep(DELAY)

def run_normal_activity():
    session = requests.Session()
    
    # 1. Open login page
    res = session.get(LOGIN_URL)
    
    # 2. Successful login
    res = session.post(LOGIN_URL, data={"username": "admin", "password": "Admin@123"}, allow_redirects=False)
    print_result("Normal User Activity - Login", "POST", LOGIN_URL, res.status_code, "Normal Activity (No Alert)")
    
    # 3. Dashboard access
    res = session.get(DASHBOARD_URL)
    print_result("Normal User Activity - Dashboard", "GET", DASHBOARD_URL, res.status_code, "Normal Activity (No Alert)")
    
    # 4. Logout
    res = session.get(LOGOUT_URL, allow_redirects=False)
    print_result("Normal User Activity - Logout", "GET", LOGOUT_URL, res.status_code, "Normal Activity (No Alert)")

def run_failed_login():
    for i in range(5):
        res = requests.post(LOGIN_URL, data={"username": "admin", "password": "WrongPassword123"}, allow_redirects=False)
    print_result("Failed Login (5 attempts)", "POST", LOGIN_URL, res.status_code, "Authentication Failure")

def run_bruteforce_attack():
    for i in range(15):
        # Fire off requests quickly
        res = requests.post(LOGIN_URL, data={"username": "admin", "password": f"WrongPassword{i}"}, allow_redirects=False)
    print_result("Brute Force (15 rapid attempts)", "POST", LOGIN_URL, res.status_code, "Brute Force Detection")

def run_sql_injection():
    payloads = [
        ("admin' OR '1'='1", "password"),
        ("' UNION SELECT NULL--", "password"),
        ("admin'--", "password")
    ]
    for user, pwd in payloads:
        res = requests.post(LOGIN_URL, data={"username": user, "password": pwd}, allow_redirects=False)
        print_result(f"SQL Injection: {user}", "POST", LOGIN_URL, res.status_code, "SQL Injection Attempt")

def run_directory_traversal():
    payloads = [
        "/../../etc/passwd",
        "/../windows/win.ini",
        "/.git/config"
    ]
    for payload in payloads:
        url = f"http://localhost{payload}"  # Bypassing the /loginapp/ path intentionally or using it directly
        res = requests.get(url)
        print_result(f"Directory Traversal: {payload}", "GET", url, res.status_code, "Path Traversal Detection")
        
        url_app = f"{BASE_URL[:-1]}{payload}"
        res = requests.get(url_app)
        print_result(f"Directory Traversal (App Path): {payload}", "GET", url_app, res.status_code, "Path Traversal Detection")

def run_invalid_urls():
    payloads = [
        "admin",
        "backup",
        "config",
        "secret"
    ]
    for payload in payloads:
        url = f"{BASE_URL}{payload}"
        res = requests.get(url)
        print_result(f"Invalid URLs: {payload}", "GET", url, res.status_code, "Reconnaissance / 404 Not Found")

def run_http_method_tests():
    methods = [
        requests.put,
        requests.delete,
        requests.options,
        requests.trace if hasattr(requests, 'trace') else requests.request
    ]
    
    for method in methods:
        try:
            if method == requests.request:
                res = method('TRACE', BASE_URL)
                m_name = "TRACE"
            else:
                res = method(BASE_URL)
                m_name = method.__name__.upper()
            print_result(f"HTTP Method Abuse: {m_name}", m_name, BASE_URL, res.status_code, "Unusual HTTP Method")
        except Exception as e:
            print(f"Failed to execute method: {e}")

def run_high_volume_traffic():
    print("Starting high-volume traffic (50 GET requests)...")
    for i in range(50):
        # Adding a random UUID just to make URLs unique and avoid purely cached responses
        url = f"{BASE_URL}?req={uuid.uuid4()}"
        res = requests.get(url)
    print_result("High Request Volume", "GET", f"{BASE_URL}?req=...", res.status_code, "High Volume / DoS Probing")

def main():
    print("="*50)
    print("STARTING PHASE 2: ATTACK SIMULATION")
    print("="*50)
    
    run_normal_activity()
    run_failed_login()
    run_bruteforce_attack()
    run_sql_injection()
    run_directory_traversal()
    run_invalid_urls()
    run_http_method_tests()
    run_high_volume_traffic()
    
    print("="*50)
    print("ATTACK SIMULATION COMPLETE")
    print("="*50)

if __name__ == "__main__":
    main()
