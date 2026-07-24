# Deep-Dive Investigation Report: Port Traffic Monitoring Collector

**Target File**: [port_traffic_collector.py](file:///c:/Bestowal%20Projects/Cyber-Security-Operation-Platform-/backend/collectors/port_traffic_collector.py)  
**Investigation Mode**: Read-only Diagnosis (Zero code or file modifications performed)

---

### 1. Current Collector Architecture

The collector is implemented in the class `PortTrafficCollector` in [port_traffic_collector.py](file:///c:/Bestowal%20Projects/Cyber-Security-Operation-Platform-/backend/collectors/port_traffic_collector.py#L112-L167). It is designed as a multi-threaded daemon with three concurrent monitoring threads spawned in `run()`:

1. **`RawSnifferThread`** ([line 587-590](file:///c:/Bestowal%20Projects/Cyber-Security-Operation-Platform-/backend/collectors/port_traffic_collector.py#L587-L590)): Executes `_raw_socket_sniffer_loop()` attempting Windows Raw Socket packet capture.
2. **`ScapySnifferThread`** ([line 592-597](file:///c:/Bestowal%20Projects/Cyber-Security-Operation-Platform-/backend/collectors/port_traffic_collector.py#L592-L597)): Executes `_scapy_sniffer_loop()` if Scapy is installed (`HAS_SCAPY = True`).
3. **`PollThread`** ([line 599-603](file:///c:/Bestowal%20Projects/Cyber-Security-Operation-Platform-/backend/collectors/port_traffic_collector.py#L599-L603)): Executes `_polling_loop()` which periodically polls `psutil.net_connections(kind="tcp")` at intervals defined by `POLL_INTERVAL` (default: 1.0 second).

The main thread loops continuously for `TIME_WINDOW_SECONDS` (default: 60s) before executing `_evaluate_window()` to compare aggregated counts against `TRAFFIC_THRESHOLD`.

---

### 2. Actual Detection Mechanism

The collector contains two active paths for registering connection events via `record_connection_event()` ([line 172-191](file:///c:/Bestowal%20Projects/Cyber-Security-Operation-Platform-/backend/collectors/port_traffic_collector.py#L172-L191)):

1. **Event-Based Sniffing Path** (`_raw_socket_sniffer_loop` and `_scapy_sniffer_loop`):
   - Intended to intercept raw TCP `SYN` packets (`flags & 0x02`) in real time and call `record_connection_event()`.
2. **Snapshot Diffing Polling Path** (`_poll_connections`):
   - Periodically queries `psutil.net_connections(kind="tcp")` every `POLL_INTERVAL` (1.0s).
   - Maintains `self._prev_connections: set[tuple[str, int, int]]` containing `(remote_ip, remote_port, local_port)`.
   - If a connection tuple is present in the current `psutil` snapshot but **not** in `_prev_connections`, it calls `record_connection_event()`.

---

### 3. Test 1: Long-Lived Connections (Why It Works)

#### Lifecycle of Test 1:
```text
OPEN → ACTIVE (Held open for 30s) → POLL (psutil sees active socket) → COUNT +1 → THRESHOLD → BACKEND
```

1. Test 1 creates 20 TCP sockets to `127.0.0.1:8080` and enters `time.sleep(30)`.
2. All 20 sockets remain in the OS Winsock TCP socket table in `ESTABLISHED` state for the entire 30 seconds.
3. Every 1.0 second, `_polling_loop()` calls `_poll_connections()` ([line 302-343](file:///c:/Bestowal%20Projects/Cyber-Security-Operation-Platform-/backend/collectors/port_traffic_collector.py#L302-L343)).
4. `psutil.net_connections(kind="tcp")` queries the OS kernel table and returns all 20 active connections.
5. On the first poll cycle after connection creation, all 20 tuples `(remote_ip, remote_port, 8080)` are absent from `_prev_connections`.
6. `record_connection_event()` is called **20 times**, incrementing `self._window_event_count[8080]` to **20**.
7. `_prev_connections` is updated to include all 20 active connection tuples.
8. At window expiration (60s), `_evaluate_window()` reads `event_count = 20`. Since 20 > `TRAFFIC_THRESHOLD`, it logs an `[ANOMALY]` and sends the payload to `POST /api/logs`.

---

### 4. Test 2: Short-Lived Connections (Why It Fails)

#### Lifecycle of Test 2:
```text
OPEN → CONNECT → CLOSE IMMEDIATELY (<1ms) → [NO POLL ACTIVE AT THIS INSTANT] → CLEARED FROM OS TABLE
```

1. Test 2 opens connection *i*, sends `connect()`, and immediately calls `close()`.
2. On localhost (`127.0.0.1`), the entire TCP handshake (`SYN` → `SYN-ACK` → `ACK` → `FIN` → `ACK`) completes and closes in **less than 1 millisecond**.
3. All 20 iterations complete in under **5 milliseconds**.
4. During these 5 milliseconds, `_polling_loop()` is sleeping inside `time.sleep(min(remaining, 0.25))` ([line 350-353](file:///c:/Bestowal%20Projects/Cyber-Security-Operation-Platform-/backend/collectors/port_traffic_collector.py#L350-L353)) waiting for the 1.0-second interval to elapse.
5. When `_polling_loop()` wakes up 1.0 second later and calls `psutil.net_connections(kind="tcp")`, **all 20 connections have already closed and disappeared from the OS socket table**.
6. `psutil.net_connections()` returns `0` active connections on port 8080.
7. `_poll_connections()` finds zero new connections. `record_connection_event()` is called **0 times**.
8. `_window_event_count[8080]` remains `0`.
9. At window expiration, 0 <= `TRAFFIC_THRESHOLD`. **No alert is generated.**

---

### 5. Exact Root Cause of the Difference

The fundamental reason for the failure in Test 2 lies in two core architectural realities of the current codebase:

1. **The Event-Based Sniffer Path is INACTIVE / UNAVAILABLE** (see Section 6 below).
2. **The Active Detection Path relies EXCLUSIVELY on Periodic Snapshot Diffing** (`psutil.net_connections`).
   - Sockets must be **actively alive in the OS TCP table at the exact millisecond `psutil` runs**.
   - Sockets that open and close in between two polling cycles are completely invisible to `psutil.net_connections`.

---

### 6. Raw Socket Monitor Status Analysis

The raw socket monitor (`_raw_socket_sniffer_loop`, lines 197-264) fails and deactivates on Windows for two independent technical reasons:

#### A. Administrative Elevation Privilege Failure
Line 207-210 attempts:
```python
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
s.bind((host_ip, 0))
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
```
On Windows, creating a raw IP socket or executing `SIO_RCVALL` requires **Administrator privileges**. When run under a standard user process, Windows raises:
`[WinError 10013] An attempt was made to access a socket in a way forbidden by its access permissions`
Line 212-217 catches this exception, logs:
`"Windows Raw Socket event monitor not elevated or unavailable... Supplemental connection diffing active."`
and **`return`s immediately**. The thread terminates silently at startup!

#### B. Loopback Interface Architecture (`127.0.0.1`)
Even if run as Administrator:
- Line 206 executes: `host_ip = socket.gethostbyname(socket.gethostname())`. This resolves to the machine's physical network adapter IP (e.g., `192.168.x.x`), **not** `127.0.0.1`.
- `s.bind((host_ip, 0))` binds the raw socket to the physical network interface card.
- In Windows TCP/IP stack architecture, loopback (`127.0.0.1`) traffic bypasses NDIS physical network adapters entirely and is handled internally by the Winsock Loopback driver.
- Windows `SIO_RCVALL` raw sockets **never capture loopback (`127.0.0.1`) traffic**.
- Therefore, Test 1 & Test 2 (which connect to `127.0.0.1`) can **never** be observed by the raw socket sniffer on Windows.

---

### 7. Fallback Connection Diffing Behavior

When raw socket sniffing terminates, the collector relies entirely on `_poll_connections()` ([line 302-343](file:///c:/Bestowal%20Projects/Cyber-Security-Operation-Platform-/backend/collectors/port_traffic_collector.py#L302-L343)).

- **What "Supplemental connection diffing active" means**: It means event sniffing is dead, and the collector has degraded to checking `psutil` snapshot diffs every 1.0s.
- **Data Compared**: It compares the `set` of `(remote_ip, remote_port, local_port)` tuples returned by `psutil.net_connections(kind="tcp")` against `self._prev_connections`.
- **Flaw / Missed Events**: It can **only** detect connections that exist long enough to overlap with a `psutil` sampling tick.
- **Can it detect a connection opening and closing between snapshots?**: **No.** Any connection created and destroyed within the 1.0-second interval between snapshot ticks leaves zero trace in `psutil`.

---

### 8. Polling and Timing Analysis

| Metric | Code Value / Reference |
| :--- | :--- |
| **Polling Inspection Interval** | `POLL_INTERVAL = 1.0` seconds ([line 97](file:///c:/Bestowal%20Projects/Cyber-Security-Operation-Platform-/backend/collectors/port_traffic_collector.py#L97)) |
| **Window Evaluation Frequency** | `TIME_WINDOW_SECONDS = 60` seconds ([line 91](file:///c:/Bestowal%20Projects/Cyber-Security-Operation-Platform-/backend/collectors/port_traffic_collector.py#L91)) |
| **Can connection open/close between polls?** | **Yes.** Test 2 opens and closes in <1 millisecond. |
| **Consequence of missing poll window** | The connection is never passed to `record_connection_event()`, `connection_event_count` remains 0. |

---

### 9. Trace of Complete Data Flow

```text
[ Test 1: Long-Lived ]
Operating System TCP Table (ESTABLISHED for 30s)
    ↓
_poll_connections() runs at t=1.0s tick
    ↓
psutil.net_connections(kind="tcp") returns 20 active sockets
    ↓
conn_key not in _prev_connections → record_connection_event() called 20 times
    ↓
self._window_event_count[8080] = 20
    ↓
_evaluate_window() at t=60s: 20 > TRAFFIC_THRESHOLD (5)
    ↓
_build_payload() creates event_type="unauthorized_port_traffic"
    ↓
send_to_backend() POSTs JSON to http://127.0.0.1:8000/api/logs

[ Test 2: Short-Lived ]
Operating System TCP Table (Opened & Closed in <1ms)
    ↓
_poll_connections() sleeping in time.sleep(0.25)
    ↓
Sockets closed & removed from OS TCP Table before poll runs
    ↓
_poll_connections() runs at t=1.0s tick → psutil returns 0 sockets
    ↓
record_connection_event() called 0 times
    ↓
self._window_event_count[8080] = 0
    ↓
_evaluate_window() at t=60s: 0 <= TRAFFIC_THRESHOLD → NO ACTION
```

---

### 10. Capability Matrix of Current Implementation

#### What the Collector CURRENTLY Supports:
- Persistent or long-lived TCP connections that remain active across at least one `psutil` polling interval (1.0s).
- Multi-port isolation (`8080`, `443` tracked separately).
- Aggregation window evaluation and threshold comparison.
- Cooldown suppression and backend retry buffering.

#### What the Collector CURRENTLY Does NOT Support:
- Short-lived TCP connections opening and closing between 1.0-second polling cycles.
- Non-elevated Windows event monitoring (fails with `WinError 10013`).
- Loopback (`127.0.0.1`) packet sniffing on Windows via Raw Sockets.

---

### 11. Other Potential Causes Checked & Excluded

- **Wrong Monitored Port**: Excluded. `MONITORED_PORTS` contains `8080`.
- **Process Filter**: Excluded. `psutil.net_connections(kind="tcp")` looks at all system TCP connections, not scoped to any PID.
- **Localhost / 127.0.0.1 Filtering in `psutil` logic**: Excluded. `_poll_connections()` does not filter out `127.0.0.1` IPs in Python logic; it fails solely because `127.0.0.1` short-lived sockets vanish before `psutil` runs.
- **Cooldown Behavior**: Excluded. Cooldown is only applied *after* a threshold breach is triggered ([line 418-420](file:///c:/Bestowal%20Projects/Cyber-Security-Operation-Platform-/backend/collectors/port_traffic_collector.py#L418-L420)).

---

### 12. Final Diagnosis

The current `port_traffic_collector.py` **cannot detect short-lived connections (Test 2)** because:

1. Its real-time raw socket sniffer thread (`_raw_socket_sniffer_loop`) crashes at startup due to missing Windows Administrator privileges (`WinError 10013`) and cannot capture `127.0.0.1` loopback traffic on Windows.
2. The fallback mechanism (`_poll_connections`) relies entirely on discrete 1.0-second snapshot polling of `psutil.net_connections()`.
3. Sockets that open and close in <1 millisecond between polls are completely absent during snapshot execution and are never recorded.
