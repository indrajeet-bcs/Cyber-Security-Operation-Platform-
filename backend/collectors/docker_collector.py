import os
import sys
import time
import socket
import threading
import requests
import uuid
import logging
from datetime import datetime, timezone

# ─── Logging Configuration ──────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("DockerCollector")


# ─── Docker SDK ─────────────────────────────────────────────────────────────
try:
    import docker
    from docker.errors import DockerException
except ImportError:
    print("[FATAL] 'docker' package is not installed.")
    print("        Run: pip install docker")
    sys.exit(1)

# ─── Configuration ──────────────────────────────────────────────────────────
BACKEND_URL = "http://127.0.0.1:8000/api/logs/"
POLL_INTERVAL = 5.0
RECONNECT_INTERVAL = 5.0

class DockerCollector:
    def __init__(self, backend_url: str = BACKEND_URL):
        self.backend_url = backend_url
        self.host_name = socket.gethostname() or "local-docker-host"
        self.client = None
        self.running = True
        
        # Track active stream readers: container_id -> set of stream types ("stdout", "stderr")
        self.active_streams = {}
        self.lock = threading.Lock()
        
        # Track last log timestamp for each container: (container_id, stream_type) -> timestamp string
        self.last_timestamps = {}
        self.timestamps_lock = threading.Lock()

        # Duplicate event tracking
        self.processed_events = set()
        self.events_lock = threading.Lock()
        self.event_thread = None

    def get_client(self):
        """Attempts to connect to the Docker daemon."""
        try:
            client = docker.from_env()
            client.ping()
            return client
        except Exception as e:
            print(f"[-] Error connecting to Docker daemon: {e}")
            return None

    def send_to_backend(self, payload: dict) -> bool:
        """Sends a log payload to the FastAPI backend."""
        try:
            response = requests.post(self.backend_url, json=payload, timeout=5)
            if response.status_code in (200, 201):
                # Successfully sent
                return True
            elif response.status_code == 409:
                # Duplicate event
                return True
            else:
                logger.error(f"Failed to send log to backend. Status: {response.status_code}, Response: {response.text}")
                return False
        except Exception as e:
            logger.error(f"Network error sending log to backend: {e}")
            return False

    def get_container_metadata(self, container):
        """Helper to extract container metadata."""
        try:
            return {
                "container_id": container.id,
                "container_name": container.name,
                "image": container.image.tags[0] if container.image.tags else "unknown",
                "container_status": container.status,
                "docker_host": self.host_name
            }
        except Exception:
            return {
                "container_id": container.id,
                "container_name": container.name,
                "image": "unknown",
                "container_status": "unknown",
                "docker_host": self.host_name
            }

    def read_stream(self, container_id, container_name, stream_type):
        """Worker thread function to stream logs for a specific container and stream type."""
        print(f"[+] Starting log stream ({stream_type}) for container: {container_name} ({container_id[:12]})")
        
        since_time = None
        with self.timestamps_lock:
            since_time = self.last_timestamps.get((container_id, stream_type))

        # Convert since_time (ISO string) to UNIX timestamp if exists
        since_param = None
        if since_time:
            try:
                # Parse ISO timestamp
                dt = datetime.fromisoformat(since_time.replace("Z", "+00:00"))
                since_param = int(dt.timestamp())
            except Exception:
                pass

        if since_param is None:
            since_param = int(time.time())

        # Buffer to handle line accumulation
        buffer = b""

        while self.running:
            try:
                if not self.client:
                    break
                
                try:
                    container = self.client.containers.get(container_id)
                except Exception:
                    # Container might have been deleted/stopped
                    break

                # Stream logs
                stdout_opt = (stream_type == "stdout")
                stderr_opt = (stream_type == "stderr")
                
                log_generator = container.logs(
                    stdout=stdout_opt,
                    stderr=stderr_opt,
                    stream=True,
                    follow=True,
                    timestamps=True,
                    since=since_param
                )

                for chunk in log_generator:
                    if not self.running:
                        break
                    
                    buffer += chunk
                    lines = buffer.split(b"\n")
                    buffer = lines.pop() # Keep the last incomplete chunk in buffer
                    
                    for line in lines:
                        if not line.strip():
                            continue
                        
                        # Parse timestamp and message
                        parts = line.split(b" ", 1)
                        if len(parts) == 2:
                            ts_str = parts[0].decode("utf-8", errors="ignore")
                            msg_str = parts[1].decode("utf-8", errors="ignore").rstrip("\r\n")
                        else:
                            ts_str = datetime.now(timezone.utc).isoformat()
                            msg_str = line.decode("utf-8", errors="ignore").rstrip("\r\n")

                        # Determine severity
                        severity = "info"
                        msg_lower = msg_str.lower()
                        if "error" in msg_lower or "failed" in msg_lower or "exception" in msg_lower:
                            severity = "high"
                        elif "warning" in msg_lower or "warn" in msg_lower:
                            severity = "warning"

                        # Send payload
                        payload = {
                            "source": "docker",
                            "event_type": f"docker.{stream_type}",
                            "message": msg_str,
                            "severity": severity,
                            "host": self.host_name,
                            "timestamp": ts_str,
                            "metadata": self.get_container_metadata(container)
                        }
                        
                        if self.send_to_backend(payload):
                            # Record last successfully sent timestamp
                            with self.timestamps_lock:
                                self.last_timestamps[(container_id, stream_type)] = ts_str
                                
                # If generator finishes, wait a bit and retry if container is still running
                time.sleep(2)
                
            except Exception as e:
                # Log reading error, break out and retry/cleanup
                print(f"[-] Error reading logs for container {container_name} ({stream_type}): {e}")
                break

        # Cleanup active stream registry
        with self.lock:
            if container_id in self.active_streams:
                self.active_streams[container_id].discard(stream_type)
                if not self.active_streams[container_id]:
                    del self.active_streams[container_id]
                    
        print(f"[-] Stopped log stream ({stream_type}) for container: {container_name} ({container_id[:12]})")

    def start_container_streams(self, container):
        """Starts log streaming threads for a container if not already streaming."""
        container_id = container.id
        container_name = container.name
        
        # Check status, only stream logs for running containers
        if container.status != "running":
            return

        with self.lock:
            if container_id not in self.active_streams:
                self.active_streams[container_id] = set()

            for stream_type in ("stdout", "stderr"):
                if stream_type not in self.active_streams[container_id]:
                    self.active_streams[container_id].add(stream_type)
                    t = threading.Thread(
                        target=self.read_stream,
                        args=(container_id, container_name, stream_type),
                        daemon=True
                    )
                    t.start()

    def process_lifecycle_event(self, event):
        """Converts and forwards a lifecycle event to the backend."""
        # 1. Log event reception immediately
        logger.info("Docker event received")
        print(event) # Inspect raw event payload

        # Extract Docker native event ID immediately BEFORE any container inspection.
        # This prevents failure if a fast container disappears before we query it.
        docker_event_id = event.get("id")
        if not docker_event_id:
            return

        action = event.get("Action") or event.get("status") or "unknown"
        actor = event.get("Actor", {})
        attributes = actor.get("Attributes", {})
        container_name = attributes.get("name", "unknown")
        image = attributes.get("image", "unknown")

        event_type_mapping = {
            "start": "docker.container_started",
            "stop": "docker.container_stopped",
            "die": "docker.container_stopped",
            "restart": "docker.container_restarted",
            "oom": "docker.container_stopped",
            "exec_create": "docker.security_event",
            "exec_start": "docker.security_event"
        }

        event_type = event_type_mapping.get(action)
        if not event_type:
            # We only forward events that are container lifecycle related
            return

        # 2. Build unique key using Docker-native values for duplicate prevention.
        # We do NOT use the UUID for deduplication because a UUID is generated on the fly and is
        # always unique, which would fail to prevent duplicates.
        time_nano = event.get("timeNano")
        if time_nano:
            event_key = f"{action}_{docker_event_id}_{time_nano}"
        else:
            time_sec = event.get("time") or int(time.time())
            event_key = f"{action}_{docker_event_id}_{time_sec}"

        with self.events_lock:
            if event_key in self.processed_events:
                logger.info("Duplicate Docker event skipped")
                return
            self.processed_events.add(event_key)

        # 3. Generate a unique SOC-side event ID ONLY after the event is accepted for processing.
        # This UUID is needed for permanent SOC tracking, future alert correlation, cross-source
        # linking, and incident tracing.
        soc_event_id = str(uuid.uuid4())
        logger.info("SOC event UUID generated")

        # Determine severity and message based on action
        severity = "info"
        message = f"Container {container_name} ({docker_event_id[:12]}) action: {action}"
        
        if action == "oom":
            severity = "high"
            message = f"Container {container_name} ({docker_event_id[:12]}) was terminated due to Out Of Memory (OOM) error"
        elif action in ("exec_create", "exec_start"):
            severity = "warning"
            exec_cmd = attributes.get("execCmd", "unknown")
            message = f"Security Event: Command execution attempted inside container {container_name} ({docker_event_id[:12]}): {exec_cmd}"
        elif action in ("stop", "die"):
            exit_code = attributes.get("exitCode", "0")
            if exit_code != "0":
                severity = "warning"
                message = f"Container {container_name} ({docker_event_id[:12]}) stopped with non-zero exit code: {exit_code}"

        payload = {
            "source": "docker",
            "event_type": event_type,
            "message": message,
            "severity": severity,
            "host": self.host_name,
            "timestamp": datetime.fromtimestamp(event.get("time", time.time()), tz=timezone.utc).isoformat(),
            "metadata": {
                "soc_event_id": soc_event_id,
                "docker_event_id": docker_event_id,
                "container_id": docker_event_id,
                "container_name": container_name,
                "image": image,
                "container_status": action,
                "docker_host": self.host_name
            }
        }
        
        if attributes.get("exitCode") is not None:
            payload["metadata"]["exit_code"] = attributes.get("exitCode")
        if attributes.get("execCmd") is not None:
            payload["metadata"]["exec_cmd"] = attributes.get("execCmd")
            
        logger.info("Sending Docker event to backend")
        self.send_to_backend(payload)

    def listen_events(self):
        """Listens to Docker events stream and processes container lifecycle events."""
        logger.info("[+] Starting Docker event listener...")
        while self.running and self.client:
            try:
                event_stream = self.client.events(filters={"type": "container"}, decode=True)
                for event in event_stream:
                    if not self.running:
                        break
                    
                    # Extract Docker event ID directly from live Docker event stream BEFORE container inspection
                    docker_event_id = event.get("id")
                    if not docker_event_id:
                        continue

                    # Process event
                    self.process_lifecycle_event(event)

                    # If container started, spin up log streams
                    action = event.get("Action") or event.get("status")
                    if action in ("start", "restart"):
                        try:
                            container = self.client.containers.get(docker_event_id)
                            self.start_container_streams(container)
                        except Exception:
                            pass
            except Exception as e:
                logger.error(f"Error in Docker event stream: {e}")
                break
        logger.info("[-] Docker event listener stopped.")

    def run(self):
        """Main execution loop for Docker collector."""
        logger.info(f"[*] Docker Log Collector started on host: {self.host_name}")
        
        while self.running:
            self.client = self.get_client()
            
            if not self.client:
                logger.warning(f"Docker daemon is not accessible. Retrying in {RECONNECT_INTERVAL} seconds...")
                time.sleep(RECONNECT_INTERVAL)
                continue
            
            logger.info("Connected to Docker daemon.")
            
            # Start event listener thread if not already running
            if not self.event_thread or not self.event_thread.is_alive():
                self.event_thread = threading.Thread(target=self.listen_events, daemon=True)
                self.event_thread.start()

            # Dynamic loop to periodically scan for running containers
            while self.running:
                try:
                    # Ping docker daemon to ensure connection is alive
                    self.client.ping()
                    
                    # Scan for currently running containers and start log streams if needed
                    containers = self.client.containers.list()
                    for container in containers:
                        self.start_container_streams(container)
                        
                    time.sleep(POLL_INTERVAL)
                except Exception as e:
                    logger.error(f"Docker daemon connection lost: {e}")
                    self.client = None
                    break

        logger.info("[*] Docker Log Collector shutting down...")

if __name__ == "__main__":
    collector = DockerCollector()
    try:
        collector.run()
    except KeyboardInterrupt:
        collector.running = False
        print("\n[*] Exiting on user request.")
