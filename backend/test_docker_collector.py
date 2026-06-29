import os
import sys
import time
import unittest
import requests
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from collectors.docker_collector import DockerCollector

class TestDockerCollectorUnit(unittest.TestCase):
    def setUp(self):
        self.collector = DockerCollector()
        self.collector.running = False # Don't start loops immediately
        
    @patch('collectors.docker_collector.requests.post')
    def test_send_to_backend(self, mock_post):
        # Setup mock responses
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_post.return_value = mock_response
        
        payload = {"source": "docker", "event_type": "docker.stdout", "message": "test message"}
        result = self.collector.send_to_backend(payload)
        
        self.assertTrue(result)
        mock_post.assert_called_once_with(self.collector.backend_url, json=payload, timeout=5)

    def test_get_container_metadata(self):
        mock_container = MagicMock()
        mock_container.id = "abcdef1234567890"
        mock_container.name = "test-container"
        mock_container.image.tags = ["ubuntu:latest"]
        mock_container.status = "running"
        
        metadata = self.collector.get_container_metadata(mock_container)
        
        self.assertEqual(metadata["container_id"], "abcdef1234567890")
        self.assertEqual(metadata["container_name"], "test-container")
        self.assertEqual(metadata["image"], "ubuntu:latest")
        self.assertEqual(metadata["container_status"], "running")
        self.assertEqual(metadata["docker_host"], self.collector.host_name)

    @patch('collectors.docker_collector.requests.post')
    def test_process_lifecycle_event(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_post.return_value = mock_response
        
        # Test start container event
        event = {
            "Action": "start",
            "Type": "container",
            "id": "abcdef1234567890",
            "time": int(time.time()),
            "Actor": {
                "Attributes": {
                    "name": "test-container",
                    "image": "ubuntu:latest"
                }
            }
        }
        
        self.collector.process_lifecycle_event(event)
        
        self.assertTrue(mock_post.called)
        call_args = mock_post.call_args[1]["json"]
        self.assertEqual(call_args["source"], "docker")
        self.assertEqual(call_args["event_type"], "docker.container_started")
        self.assertEqual(call_args["metadata"]["docker_event_id"], "abcdef1234567890")
        self.assertEqual(call_args["metadata"]["container_id"], "abcdef1234567890")
        self.assertEqual(call_args["metadata"]["container_name"], "test-container")
        self.assertIn("soc_event_id", call_args["metadata"])
        self.assertEqual(len(call_args["metadata"]["soc_event_id"]), 36)

    @patch('collectors.docker_collector.requests.post')
    def test_duplicate_event_skipping(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_post.return_value = mock_response

        event = {
            "Action": "start",
            "Type": "container",
            "id": "dup-id-123456",
            "time": 123456789,
            "Actor": {
                "Attributes": {
                    "name": "test-container-dup",
                    "image": "ubuntu:latest"
                }
            }
        }

        # Send first time
        self.collector.process_lifecycle_event(event)
        self.assertEqual(mock_post.call_count, 1)

        # Send second time (should be skipped)
        self.collector.process_lifecycle_event(event)
        self.assertEqual(mock_post.call_count, 1)

class TestDockerCollectorIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Try to ping the backend to see if it's running
        cls.backend_running = False
        try:
            r = requests.get("http://127.0.0.1:8000/health", timeout=2)
            if r.status_code == 200:
                cls.backend_running = True
        except Exception:
            pass

    def test_api_log_ingestion(self):
        if not self.backend_running:
            self.skipTest("FastAPI backend is not running at http://127.0.0.1:8000")
            
        collector = DockerCollector()
        
        # Test sending a mock docker stdout log
        payload = {
            "source": "docker",
            "event_type": "docker.stdout",
            "message": "Permission denied while accessing /etc/passwd",
            "severity": "warning",
            "host": collector.host_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metadata": {
                "container_id": "test12345678",
                "container_name": "test_ubuntu",
                "image": "ubuntu:latest",
                "container_status": "running",
                "docker_host": collector.host_name
            }
        }
        
        # Ingest via collector method
        success = collector.send_to_backend(payload)
        self.assertTrue(success)
        
        # Verify it appears in GET /api/logs/
        time.sleep(1) # Allow in-memory DB to process
        r = requests.get("http://127.0.0.1:8000/api/logs/")
        self.assertEqual(r.status_code, 200)
        logs = r.json()
        print(f"DEBUG integration test: fetched logs = {logs}")
        
        # Find our logged message
        found = False
        for log in logs:
            if log.get("source") == "docker" and log.get("message") == "Permission denied while accessing /etc/passwd":
                found = True
                # Check metadata was preserved
                self.assertEqual(log["metadata"]["container_id"], "test12345678")
                self.assertEqual(log["metadata"]["container_name"], "test_ubuntu")
                self.assertEqual(log["metadata"]["image"], "ubuntu:latest")
                break
                
        self.assertTrue(found, f"Log not found in backend list: {logs}")

if __name__ == "__main__":
    unittest.main()
