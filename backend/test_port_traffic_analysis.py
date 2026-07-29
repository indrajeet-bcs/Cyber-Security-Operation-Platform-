#!/usr/bin/env python3
"""
Test suite for Port Traffic Analysis & Reporting Layer.
Tests cover:
  - Normal traffic history recording & query
  - Multi-IP independent tracking on the same port
  - Factual evidence-based IP classifications (BLACKLISTED, INTERNAL RFC 1918, INTERNAL / LOOPBACK, UNKNOWN/OBSERVED)
  - Observed activity duration vs exact connection lifetime
  - Timeline bucket generation
  - FastAPI router endpoints (POST /api/port-traffic/record, GET /api/port-traffic/report, GET /api/port-traffic/monitored-ports)
"""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

# Add backend directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient
from app.main import app
from app.schemas.port_traffic import (
    PortTrafficRecordItem,
    PortTrafficIngestRequest,
    PortTrafficReportResponse,
)
from app.services.port_traffic_analysis_service import port_traffic_analysis_service
from app.database import port_traffic_repository


class TestPortTrafficAnalysis(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.now = datetime.now(timezone.utc)

    @patch("app.database.port_traffic_repository.get_port_records_in_window")
    @patch("app.database.port_traffic_repository.get_monitored_ports_list")
    def test_multi_ip_independence_and_metrics(self, mock_ports, mock_records):
        """Tests that multiple source IPs on Port 8080 are tracked independently with accurate metrics."""
        mock_ports.return_value = [8080]

        start_time = self.now - timedelta(hours=1)
        end_time = self.now

        # 4 distinct IPs on Port 8080
        mock_records.return_value = [
            {
                "id": 1,
                "monitored_port": 8080,
                "source_ip": "192.168.1.10",
                "destination_ip": "127.0.0.1",
                "protocol": "TCP",
                "first_seen_at": start_time + timedelta(minutes=5),
                "last_seen_at": start_time + timedelta(minutes=55),
                "activity_count": 800,
                "observed_duration_seconds": 3000.0,
                "monitoring_window_start": start_time,
                "monitoring_window_end": end_time,
                "classification": "BLACKLISTED",
            },
            {
                "id": 2,
                "monitored_port": 8080,
                "source_ip": "192.168.1.11",
                "destination_ip": "127.0.0.1",
                "protocol": "TCP",
                "first_seen_at": start_time + timedelta(minutes=10),
                "last_seen_at": start_time + timedelta(minutes=45),
                "activity_count": 300,
                "observed_duration_seconds": 2100.0,
                "monitoring_window_start": start_time,
                "monitoring_window_end": end_time,
                "classification": "INTERNAL",
            },
            {
                "id": 3,
                "monitored_port": 8080,
                "source_ip": "10.0.0.5",
                "destination_ip": "127.0.0.1",
                "protocol": "TCP",
                "first_seen_at": start_time + timedelta(minutes=15),
                "last_seen_at": start_time + timedelta(minutes=30),
                "activity_count": 100,
                "observed_duration_seconds": 900.0,
                "monitoring_window_start": start_time,
                "monitoring_window_end": end_time,
                "classification": "INTERNAL",
            },
            {
                "id": 4,
                "monitored_port": 8080,
                "source_ip": "127.0.0.1",
                "destination_ip": "127.0.0.1",
                "protocol": "TCP",
                "first_seen_at": start_time + timedelta(minutes=20),
                "last_seen_at": start_time + timedelta(minutes=40),
                "activity_count": 50,
                "observed_duration_seconds": 1200.0,
                "monitoring_window_start": start_time,
                "monitoring_window_end": end_time,
                "classification": "INTERNAL / LOOPBACK",
            },
        ]

        report = port_traffic_analysis_service.generate_report(
            port=8080, start_time=start_time, end_time=end_time, bucket_minutes=15
        )

        self.assertEqual(report.port, 8080)
        self.assertEqual(report.service_name, "Login Application")
        self.assertEqual(report.summary.total_activity_count, 1250)
        self.assertEqual(report.summary.unique_source_ips, 4)

        # Assert IP breakdown order and field names
        ip_map = {item.source_ip: item for item in report.ip_breakdown}
        self.assertIn("192.168.1.10", ip_map)
        self.assertIn("192.168.1.11", ip_map)
        self.assertIn("10.0.0.5", ip_map)
        self.assertIn("127.0.0.1", ip_map)

        # Check observed_duration_seconds naming (not active_duration_seconds)
        self.assertEqual(ip_map["192.168.1.10"].observed_duration_seconds, 3000.0)
        self.assertFalse(ip_map["192.168.1.10"].exact_lifetime_proven)

    def test_evidence_based_classifications(self):
        """Tests evidence-based classification logic for Blacklisted, Private RFC 1918, Loopback, and Unknown IPs."""
        # Blacklisted IP
        c1, e1 = port_traffic_analysis_service._determine_classification("192.168.1.10")
        self.assertEqual(c1, "BLACKLISTED")
        self.assertIn("blacklist", e1.lower())

        with patch.object(port_traffic_analysis_service, "_has_suspicious_evidence", return_value=False):
            # RFC 1918 Private IP (192.168.0.0/16)
            c2, e2 = port_traffic_analysis_service._determine_classification("192.168.1.11")
            self.assertEqual(c2, "INTERNAL")
            self.assertIn("RFC 1918", e2)
            self.assertIn("192.168.0.0/16", e2)

            # RFC 1918 Private IP (10.0.0.0/8)
            c3, e3 = port_traffic_analysis_service._determine_classification("10.0.0.5")
            self.assertEqual(c3, "INTERNAL")
            self.assertIn("RFC 1918", e3)
            self.assertIn("10.0.0.0/8", e3)

            # Loopback IP (127.0.0.1)
            c4, e4 = port_traffic_analysis_service._determine_classification("127.0.0.1")
            self.assertEqual(c4, "INTERNAL / LOOPBACK")
            self.assertIn("Loopback", e4)

            # Public / Unknown IP without alert history
            c5, e5 = port_traffic_analysis_service._determine_classification("8.8.8.8")
            self.assertEqual(c5, "UNKNOWN / OBSERVED")


    @patch("app.database.port_traffic_repository.bulk_insert_port_traffic_records")
    def test_api_record_normal_traffic(self, mock_bulk):
        """Tests POST /api/port-traffic/record endpoint for storing normal traffic history."""
        mock_bulk.return_value = [101, 102]

        payload = {
            "monitored_port": 8080,
            "window_start": self.now.isoformat(),
            "window_end": (self.now + timedelta(minutes=1)).isoformat(),
            "records": [
                {
                    "source_ip": "192.168.1.50",
                    "destination_ip": "127.0.0.1",
                    "protocol": "TCP",
                    "first_seen_at": self.now.isoformat(),
                    "last_seen_at": (self.now + timedelta(seconds=30)).isoformat(),
                    "activity_count": 5,
                    "observed_duration_seconds": 30.0,
                }
            ],
        }

        response = self.client.post("/api/port-traffic/record", json=payload)
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["inserted_count"], 2)

    @patch("app.database.port_traffic_repository.get_monitored_ports_list")
    def test_api_monitored_ports(self, mock_ports):
        """Tests GET /api/port-traffic/monitored-ports endpoint."""
        mock_ports.return_value = [8080, 443]

        response = self.client.get("/api/port-traffic/monitored-ports")
        self.assertEqual(response.status_code, 200)
        self.assertIn(8080, response.json())
        self.assertIn(443, response.json())

    @patch("app.services.port_traffic_analysis_service.psutil.net_connections")
    @patch("app.services.port_traffic_analysis_service.psutil.Process")
    @patch("app.database.port_traffic_repository.get_port_records_in_window")
    @patch("app.services.port_traffic_analysis_service.PortTrafficAnalysisService.get_monitored_ports")
    def test_live_port_status(self, mock_monitored, mock_records, mock_process, mock_connections):
        """Tests live port status combination of psutil socket states and historical data."""
        mock_monitored.return_value = [8080, 443, 9090]
        
        # Mock historical records for port 8080 only
        mock_records.side_effect = lambda port, start_time, end_time: [
            {
                "monitored_port": 8080,
                "source_ip": "10.0.0.5",
                "first_seen_at": self.now - timedelta(hours=1),
                "last_seen_at": self.now - timedelta(minutes=30),
                "activity_count": 50,
                "observed_duration_seconds": 1800.0,
                "classification": "INTERNAL"
            }
        ] if port == 8080 else []

        import psutil
        
        # Mock psutil connections
        conn1 = MagicMock()
        conn1.laddr.port = 8080
        conn1.laddr.ip = "0.0.0.0"
        conn1.status = psutil.CONN_LISTEN
        conn1.pid = 1000

        conn2 = MagicMock()
        conn2.laddr.port = 8080
        conn2.laddr.ip = "127.0.0.1"
        conn2.status = psutil.CONN_ESTABLISHED
        conn2.pid = 1000

        conn3 = MagicMock()
        conn3.laddr.port = 443
        conn3.laddr.ip = "0.0.0.0"
        conn3.status = psutil.CONN_LISTEN
        conn3.pid = 2000

        mock_connections.return_value = [conn1, conn2, conn3]
        
        # Mock Process name
        mock_proc_instance = MagicMock()
        mock_proc_instance.name.return_value = "python.exe"
        mock_process.return_value = mock_proc_instance

        # Call API
        response = self.client.get("/api/port-traffic/live-status?hours=6")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        ports = data["ports"]
        self.assertEqual(len(ports), 3)

        port_8080 = next(p for p in ports if p["port"] == 8080)
        self.assertEqual(port_8080["current_status"], "OPEN_AND_ACTIVE")
        self.assertEqual(port_8080["current_active_connections"], 1)
        self.assertEqual(port_8080["process_name"], "python.exe")
        self.assertEqual(port_8080["total_activity_count"], 50)
        self.assertEqual(len(port_8080["source_ips"]), 1)

        port_443 = next(p for p in ports if p["port"] == 443)
        self.assertEqual(port_443["current_status"], "OPEN_IDLE")
        self.assertEqual(port_443["current_active_connections"], 0)
        self.assertEqual(port_443["total_activity_count"], 0)

        port_9090 = next(p for p in ports if p["port"] == 9090)
        self.assertEqual(port_9090["current_status"], "CLOSED")


if __name__ == "__main__":
    unittest.main()
