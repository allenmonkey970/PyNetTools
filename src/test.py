import unittest
from unittest.mock import patch

from src.main import resolve_hostname, ping, traceroute, speed_test, port_scan, os_scan


class TestPingTracerouteTool(unittest.TestCase):

    def test_resolve_hostname(self):
        # Test resolving a valid hostname
        resolved_ip = resolve_hostname("google.com")
        self.assertIsNotNone(resolved_ip, "Failed to resolve hostname to IP address.")

    def test_resolve_hostname_invalid(self):
        # Test resolving an invalid hostname
        resolved_ip = resolve_hostname("invalid.hostname")
        self.assertIsNone(resolved_ip, "Invalid hostname should not resolve to an IP.")

    def test_ping(self):
        # Test pinging a valid target
        result = ping("8.8.8.8", count=1)
        self.assertTrue(result, "Ping failed to receive any replies.")

    def test_ping_invalid_target(self):
        # Test pinging an invalid target
        result = ping("256.256.256.256", count=1)
        self.assertFalse(result, "Ping to an invalid target should fail.")

    def test_traceroute(self):
        # Test traceroute to a valid target
        result = traceroute("8.8.8.8", max_hops=30)
        self.assertTrue(result, "Traceroute failed to reach the target.")

    def test_traceroute_unreachable(self):
        # Test traceroute to an unreachable target
        result = traceroute("10.255.255.1.2", max_hops=5)
        self.assertFalse(result, "Traceroute to an unreachable target should fail.")

    def test_speed_test(self):
        try:
            speed_test()  # Perform an actual speed test
        except Exception as e:
            self.fail(f"speed_test raised an exception: {e}")

    @patch("src.main.nmap.PortScanner.scan")
    def test_os_scan(self, mock_scan):
        mock_scan.return_value = None  # Simulate a successful scan
        try:
            os_scan("8.8.8.8")
        except Exception as e:
            self.fail(f"os_scan raised an exception: {e}")

    @patch("src.main.nmap.PortScanner.scan")
    def test_port_scan(self, mock_scan):
        mock_scan.return_value = None  # Simulate a successful scan
        try:
            port_scan("8.8.8.8", ports="22-80")
        except Exception as e:
            self.fail(f"port_scan raised an exception: {e}")

if __name__ == "__main__":
    unittest.main()
