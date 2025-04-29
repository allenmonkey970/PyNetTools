import unittest
from main import resolve_hostname, ping, traceroute

class TestPingTracerouteTool(unittest.TestCase):

    def test_resolve_hostname(self):
        # Test resolving a valid hostname
        resolved_ip = resolve_hostname("google.com")
        self.assertIsNotNone(resolved_ip, "Failed to resolve hostname to IP address.")

    def test_ping(self):
        # Test pinging a valid target
        result = ping("8.8.8.8", count=1)
        self.assertTrue(result, "Ping failed to receive any replies.")

    def test_traceroute(self):
        # Test traceroute to a valid target
        result = traceroute("8.8.8.8", max_hops=30)
        self.assertTrue(result, "Traceroute failed to reach the target.")

if __name__ == "__main__":
    unittest.main()