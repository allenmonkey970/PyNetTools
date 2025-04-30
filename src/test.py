import unittest
from unittest.mock import patch, Mock, MagicMock
import json
import os
import socket

from src.main import NetworkTool


class TestNetworkTool(unittest.TestCase):

    @patch('os.makedirs')
    @patch('os.path.exists')
    def setUp(self, mock_exists, mock_makedirs):
        mock_exists.return_value = False
        self.tool = NetworkTool()
        # Override the logger to avoid actual logging during tests
        self.tool.logger = Mock()

    @patch('socket.gethostbyname')
    def test_resolve_hostname_success(self, mock_gethostbyname):
        # Setup mock
        mock_gethostbyname.return_value = '142.250.190.78'

        # Test
        result = self.tool.resolve_hostname('google.com')

        # Verify
        self.assertEqual(result, '142.250.190.78')
        mock_gethostbyname.assert_called_once_with('google.com')

    @patch('socket.gethostbyname')
    def test_resolve_hostname_failure(self, mock_gethostbyname):
        # Setup mock to raise an exception
        mock_gethostbyname.side_effect = socket.gaierror("Name or service not known")

        # Test
        result = self.tool.resolve_hostname('invalid.hostname')

        # Verify
        self.assertIsNone(result)
        mock_gethostbyname.assert_called_once_with('invalid.hostname')

    @patch('src.main.sr1')
    @patch('src.main.IP')
    def test_ping_success(self, mock_ip, mock_sr1):
        # Create a return value that will make the ping function return True
        mock_reply = MagicMock()
        mock_reply.src = '8.8.8.8'
        # These attributes ensure proper RTT calculation
        mock_reply.time = 10.0

        # Setup packet with correct attributes
        mock_packet = MagicMock()
        mock_packet.sent_time = 9.0

        # Configure mocks to return our prepared objects
        mock_ip.return_value = mock_packet
        mock_sr1.return_value = mock_reply

        # Override the print function to avoid console output
        with patch('builtins.print'):
            # Call the method with count=1 to simplify testing
            result = self.tool.ping('8.8.8.8', count=1)

        # Verify
        self.assertTrue(result)
        mock_sr1.assert_called_once()

    @patch('src.main.sr1')
    @patch('src.main.IP')
    def test_ping_failure(self, mock_ip, mock_sr1):
        # Setup mocks
        mock_sr1.return_value = None

        # Test
        result = self.tool.ping('8.8.8.8', count=1)

        # Verify
        self.assertFalse(result)
        mock_sr1.assert_called_once()

    @patch('socket.gethostbyaddr')
    @patch('src.main.sr1')
    @patch('src.main.IP')
    def test_traceroute_success(self, mock_ip, mock_sr1, mock_gethostbyaddr):
        # Setup mocks
        mock_reply = Mock()
        mock_reply.src = '8.8.8.8'
        mock_reply.type = 0  # ICMP Echo Reply
        mock_sr1.return_value = mock_reply
        mock_gethostbyaddr.return_value = ('dns.google', [], ['8.8.8.8'])

        # Test
        result = self.tool.traceroute('8.8.8.8', max_hops=1)

        # Verify
        self.assertTrue(result)
        mock_sr1.assert_called_once()

    @patch('src.main.sr1')
    @patch('src.main.IP')
    def test_traceroute_failure(self, mock_ip, mock_sr1):
        # Setup mocks
        mock_sr1.return_value = None

        # Test
        result = self.tool.traceroute('8.8.8.8', max_hops=1)

        # Verify
        self.assertFalse(result)
        mock_sr1.assert_called_once()

    @patch('src.main.speedtest.Speedtest')
    def test_speed_test(self, mock_speedtest_class):
        # Setup mock
        mock_speedtest = Mock()
        mock_speedtest.download.return_value = 100000000  # 100 Mbps
        mock_speedtest.upload.return_value = 50000000  # 50 Mbps
        mock_speedtest.results.ping = 20
        mock_speedtest.results.server = {'host': 'test-server'}
        mock_speedtest.results.timestamp = '2023-01-01'
        mock_speedtest_class.return_value = mock_speedtest

        # Test
        with patch('builtins.open', unittest.mock.mock_open()) as mock_file:
            download, upload, ping = self.tool.speed_test()

        # Verify
        self.assertEqual(download, 100)
        self.assertEqual(upload, 50)
        self.assertEqual(ping, 20)
        mock_speedtest.download.assert_called_once()
        mock_speedtest.upload.assert_called_once()

    @patch('nmap.PortScanner')
    def test_port_scan(self, mock_port_scanner_class):
        # Setup mock
        mock_scanner = MagicMock()
        mock_scanner.all_hosts.return_value = ['8.8.8.8']

        # Use MagicMock's __getitem__ behavior instead of trying to mock it directly
        host_info = MagicMock()
        host_info.hostname.return_value = 'dns.google'
        host_info.state.return_value = 'up'
        host_info.all_protocols.return_value = ['tcp']
        host_info['tcp'] = {80: {'state': 'open', 'name': 'http'}}

        # Configure the dictionary-like access
        mock_scanner.__getitem__.return_value = host_info
        mock_port_scanner_class.return_value = mock_scanner

        # Test
        with patch('builtins.open', unittest.mock.mock_open()) as mock_file:
            self.tool.port_scan('8.8.8.8', ports='80')

        # Verify
        mock_scanner.scan.assert_called_once()
        mock_scanner.all_hosts.assert_called_once()

    @patch('nmap.PortScanner')
    def test_os_scan(self, mock_port_scanner_class):
        # Setup mock
        mock_scanner = MagicMock()
        mock_scanner.all_hosts.return_value = ['8.8.8.8']

        # Use MagicMock's __getitem__ behavior
        host_info = MagicMock()
        host_info.hostname.return_value = 'dns.google'
        host_info.state.return_value = 'up'
        host_info['osmatch'] = [{'name': 'Linux', 'accuracy': '95'}]

        # Configure the dictionary-like access
        mock_scanner.__getitem__.return_value = host_info
        mock_port_scanner_class.return_value = mock_scanner

        # Test
        with patch('builtins.open', unittest.mock.mock_open()) as mock_file:
            self.tool.os_scan('8.8.8.8')

        # Verify
        mock_scanner.scan.assert_called_once()


if __name__ == '__main__':
    unittest.main()