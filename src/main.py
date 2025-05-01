import socket
import sys
import os
import json
import logging
import threading
import ipaddress
import concurrent.futures
import argparse

try:
    from scapy.all import IP, ICMP, sr1, conf
except ImportError:
    print("Error: Scapy is not installed. Install it using 'pip install scapy'.")
    sys.exit(1)
try:
    import speedtest
except ImportError:
    print("Error: Speedtest module is not installed. Install it using 'pip install speedtest-cli'.")
    sys.exit(1)
try:
    import nmap
except ImportError:
    print("Error: python-nmap is not installed. Install it using 'pip install python-nmap'.")
    sys.exit(1)
try:
    import tqdm
except ImportError:
    print("Error: tqdm is not installed. Install it using 'pip install tqdm'.")
    sys.exit(1)

try:
    # Optional visualization imports
    import matplotlib.pyplot as plt
    import networkx as nx
    visualization_available = True
except ImportError:
    visualization_available = False


class NetworkTool:
    def __init__(self):
        self.results_dir = "results"
        os.makedirs(self.results_dir, exist_ok=True)
        self.config = self.load_config()
        self.logger = self.setup_logging()

        # Check for admin privileges
        try:
            conf.use_pcap = True
            # Test if we have necessary permissions
            test_packet = IP(dst="127.0.0.1") / ICMP()
            sr1(test_packet, timeout=0.1, verbose=0)
        except Exception:
            self.logger.warning("Some features require administrator/root privileges")
            print("Warning: Some features require administrator/root privileges")

    def load_config(self):
        """Load configuration from config.json if exists."""
        config_file = "config.json"
        default_config = {
            "timeout": 1,
            "max_hops": 30,
            "threads": 10,
            "default_ports": "1-1024"
        }

        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                print("Error in config file. Using defaults.")

        return default_config

    def setup_logging(self):
        """Setup logging to file and console."""
        log_file = os.path.join(self.results_dir, "network_tool.log")
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger('network_tool')

    def resolve_hostname(self, target):
        """Resolve hostname to IP address."""
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            self.logger.error(f"Unable to resolve {target}")
            print(f"Error: Unable to resolve {target}. Please check the hostname or IP.")
            return None

    def ping(self, target, count=4, timeout=1):
        """Ping a target using ICMP Echo Requests."""
        self.logger.info(f"Pinging {target} with {count} packets")
        print(f"\nPinging {target} with {count} packets:")
        success = False
        for i in range(count):
            try:
                packet = IP(dst=target) / ICMP()
                reply = sr1(packet, timeout=timeout, verbose=0)
                if reply:
                    success = True
                    rtt = (reply.time - packet.sent_time) * 1000
                    print(f"Reply from {reply.src}: time={rtt:.2f} ms")
                else:
                    print("Request timed out.")
            except Exception as e:
                self.logger.error(f"Error during ping: {e}")
                print(f"Error during ping: {e}")
        return success

    def ping_sweep(self, subnet, timeout=1, threads=10):
        """Perform a ping sweep on a given subnet using multiple threads."""
        self.logger.info(f"Performing ping sweep on subnet: {subnet}")
        print(f"\nPerforming ping sweep on subnet: {subnet}")
        live_hosts = []
        lock = threading.Lock()

        try:
            network = ipaddress.ip_network(subnet, strict=False)
            hosts = list(network.hosts())
        except ValueError:
            self.logger.error(f"Invalid subnet: {subnet}")
            print("Error: Invalid subnet or IP range.")
            return []

        def ping_host(ip):
            try:
                packet = IP(dst=str(ip)) / ICMP()
                reply = sr1(packet, timeout=timeout, verbose=0)
                if reply:
                    with lock:
                        print(f"Host {ip} is up.")
                        live_hosts.append(str(ip))
                else:
                    with lock:
                        print(f"Host {ip} is down.")
            except Exception as e:
                with lock:
                    self.logger.error(f"Error during ping sweep for {ip}: {e}")
                    print(f"Error during ping sweep for {ip}: {e}")

        with tqdm(total=len(hosts), desc="Scanning hosts") as pbar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                future_to_ip = {executor.submit(ping_host, ip): ip for ip in hosts}
                for future in concurrent.futures.as_completed(future_to_ip):
                    pbar.update(1)

        if live_hosts:
            print("\nLive hosts found:")
            for host in live_hosts:
                print(f"- {host}")
        else:
            print("\nNo live hosts found.")

        # Save results to file
        result_file = os.path.join(self.results_dir, f"ping_sweep_{subnet.replace('/', '_')}.txt")
        try:
            with open(result_file, "w") as file:
                file.write("\n".join(live_hosts))
            print(f"\nResults saved to '{result_file}'.")
        except IOError as e:
            self.logger.error(f"Error saving results to file: {e}")
            print(f"Error saving results to file: {e}")

        return live_hosts

    def traceroute(self, target, max_hops=30, timeout=1, save_to_file=False):
        """Perform a traceroute to the target."""
        self.logger.info(f"Traceroute to {target}, max hops: {max_hops}")
        print(f"\nTraceroute to {target}, max hops: {max_hops}")
        results = []
        reached_target = False

        with tqdm.tqdm(total=max_hops, desc="Tracing route") as pbar:
            for ttl in range(1, max_hops + 1):
                try:
                    packet = IP(dst=target, ttl=ttl) / ICMP()
                    reply = sr1(packet, timeout=timeout, verbose=0)
                    if reply:
                        try:
                            hostname = socket.gethostbyaddr(reply.src)[0]
                        except socket.herror:
                            hostname = "Unknown"
                        print(f"{ttl}\t{reply.src} ({hostname})")
                        results.append(f"{ttl}\t{reply.src} ({hostname})")
                        if reply.type == 0:  # ICMP Echo Reply
                            print("Reached target.")
                            reached_target = True
                            break
                    else:
                        print(f"{ttl}\t*")
                        results.append(f"{ttl}\t*")
                except Exception as e:
                    self.logger.error(f"Error during traceroute: {e}")
                    print(f"Error during traceroute: {e}")
                    break
                pbar.update(1)

        if save_to_file:
            result_file = os.path.join(self.results_dir, f"traceroute_{target}.txt")
            try:
                with open(result_file, "w") as file:
                    file.write("\n".join(results))
                print(f"\nResults saved to '{result_file}'.")
            except IOError as e:
                self.logger.error(f"Error saving results to file: {e}")
                print(f"Error saving results to file: {e}")

        # Generate visualization if available
        if visualization_available and len(results) > 0:
            self.visualize_traceroute(results, target)

        return reached_target

    def visualize_traceroute(self, results, target):
        """Create a visual representation of traceroute results."""
        if not visualization_available:
            return

        G = nx.DiGraph()
        prev_node = "You"

        for hop in results:
            if "*" not in hop:
                parts = hop.split('\t')
                if len(parts) >= 2:
                    hop_num = parts[0]
                    ip = parts[1].split()[0]
                    G.add_edge(prev_node, ip)
                    prev_node = ip

        plt.figure(figsize=(10, 8))
        nx.draw(G, with_labels=True, node_color='lightblue',
                node_size=1500, arrows=True)
        plt.title(f"Traceroute to {target}")

        viz_file = os.path.join(self.results_dir, f"traceroute_{target}.png")
        plt.savefig(viz_file)
        print(f"Traceroute visualization saved to {viz_file}")

    def speed_test(self):
        """Perform a speed test on your current internet connection."""
        self.logger.info("Starting speed test")
        print("\nStarting speed test...")
        try:
            st = speedtest.Speedtest(secure=True)
            st.get_best_server()

            print("Testing download speed...")
            download_speed = st.download() / 1000000  # Convert to Mbps
            print(f"Download Speed: {download_speed:.2f} Mbps")

            print("Testing upload speed...")
            upload_speed = st.upload() / 1000000  # Convert to Mbps
            print(f"Upload Speed: {upload_speed:.2f} Mbps")

            ping_latency = st.results.ping
            print(f"Ping Latency: {ping_latency:.2f} ms")

            # Save results to file
            result_file = os.path.join(self.results_dir, "speedtest_results.json")
            with open(result_file, "w") as f:
                json.dump({
                    "download_mbps": round(download_speed, 2),
                    "upload_mbps": round(upload_speed, 2),
                    "ping_ms": round(ping_latency, 2),
                    "server": st.results.server,
                    "timestamp": st.results.timestamp
                }, f, indent=4)
            print(f"\nResults saved to '{result_file}'.")

            return download_speed, upload_speed, ping_latency
        except Exception as e:
            self.logger.error(f"Error during speed test: {e}")
            print(f"Error during speed test: {e}")
            return None

    def port_scan(self, target, ports="1-1024"):
        """Perform a port scan on the target."""
        self.logger.info(f"Performing port scan on {target} (ports: {ports})")
        print(f"\nPerforming port scan on {target} (ports: {ports})")
        nm = nmap.PortScanner()

        # Parse port range for progress bar
        if "-" in ports:
            start, end = map(int, ports.split("-"))
            total_ports = end - start + 1
        else:
            total_ports = len(ports.split(","))

        open_ports = []
        try:
            print("Scanning ports (this may take some time)...")
            nm.scan(hosts=target, ports=ports, arguments="-sS")

            for host in nm.all_hosts():
                print(f"Host: {host} ({nm[host].hostname() if nm[host].hostname() else 'Unknown'})")
                print(f"State: {nm[host].state()}")
                for proto in nm[host].all_protocols():
                    print(f"Protocol: {proto}")
                    ports = nm[host][proto].keys()
                    for port in sorted(ports):
                        state = nm[host][proto][port]["state"]
                        service = nm[host][proto][port]["name"]
                        print(f"Port: {port}\tState: {state}\tService: {service}")
                        if state == "open":
                            open_ports.append((port, service))

            # Save results to file
            result_file = os.path.join(self.results_dir, f"portscan_{target}.txt")
            try:
                with open(result_file, "w") as file:
                    file.write(f"Port scan results for {target}\n")
                    file.write("-" * 40 + "\n")
                    for port, service in open_ports:
                        file.write(f"Port {port}: {service}\n")
                print(f"\nResults saved to '{result_file}'.")
            except IOError as e:
                self.logger.error(f"Error saving results to file: {e}")
        except Exception as e:
            self.logger.error(f"Error during port scan: {e}")
            print(f"Error during port scan: {e}")

    def os_scan(self, target):
        """Perform an OS scan on the target."""
        self.logger.info(f"Performing OS scan on {target}")
        print(f"\nPerforming OS scan on {target}")
        nm = nmap.PortScanner()
        try:
            print("This may take some time...")
            nm.scan(hosts=target, arguments="-O")
            for host in nm.all_hosts():
                print(f"Host: {host} ({nm[host].hostname() if nm[host].hostname() else 'Unknown'})")
                print(f"State: {nm[host].state()}")

                # Save results to file
                result_file = os.path.join(self.results_dir, f"osscan_{target}.txt")
                try:
                    with open(result_file, "w") as file:
                        file.write(f"OS scan results for {target}\n")
                        file.write("-" * 40 + "\n")

                        if "osmatch" in nm[host]:
                            print("OS Matches:")
                            for os_match in nm[host]["osmatch"]:
                                print(f"- {os_match['name']} (Accuracy: {os_match['accuracy']}%)")
                                file.write(f"{os_match['name']} (Accuracy: {os_match['accuracy']}%)\n")
                        else:
                            print("No OS information available.")
                            file.write("No OS information available.\n")

                    print(f"\nResults saved to '{result_file}'.")
                except IOError as e:
                    self.logger.error(f"Error saving results to file: {e}")
                    print(f"Error saving results to file: {e}")
        except Exception as e:
            self.logger.error(f"Error during OS scan: {e}")
            print(f"Error during OS scan: {e}")

    def parse_args(self):
        """Parse command line arguments."""
        parser = argparse.ArgumentParser(description="Network Tool")
        subparsers = parser.add_subparsers(dest="command", help="Command to run")

        # Speed test parser
        subparsers.add_parser("speedtest", help="Run a speed test")

        # Ping parser
        ping_parser = subparsers.add_parser("ping", help="Ping a target")
        ping_parser.add_argument("target", help="Target IP or hostname")
        ping_parser.add_argument("-c", "--count", type=int, default=4, help="Number of packets")
        ping_parser.add_argument("-t", "--timeout", type=float, default=1, help="Timeout in seconds")

        # Traceroute parser
        tracert_parser = subparsers.add_parser("traceroute", help="Perform a traceroute")
        tracert_parser.add_argument("target", help="Target IP or hostname")
        tracert_parser.add_argument("-m", "--max-hops", type=int, default=30, help="Maximum hops")
        tracert_parser.add_argument("-t", "--timeout", type=float, default=1, help="Timeout in seconds")
        tracert_parser.add_argument("-s", "--save", action="store_true", help="Save results to file")

        # Ping sweep parser
        sweep_parser = subparsers.add_parser("sweep", help="Perform a ping sweep")
        sweep_parser.add_argument("subnet", help="Subnet to scan (e.g., 192.168.1.0/24)")
        sweep_parser.add_argument("-t", "--timeout", type=float, default=1, help="Timeout in seconds")
        sweep_parser.add_argument("--threads", type=int, default=10, help="Number of threads")

        # Port scan parser
        portscan_parser = subparsers.add_parser("portscan", help="Perform a port scan")
        portscan_parser.add_argument("target", help="Target IP or hostname")
        portscan_parser.add_argument("-p", "--ports", default="1-1024", help="Port range (e.g., 1-1024 or 22,80,443)")

        # OS scan parser
        osscan_parser = subparsers.add_parser("osscan", help="Perform an OS scan")
        osscan_parser.add_argument("target", help="Target IP or hostname")

        return parser.parse_args()

    def get_validated_input(self, prompt, validator=None, default=None):
        """Get validated user input with an optional default value."""
        while True:
            value = input(f"{prompt}{f' (default: {default})' if default else ''}: ").strip()
            if not value and default is not None:
                return default
            if not validator or validator(value):
                return value
            print("Invalid input. Please try again.")

    def run(self):
        """Run the network tool with command line arguments or interactive menu."""
        if len(sys.argv) > 1:
            args = self.parse_args()
            if args.command == "speedtest":
                self.speed_test()
            elif args.command == "ping":
                target = self.resolve_hostname(args.target)
                if target:
                    self.ping(target, args.count, args.timeout)
            elif args.command == "traceroute":
                target = self.resolve_hostname(args.target)
                if target:
                    self.traceroute(target, args.max_hops, args.timeout, args.save)
            elif args.command == "sweep":
                self.ping_sweep(args.subnet, args.timeout, args.threads)
            elif args.command == "portscan":
                target = self.resolve_hostname(args.target)
                if target:
                    self.port_scan(target, args.ports)
            elif args.command == "osscan":
                target = self.resolve_hostname(args.target)
                if target:
                    self.os_scan(target)
        else:
            self.interactive_menu()

    def interactive_menu(self):
        """Run the interactive menu."""
        try:
            while True:
                print("\nNetwork Tool Menu:")
                print("1. Perform Speed Test")
                print("2. Ping a Target")
                print("3. Traceroute to a Target")
                print("4. Ping Sweep")
                print("5. Port Scan")
                print("6. OS Scan")
                print("7. Exit")
                choice = input("Enter your choice (1-7): ").strip()

                if choice == "1":
                    self.speed_test()
                elif choice == "2":
                    target = input("Enter the target IP or hostname: ")
                    resolved_target = self.resolve_hostname(target)
                    if not resolved_target:
                        continue

                    try:
                        count = int(input("Enter the number of ping packets (default: 4): ") or 4)
                        timeout = float(input("Enter the timeout for each request in seconds (default: 1): ") or 1)
                    except ValueError:
                        print("Error: Invalid input. Please enter numeric values.")
                        continue

                    self.ping(resolved_target, count, timeout)
                elif choice == "3":
                    target = input("Enter the target IP or hostname: ")
                    resolved_target = self.resolve_hostname(target)
                    if not resolved_target:
                        continue

                    try:
                        max_hops = int(input("Enter the maximum hops for traceroute (default: 30): ") or 30)
                        timeout = float(input("Enter the timeout for each request in seconds (default: 1): ") or 1)
                    except ValueError:
                        print("Error: Invalid input. Please enter numeric values.")
                        continue

                    save_to_file = input("Save traceroute results to file? (yes/no): ").strip().lower() == "yes"
                    self.traceroute(resolved_target, max_hops, timeout, save_to_file)
                elif choice == "4":
                    subnet = input("Enter the subnet (e.g., 192.168.1.0/24): ").strip()
                    try:
                        timeout = float(input("Enter the timeout for each request in seconds (default: 1): ") or 1)
                        threads = int(input("Enter the number of threads (default: 10): ") or 10)
                    except ValueError:
                        print("Error: Invalid input. Please enter numeric values.")
                        continue

                    self.ping_sweep(subnet, timeout, threads)
                elif choice == "5":
                    target = input("Enter the target IP or hostname: ")
                    resolved_target = self.resolve_hostname(target)
                    if not resolved_target:
                        continue

                    ports = input("Enter the port range (default: 1-1024): ").strip() or "1-1024"
                    self.port_scan(resolved_target, ports)
                elif choice == "6":
                    target = input("Enter the target IP or hostname: ")
                    resolved_target = self.resolve_hostname(target)
                    if not resolved_target:
                        continue

                    self.os_scan(resolved_target)
                elif choice == "7":
                    print("Exiting. Goodbye!")
                    break
                else:
                    print("Invalid choice. Please select a valid option.")
        except KeyboardInterrupt:
            self.logger.info("Operation canceled by user")
            print("\nOperation canceled by user.")
        except Exception as e:
            self.logger.error(f"An unexpected error occurred: {e}")
            print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    tool = NetworkTool()
    tool.run()
