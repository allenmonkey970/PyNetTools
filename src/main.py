import socket
import sys
import ipaddress

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

conf.use_pcap = True


def resolve_hostname(target):
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"Error: Unable to resolve {target}. Please check the hostname or IP.")
        return None


def ping(target, count=4, timeout=1):
    """Ping a target using ICMP Echo Requests."""
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
            print(f"Error during ping: {e}")
    return success


def ping_sweep(subnet, timeout=1):
    """Perform a ping sweep on a given subnet."""
    print(f"\nPerforming ping sweep on subnet: {subnet}")
    live_hosts = []

    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        print("Error: Invalid subnet or IP range.")
        return

    for ip in network.hosts():
        try:
            packet = IP(dst=str(ip)) / ICMP()
            reply = sr1(packet, timeout=timeout, verbose=0)
            if reply:
                print(f"Host {ip} is up.")
                live_hosts.append(str(ip))
            else:
                print(f"Host {ip} is down.")
        except Exception as e:
            print(f"Error during ping sweep for {ip}: {e}")

    if live_hosts:
        print("\nLive hosts found:")
        for host in live_hosts:
            print(f"- {host}")
    else:
        print("\nNo live hosts found.")

    return live_hosts


def traceroute(target, max_hops=30, timeout=1, save_to_file=False):
    """Perform a traceroute to the target."""
    print(f"\nTraceroute to {target}, max hops: {max_hops}")
    results = []
    reached_target = False
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
            print(f"Error during traceroute: {e}")
            break

    if save_to_file:
        try:
            with open("traceroute_results.txt", "w") as file:
                file.write("\n".join(results))
            print("\nResults saved to 'traceroute_results.txt'.")
        except IOError as e:
            print(f"Error saving results to file: {e}")

    return reached_target


def speed_test():
    """Perform a speed test on your current internet connection."""
    st = speedtest.Speedtest(secure=True)
    st.get_best_server()
    print("Testing download speed...")
    download_speed = st.download() / 1000000  # Convert to Mbps
    print(f"Download Speed: {download_speed:.2f} Mbps")

    print("Testing upload speed...")
    upload_speed = st.upload() / 1000000  # Convert to Mbps
    print(f"Upload Speed: {upload_speed:.2f} Mbps")


def port_scan(target, ports="1-1024"):
    """Perform a port scan on the target."""
    print(f"\nPerforming port scan on {target} (ports: {ports})")
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, ports=ports, arguments="-sS")
        for host in nm.all_hosts():
            print(f"Host: {host} ({nm[host].hostname()})")
            print(f"State: {nm[host].state()}")
            for proto in nm[host].all_protocols():
                print(f"Protocol: {proto}")
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    state = nm[host][proto][port]["state"]
                    print(f"Port: {port}\tState: {state}")
    except Exception as e:
        print(f"Error during port scan: {e}")


def os_scan(target):
    """Perform an OS scan on the target."""
    print(f"\nPerforming OS scan on {target}")
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, arguments="-O")
        for host in nm.all_hosts():
            print(f"Host: {host} ({nm[host].hostname()})")
            print(f"State: {nm[host].state()}")
            if "osmatch" in nm[host]:
                print("OS Matches:")
                for os in nm[host]["osmatch"]:
                    print(f"- {os['name']} (Accuracy: {os['accuracy']}%)")
            else:
                print("No OS information available.")
    except Exception as e:
        print(f"Error during OS scan: {e}")


if __name__ == "__main__":
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
                speed_test()
            elif choice == "2":
                target = input("Enter the target IP or hostname: ")
                resolved_target = resolve_hostname(target)
                if not resolved_target:
                    continue

                try:
                    count = int(input("Enter the number of ping packets (default: 4): ") or 4)
                    timeout = float(input("Enter the timeout for each request in seconds (default: 1): ") or 1)
                except ValueError:
                    print("Error: Invalid input. Please enter numeric values.")
                    continue

                ping(resolved_target, count, timeout)
            elif choice == "3":
                target = input("Enter the target IP or hostname: ")
                resolved_target = resolve_hostname(target)
                if not resolved_target:
                    continue

                try:
                    max_hops = int(input("Enter the maximum hops for traceroute (default: 30): ") or 30)
                    timeout = float(input("Enter the timeout for each request in seconds (default: 1): ") or 1)
                except ValueError:
                    print("Error: Invalid input. Please enter numeric values.")
                    continue

                save_to_file = input("Save traceroute results to file? (yes/no): ").strip().lower() == "yes"
                traceroute(resolved_target, max_hops, timeout, save_to_file)
            elif choice == "4":
                subnet = input("Enter the subnet (e.g., 192.168.1.0/24): ").strip()
                try:
                    timeout = float(input("Enter the timeout for each request in seconds (default: 1): ") or 1)
                except ValueError:
                    print("Error: Invalid input. Please enter a numeric value.")
                    continue

                ping_sweep(subnet, timeout)
            elif choice == "5":
                target = input("Enter the target IP or hostname: ")
                resolved_target = resolve_hostname(target)
                if not resolved_target:
                    continue

                ports = input("Enter the port range (default: 1-1024): ").strip() or "1-1024"
                port_scan(resolved_target, ports)
            elif choice == "6":
                target = input("Enter the target IP or hostname: ")
                resolved_target = resolve_hostname(target)
                if not resolved_target:
                    continue

                os_scan(resolved_target)
            elif choice == "7":
                print("Exiting. Goodbye!")
                break
            else:
                print("Invalid choice. Please select a valid option.")
    except KeyboardInterrupt:
        print("\nOperation canceled by user.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")