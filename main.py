import socket
import sys

try:
    from scapy.all import IP, ICMP, sr1, conf
    import speedtest
except ImportError:
    print("Error: Scapy is not installed. Install it using 'pip install scapy'.")
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
    st = speedtest.Speedtest()
    print("Testing download speed...")
    download_speed = st.download() / 1000000  # Convert to Mbps
    print(f"Download Speed: {download_speed:.2f} Mbps")

    print("Testing upload speed...")
    upload_speed = st.upload() / 1000000  # Convert to Mbps
    print(f"Upload Speed: {upload_speed:.2f} Mbps")


if __name__ == "__main__":
    try:
        while True:
            print("\nNetwork Tool Menu:")
            print("1. Perform Speed Test")
            print("2. Ping a Target")
            print("3. Traceroute to a Target")
            print("4. Exit")
            choice = input("Enter your choice (1-4): ").strip()

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
                print("Exiting. Goodbye!")
                break
            else:
                print("Invalid choice. Please select a valid option.")
    except KeyboardInterrupt:
        print("\nOperation canceled by user.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
