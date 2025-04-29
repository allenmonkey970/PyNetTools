# Ping-Traceroute-Tool

This Python script can perform **ping** and **traceroute** operations. It uses the `scapy` library for network packet manipulation and includes features like DNS resolution, reverse DNS lookup, and saving traceroute results to a file.

## Features

- Ping a target with customizable packet count and timeout.
- Perform a traceroute to a target with reverse DNS lookup.
- Resolve hostnames to IP addresses.
- Save traceroute results to a file.
- User input prompts.

## Requirements

- Python 3.6 or higher
- `scapy` library

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/allenmonkey970/Ping-Traceroute-Tool.git
   cd Ping-Traceroute-Tool
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the script and follow the prompts to perform ping or traceroute operations:

```bash
python main.py
```

### Example

1. Enter the target IP or hostname:
   ```
   Enter the target IP or hostname: 8.8.8.8
   ```

2. Specify the number of ping packets:
   ```
   Enter the number of ping packets (default: 4): 5
   ```

3. Specify the maximum hops for traceroute:
   ```
   Enter the maximum hops for traceroute (default: 30): 20
   ```

4. Save traceroute results to a file:
   ```
   Save traceroute results to file? (yes/no): yes
   ```

## Output

- **Ping**: Displays the round-trip time (RTT) for each packet.
- **Traceroute**: Shows each hop's IP address and hostname (if available).
- **File Output**: Saves traceroute results to `traceroute_results.txt` if enabled.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
