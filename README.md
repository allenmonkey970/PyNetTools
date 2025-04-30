# PyNetTools

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.6+-green.svg)
![Last Updated](https://img.shields.io/badge/last%20updated-2025--04--30-brightgreen)

A comprehensive network analysis and diagnostics toolkit built with Python. PyNetTools offers a suite of networking utilities including ping, traceroute, port scanning, OS detection, ping sweeping, and speed testing with both command-line and interactive interfaces.

<img src="https://github.com/allenmonkey970/pynettools/blob/main/pynettools.png" alt="PyNetTools Banner" width="600" height="400"/>

## 🚀 Features

- 📊 **Internet Speed Testing** - Measure your download/upload speeds and ping latency
- 📡 **Ping & Traceroute** - Test connectivity and trace network paths with visualizations
- 🔍 **Ping Sweep** - Discover active hosts on a network subnet
- 🔒 **Port Scanning** - Identify open ports and services on target hosts
- 💻 **OS Detection** - Determine the operating system of remote hosts
- 📋 **Logging & Reporting** - Save all results to organized files for analysis

## 📋 Requirements

- Python 3.6 or higher
- Root/Administrator privileges (for some features)

## ⚙️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/allenmonkey970/pynettools.git
   cd pynettools
   ```

2. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

## 🛠️ Usage

### Interactive Mode

Run the tool without any arguments to use the interactive menu:

```bash
python network_tool.py
```

This will present a menu with all available options:
```
Network Tool Menu:
1. Perform Speed Test
2. Ping a Target
3. Traceroute to a Target
4. Ping Sweep
5. Port Scan
6. OS Scan
7. Exit
```

### Command Line Usage

#### Speed Test
```bash
python network_tool.py speedtest
```

#### Ping a Target
```bash
python network_tool.py ping example.com -c 5 -t 2
```
- `-c, --count`: Number of packets to send (default: 4)
- `-t, --timeout`: Timeout in seconds for each packet (default: 1)

#### Traceroute
```bash
python network_tool.py traceroute example.com -m 30 -t 1 -s
```
- `-m, --max-hops`: Maximum hops (default: 30)
- `-t, --timeout`: Timeout in seconds for each probe (default: 1)
- `-s, --save`: Save results to file

#### Ping Sweep
```bash
python network_tool.py sweep 192.168.1.0/24 -t 1 --threads 20
```
- `-t, --timeout`: Timeout in seconds (default: 1)
- `--threads`: Number of threads (default: 10)

#### Port Scan
```bash
python network_tool.py portscan example.com -p 1-1024
```
- `-p, --ports`: Port range (e.g., 1-1024 or 22,80,443)

#### OS Scan
```bash
python network_tool.py osscan example.com
```

## ⚙️ Configuration

You can customize default settings by creating a `config.json` file in the root directory:

```json
{
  "timeout": 1,
  "max_hops": 30,
  "threads": 10,
  "default_ports": "1-1024"
}
```

## 📁 Results

All results are saved in the `results` directory:
- Speed test results: `speedtest_results.json`
- Traceroute results: `traceroute_[target].txt`
- Ping sweep results: `ping_sweep_[subnet].txt`
- Port scan results: `portscan_[target].txt`
- OS scan results: `osscan_[target].txt`
- Log file: `network_tool.log`

## ⚠️ Disclaimer

This tool is for network diagnostics and educational purposes only. Always ensure you have proper authorization before scanning networks that you don't own or have explicit permission to test.

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👨‍💻 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/allenmonkey970/pynettools/issues).

1. Fork the project
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
