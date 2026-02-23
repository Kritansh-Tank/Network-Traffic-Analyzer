# Network Traffic Analyzer

A powerful Python-based network traffic analyzer that captures and analyzes network packets, providing detailed insights about network usage, protocols, and potential security issues.

## Features

- Real-time packet capture and analysis
- Protocol distribution visualization
- Traffic volume monitoring
- Connection tracking
- Basic anomaly detection and security alerts
- Statistical analysis of network traffic
- Comprehensive dashboards and visualizations
- Data export for further analysis

## Requirements

- Python 3.8+
- Administrative/root privileges (required for packet sniffing)
- Libraries listed in requirements.txt:
  - scapy: For packet capturing and inspection
  - matplotlib: For visualization
  - pandas: For data manipulation and export
  - psutil: For system and network interface information
  - colorama: For colorized terminal output

## Installation

1. Clone this repository or download the files
2. Install the requirements:
   ```
   pip install -r requirements.txt
   ```
3. Ensure you have the necessary permissions to capture network traffic

## Usage

### Basic Usage

Run the main analyzer with:
```
python network_analyzer.py
```

This will start capturing packets in real-time until you press Ctrl+C.

### Running with Admin Privileges

#### Windows:
Run Command Prompt or PowerShell as Administrator, then run:
```
python network_analyzer.py
```

#### Linux/macOS:
```
sudo python3 network_analyzer.py
```

### Common Options

```
python network_analyzer.py --list-interfaces    # List available network interfaces
python network_analyzer.py --interface eth0     # Specify network interface
python network_analyzer.py --time 60            # Capture for 60 seconds
python network_analyzer.py --count 1000         # Capture 1000 packets
python network_analyzer.py --filter "tcp"       # Only capture TCP packets
python network_analyzer.py --filter "port 80"   # Only capture HTTP traffic
python network_analyzer.py --export csv         # Export results to CSV
python network_analyzer.py --output report.csv  # Specify output filename
```

### Visualization Options

```
python network_analyzer.py --visualize          # Generate detailed visualizations
python network_analyzer.py --dashboard          # Create a traffic dashboard
```

### Complete Example

```
python network_analyzer.py --interface "Wi-Fi" --time 120 --filter "tcp" --visualize
```
This will:
- Capture traffic on the Wi-Fi interface
- Run for 120 seconds
- Only capture TCP traffic
- Generate visualizations

## Modules

- `network_analyzer.py`: Main application that coordinates all components
- `packet_capture.py`: Handles packet capture functionality using Scapy
- `packet_analyzer.py`: Analyzes captured packets and extracts statistics
- `visualizer.py`: Creates visual representations of network data
- `utils.py`: Utility functions for file operations, formatting, etc.

## Output

The analyzer provides several types of output:

1. **Real-time statistics** displayed during capture
2. **Summary report** after capture completion, including:
   - Packet counts
   - Data volume
   - Protocol distribution
   - Top source/destination IP addresses
   - Top ports
   - Potential security concerns

3. **Visualizations** (when using `--visualize`):
   - Protocol distribution
   - Traffic over time
   - Top talkers
   - Connection statistics

4. **Data export** (when using `--export`):
   - Connection details
   - Traffic statistics
   - Protocol information

## Troubleshooting

### No Packets Captured

If you run the analyzer but no packets are captured:

1. **Check Permissions**: Make sure you're running as Administrator (Windows) or with sudo (Linux/macOS)
2. **Specify Interface**: Use `--list-interfaces` to see available interfaces, then specify one with `--interface`
3. **Check Network Activity**: Make sure there's active network traffic during capture
4. **Firewall Settings**: Your firewall might be blocking packet capture
5. **Try Different Interface**: If one interface isn't working, try another
6. **Longer Capture**: Use `--time` to set a longer capture duration

### Visualization Errors

If you encounter errors when generating visualizations:

1. **Check Dependencies**: Make sure matplotlib and pandas are properly installed
2. **File Permissions**: Ensure the program has permission to write files to the output directory
3. **Minimal Data**: Capture more packets before visualizing

## Security and Ethics

- This tool should only be used on networks you own or have explicit permission to monitor
- Network monitoring may be subject to legal restrictions in your jurisdiction
- Never use this tool for unauthorized network surveillance or any malicious purpose
- The tool can detect basic security issues but is not a replacement for dedicated security software

## Notes

- This tool requires administrator/root privileges to capture packets
- Performance may vary depending on network traffic volume
- For high-volume networks, consider using the `--count` or `--time` options to limit capture

- Use responsibly and only on networks you have permission to monitor

## License

Apache-2.0 License - See LICENSE file for details
