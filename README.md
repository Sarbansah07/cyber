# Network Traffic Analyzer

A medium-level cybersecurity project that analyzes network traffic and detects potential security threats in real-time.

## Features

- Real-time network packet capture and analysis
- Detection of port scanning attempts
- Identification of suspicious TCP flags
- Traffic visualization and reporting
- Protocol distribution analysis
- Suspicious IP tracking

## Prerequisites

- Python 3.7 or higher
- Administrator/root privileges (required for packet capture)
- Network interface with promiscuous mode support

## Installation

1. Clone this repository or download the files
2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Run the script with administrator/root privileges:
```bash
# On Windows (Run PowerShell as Administrator):
python network_analyzer.py

# On Linux/Mac:
sudo python3 network_analyzer.py
```

2. The script will start capturing network traffic and analyzing it in real-time
3. Press Ctrl+C to stop the capture and generate a report
4. The analysis report will be displayed in the console
5. A traffic visualization will be saved as 'traffic_analysis.png'

## Security Features

- Port Scan Detection: Monitors for rapid port scanning attempts
- Suspicious Flag Detection: Identifies potentially malicious TCP flag combinations
- Traffic Pattern Analysis: Visualizes network traffic patterns
- Protocol Analysis: Tracks and categorizes different network protocols

## Note

This tool is for educational and testing purposes only. Always ensure you have permission to monitor network traffic in your environment.

## License

This project is open source and available under the MIT License. #   c y b e r  
 