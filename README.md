# CodeAlpha Network Sniffer

A basic Python network sniffer built using Scapy. This tool captures live network 
traffic and displays source/destination IPs, protocols (TCP/UDP), ports, and payloads.

## Features
- Real-time packet capture
- Protocol detection (TCP/UDP/Other)
- Source & destination IP and port display
- Payload extraction
- Color-coded terminal output
- Logging to sniffer_log.txt
- Summary report at the end (total packets by protocol)

## Requirements
- Python 3
- Scapy (`pip install scapy`)

## Usage
```bash
sudo python3 sniffer.py
```

## Sample Output
[12:53:39] [TCP] 10.0.2.15:49504 -> 140.248.129.91:80
[12:53:39] [UDP] 10.0.2.15:35920 -> 10.138.134.34:53

--- Summary ---
TCP packets: 1
UDP packets: 16
Other packets: 0
Total: 17


## Author
Talha Abid

Ye add karke commit kar do, phir repo submission ke liye ready hoga. File structure verify karke batao agar sniffer.py andar nahi dikh raha to hum wo bhi fix kar denge.
