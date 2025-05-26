# Wi-Fi Security Assessment Tool

This is a Python script designed to help you conduct a basic security assessment of your home Wi-Fi network. It includes features for:

- Checking for weak Wi-Fi passwords (placeholder function)
- Scanning open ports on your router
- Detecting unauthorized devices connected to your network

## Features

1. **Weak Password Check (Placeholder)**  
   This function simulates testing a list of common weak passwords against your Wi-Fi SSID. It is a placeholder — real password testing requires specialized tools like `aircrack-ng` and is not implemented here.

2. **Open Port Scanning**  
   Uses the `nmap` Python library to perform a SYN port scan on your router's IP address to identify open ports that may be vulnerable.

3. **Unauthorized Device Detection**  
   Performs an ARP scan of your local network subnet using `scapy` to identify all connected devices and flags any that are not in your list of known devices.

## Prerequisites

- Python 3
- Administrative or root privileges to run network scans
- Install required Python packages:
  ```bash
  pip install scapy nmap
