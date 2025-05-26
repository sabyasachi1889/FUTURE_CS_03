#!/usr/bin/env python3

"""
Wi-Fi Security Assessment Script

This script performs these tasks:
1. Checks for weak passwords (placeholder implementation).
2. Scans for open ports on the router.
3. Scans the network for unauthorized devices.

Prerequisites:
- Run this script with administrative rights.
- Install dependencies:
    pip install scapy nmap

Usage:
- Update SSID, password list, and router IP before running.
- Run: sudo python3 wifi_security_assessment.py
"""

import subprocess
import nmap
import scapy.all as scapy
import sys

def check_weak_passwords(ssid, password_list):
    """
    Placeholder for weak password checking.
    Real password testing requires external tools (like aircrack-ng) and is complex.
    """
    print(f"\n[+] Checking for weak passwords on SSID: {ssid}")
    print("NOTE: This is a placeholder function. Real password cracking is not implemented.")
    for password in password_list:
        print(f"  - Would test password: '{password}' (no actual test performed)")

def scan_open_ports(ip):
    """
    Scans open ports on the provided IP using nmap SYN scan.
    """
    print(f"\n[+] Scanning open ports on {ip}...")
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments='-sS -Pn')
    except Exception as e:
        print(f"Error scanning ports on {ip}: {e}")
        return

    if ip not in nm.all_hosts():
        print(f"No hosts found for IP {ip}. Is the IP correct?")
        return

    for proto in nm[ip].all_protocols():
        lport = nm[ip][proto].keys()
        for port in sorted(lport):
            state = nm[ip][proto][port]['state']
            print(f"  Port {port}/{proto} is {state}")

def find_unauthorized_devices(subnet, known_devices=None):
    """
    Performs an ARP scan on the subnet to find connected devices.
    Optionally, compare found devices to a known list to identify unauthorized devices.
    """
    if known_devices is None:
        known_devices = {}

    print(f"\n[+] Scanning for devices on the network (subnet: {subnet})...")
    arp_request = scapy.ARP(pdst=subnet)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast / arp_request

    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    devices = []
    print("Devices found on the network:")
    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc
        devices.append((ip, mac))
        status = "KNOWN" if mac in known_devices.values() else "UNKNOWN"
        print(f"  IP: {ip} \t MAC: {mac} \t Status: {status}")

    unauthorized = [d for d in devices if d[1] not in known_devices.values()]
    if unauthorized:
        print("\n[!] Potential unauthorized devices detected:")
        for ip, mac in unauthorized:
            print(f"    - IP: {ip}, MAC: {mac}")
    else:
        print("\n[+] No unauthorized devices detected based on known devices list.")

def main():
    # User configuration - update these before running
    SSID = "Your_SSID"  # Your Wi-Fi network name
    ROUTER_IP = "192.168.1.1"  # Your router's IP address
    SUBNET = "192.168.1.0/24"  # Your local subnet for scanning. Adjust based on your network.
    WEAK_PASSWORDS = [
        "12345678",
        "password",
        "123456789",
        "qwerty",
        "abc123",
        "password1",
        "letmein",
        "admin123"
    ]
    # Known devices dict: device name -> MAC address, fill in your known devices' MACs
    KNOWN_DEVICES = {
        "your_phone": "AA:BB:CC:DD:EE:FF",
        "your_laptop": "11:22:33:44:55:66",
        # Add more known device MAC addresses here in uppercase format
    }

    print("\n===== Wi-Fi Security Assessment Started =====\n")

    check_weak_passwords(SSID, WEAK_PASSWORDS)
    scan_open_ports(ROUTER_IP)
    find_unauthorized_devices(SUBNET, KNOWN_DEVICES)

    print("\n===== Assessment Complete =====\n")

if __name__ == "__main__":
    if not hasattr(scapy, 'srp'):
        print("Scapy library is not installed or not functioning correctly.")
        sys.exit(1)
    main()

