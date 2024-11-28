# Packet Sniffer Tool by Sayantan Saha

![Logo](https://github.com/MasterSayantan/Network-Packet-Sniffer/blob/main/Screenshot%202024-11-28%20214235.png)  
A Python-based packet sniffer tool designed for Linux systems, offering real-time network traffic capture and analysis. This tool works exclusively in CLI mode and requires **root permissions** to operate effectively.

---

## Features

- **CLI-Based Tool**: Lightweight and designed for command-line usage.
- **Packet Sniffing**: Captures real-time network traffic on a selected interface.
- **Protocol Analysis**: Supports analysis of IP, TCP, UDP, and ICMP layers.
- **Network Details**: Displays system network information, including IP and MAC addresses.
- **Formatted Output**: Uses colored and tabulated text for clear packet details.

---

## How It Works

1. **Logo and Branding**: Displays a custom logo with branding details.
2. **Network Interface Table**: Lists active network interfaces with their IP and MAC addresses.
3. **Packet Capture**: Sniffs and displays detailed packet data for user-selected interfaces.
4. **Packet Analysis**:
   - **IP Layer**: Shows source/destination IP, TTL, protocol, and flags.
   - **TCP Layer**: Displays source/destination ports, sequence number, and flags.
   - **UDP Layer**: Displays source/destination ports.
   - **ICMP Layer**: Displays type and code.

5. **User Input**: Interactive interface selection.
6. **Root Permission Requirement**: Requires elevated privileges for packet sniffing.

---

## System Requirements

- **Operating System**: Linux-based distributions.
- **Permission**: Must be run as **root** or with **sudo** privileges.

---

## Required Modules

The following Python modules are necessary:

| Module        | Purpose                                         | Installation Command              |
|---------------|-------------------------------------------------|-----------------------------------|
| `scapy`       | Packet sniffing and network analysis.           | `pip install scapy`               |
| `psutil`      | Fetching system and network interface details.  | `pip install psutil`              |
| `prettytable` | Formatting data into tables.                    | `pip install prettytable`         |
| `colorama`    | Adding color to terminal output.                | `pip install colorama`            |

Built-in modules:  
- `subprocess`, `re`, `time` (no installation needed).

---

## Installation and Setup

1. **Clone the Repository**
   ```bash
   git clone https://github.com/MasterSayantan/PacketSnifferTool.git
   cd PacketSnifferTool
   pip install -r requirements.txt
   sudo python Packet Sniffer.py
   ```
