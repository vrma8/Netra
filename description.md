# Netspecs

NetSpecs is a high-performance network reconnaissance and packet analysis tool that combines the core capabilities of Nmap and Wireshark into a unified cybersecurity application.

It is designed to discover devices and services on a network while also providing real-time visibility into network traffic. NetSpecs can perform host discovery, port scanning, service detection, packet capture, protocol analysis, traffic filtering, and network statistics.

## Planned Features

- Network interface discovery
- Host/device discovery using ARP, ICMP, etc.
- TCP/UDP port scanning
- Service and version detection
- Real-time packet capture
- Packet and protocol decoding
- TCP/UDP/DNS/HTTP/ARP analysis
- Packet filtering and search
- Connection/session tracking
- Network traffic statistics
- PCAP capture and analysis
- CLI-based interface initially, with scope for a GUI/web dashboard
- JSON/CSV output for scan results

## Tech Stack

- Language       : C++
- Packet Capture : Npcap / libpcap
- Networking     : Boost.Asio
- Packet Parsing : PcapPlusPlus
- Security       : OpenSSL
- Data           : SQLite / JSON
- Build System   : CMake

## Goal

Build a modular, high-performance network security tool that provides both active network reconnaissance and passive traffic analysis in a single application.
