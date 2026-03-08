# DPI Engine - Deep Packet Inspection Tool

A high-performance **Deep Packet Inspection (DPI) Engine** written in Python for network traffic analysis and filtering. Originally ported from C++, this project demonstrates advanced networking concepts, multi-threaded architecture, and real-world network security applications.

---

## 🚀 Project Overview

This DPI Engine is a network analysis tool that:
- **Reads PCAP files** (packet captures from Wireshark/tcpdump)
- **Parses network packets** at multiple layers (Ethernet, IP, TCP, UDP)
- **Extracts SNI** (Server Name Indication) from TLS/HTTPS connections
- **Classifies applications** by analyzing network traffic patterns
- **Blocks traffic** based on configurable rules (IP, app, domain)
- **Supports multi-threading** for high-throughput processing

---

## 🎯 Key Features

| Feature | Description |
|---------|-------------|
| **Packet Parsing** | Complete parsing of Ethernet, IPv4, TCP, UDP headers |
| **SNI Extraction** | Extract domain names from TLS Client Hello packets |
| **App Classification** | Identify 20+ applications (YouTube, Facebook, Netflix, etc.) |
| **Traffic Blocking** | Block by IP, application type, or domain name |
| **Multi-threaded** | Parallel processing with load balancing |
| **Flow Tracking** | Maintain connection state for Stateful inspection |
| **Report Generation** | Detailed statistics and classification reports |

---

## 🏗️ Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│    PCAP     │     │   Parser    │     │   DPI       │
│   Reader    │ ──► │   Layer     │ ──► │   Engine    │
└─────────────┘     └─────────────┘     └──────┬──────┘
                                              │
                    ┌──────────────────────────┼──────────────────────────┐
                    │                          │                          │
                    ▼                          ▼                          ▼
           ┌────────────────┬┌────────────────┬┌────────────────┐
           │  Application   ││  Rule         ││  Connection   │
           │  Classifier    ││  Manager      ││  Tracker      │
           │  (SNI→App)     ││  (Blocking)   ││  (Flow State) │
           └────────────────┴┴────────────────┴┴────────────────┘
                                              │
                                              ▼
                                   ┌─────────────────────┐
                                   │   Output PCAP       │
                                   │   (Filtered Traffic)│
                                   └─────────────────────┘
```

---

## 📁 File Structure

```
python_language/
├── main.py                 # CLI entry point
├── pcap_reader.py          # PCAP file reader
├── packet_parser.py        # Network protocol parser
├── dpi_engine.py           # Main engine orchestrator
├── dpi_types.py            # Data types & structures
├── sni_extractor.py        # SNI extraction from TLS
├── rule_manager.py         # Blocking rules manager
├── connection_tracker.py   # Connection flow tracking
├── thread_safe_queue.py    # Thread-safe queue
├── load_balancer.py        # Load balancer
└── output/                 # Output files directory
```

---

## 🛠️ How to Run

### Prerequisites
- Python 3.7+
- No external dependencies (pure Python!)

### Basic Usage

```bash
# Analyze a PCAP file
python main.py analyze capture.pcap

# Run DPI analysis with output
python main.py dpi input.pcap -o output.pcap

# Block specific applications
python main.py dpi input.pcap -o output.pcap --block youtube --block facebook

# Block by IP address
python main.py dpi input.pcap -o output.pcap --block-ip 192.168.1.50

# Limit packets displayed
python main.py analyze capture.pcap 10
```

### Generate Test Data
```bash
python generate_test_pcap.py
```

---

## 💻 Technical Highlights

### 1. Network Protocol Parsing
- Manual parsing of raw bytes into structured data
- Understanding of network layers (OSI model)
- Handling network byte order (big-endian)

### 2. Deep Packet Inspection
- TLS Client Hello parsing to extract SNI
- HTTP Host header extraction
- DNS query domain extraction

### 3. Application Identification
- Pattern matching on SNI strings
- Domain-to-application mapping
- Support for 20+ popular applications

### 4. Multi-threaded Architecture
- Reader → Load Balancer → Fast Path pipeline
- Thread-safe queues for inter-thread communication
- Consistent hashing for connection affinity

### 5. Flow-based Tracking
- Five-tuple identification (srcIP, dstIP, srcPort, dstPort, protocol)
- Connection state machine (NEW → ESTABLISHED → CLASSIFIED → CLOSED)
- Timeout-based cleanup

---

## 📊 Sample Output

```
====================================
DPI Engine v1.0 (Python)
====================================

Processing: test_dpi.pcap
Output to:   output.pcap

====================================
Summary:
  Total packets read:  77
  Parse errors:        0
====================================

====================================Classification Report
====================================
  HTTPS: 39
  Unknown: 16
  YouTube: 4
  DNS: 4
  Facebook: 3
  GitHub: 2
  Google: 2
  Netflix: 1
  ...
```

---

## 🎓 What I Learned

This project demonstrates expertise in:

| Area | Skills Demonstrated |
|------|---------------------|
| **Networking** | TCP/IP, TLS/HTTPS, DNS protocols |
| **Python** | OOP, threading, data structures, file I/O |
| **System Programming** | Multi-threading, thread-safe data structures |
| **Security** | DPI concepts, traffic filtering |
| **Software Engineering** | Code organization, documentation, CLI design |

---

## 🔧 Potential Improvements

- [ ] Add HTTP/HTTPS header analysis
- [ ] Implement QUIC/HTTP3 support
- [ ] Add bandwidth throttling
- [ ] Real-time dashboard
- [ ] PCAPNG format support
- [ ] IPv6 support

---

## 📝 License

This project is for educational purposes.

---



