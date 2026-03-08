## Information Gathered

### Project Overview
This is a **Deep Packet Inspection (DPI) Engine** - a network analysis tool that:
- Reads PCAP (packet capture) files
- Parses network packets (Ethernet, IP, TCP, UDP)
- Extracts SNI (Server Name Indication) from TLS/HTTPS connections
- Classifies applications (YouTube, Facebook, Netflix, etc.)
- Can block traffic based on rules (IP, app, domain)
- Supports multi-threaded processing for high performance

### Python Files (10 files)
1. `main.py` - Main entry point with CLI
2. `pcap_reader.py` - PCAP file reader (207 lines)
3. `packet_parser.py` - Network protocol parser (237 lines)
4. `dpi_engine.py` - Main DPI engine orchestrator (456 lines)
5. `dpi_types.py` - Data types and structures (220 lines)
6. `sni_extractor.py` - SNI extraction from TLS (280 lines)
7. `rule_manager.py` - Blocking rules management (280 lines)
8. `connection_tracker.py` - Connection flow tracking
9. `thread_safe_queue.py` - Thread-safe queue implementation
10. `load_balancer.py` - Load balancer for multi-threading

### Documentation Files Found
1. `README.md` - Comprehensive technical documentation
2. `WINDOWS_SETUP.md` - Windows setup guide

