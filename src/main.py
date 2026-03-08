#!/usr/bin/env python3


import sys
import argparse
from datetime import datetime

from pcap_reader import PcapReader
from packet_parser import PacketParser, ParsedPacket
from dpi_engine import DPIEngine, SimpleDPIEngine, DPIConfig


def print_packet_summary(parsed: ParsedPacket, packet_num: int):
    """Print a summary of a parsed packet."""
    print(f"\n========== Packet #{packet_num} ==========")
    
    # Format timestamp
    timestamp = datetime.fromtimestamp(parsed.timestamp_sec)
    print(f"Time: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}.{parsed.timestamp_usec:06d}")
    
    # Ethernet layer
    print(f"\n[Ethernet]")
    print(f"  Source MAC:      {parsed.src_mac}")
    print(f"  Destination MAC: {parsed.dest_mac}")
    print(f"  EtherType:       0x{parsed.ether_type:04x}", end="")
    
    if parsed.ether_type == 0x0800:
        print(" (IPv4)")
    elif parsed.ether_type == 0x86DD:
        print(" (IPv6)")
    elif parsed.ether_type == 0x0806:
        print(" (ARP)")
    else:
        print()
    
    # IP layer
    if parsed.has_ip:
        print(f"\n[IPv{parsed.ip_version}]")
        print(f"  Source IP:      {parsed.src_ip}")
        print(f"  Destination IP: {parsed.dest_ip}")
        print(f"  Protocol:       {PacketParser.protocol_to_string(parsed.protocol)}")
        print(f"  TTL:            {parsed.ttl}")
    
    # TCP layer
    if parsed.has_tcp:
        print(f"\n[TCP]")
        print(f"  Source Port:      {parsed.src_port}")
        print(f"  Destination Port: {parsed.dest_port}")
        print(f"  Sequence Number:  {parsed.seq_number}")
        print(f"  Ack Number:       {parsed.ack_number}")
        print(f"  Flags:            {PacketParser.tcp_flags_to_string(parsed.tcp_flags)}")
    
    # UDP layer
    if parsed.has_udp:
        print(f"\n[UDP]")
        print(f"  Source Port:      {parsed.src_port}")
        print(f"  Destination Port: {parsed.dest_port}")
    
    # Payload info
    if parsed.payload_length > 0:
        print(f"\n[Payload]")
        print(f"  Length: {parsed.payload_length} bytes")
        
        # Print first 32 bytes of payload as hex
        if parsed.payload_data:
            preview_len = min(parsed.payload_length, 32)
            print("  Preview: ", end="")
            for i in range(preview_len):
                print(f"{parsed.payload_data[i]:02x} ", end="")
            if parsed.payload_length > 32:
                print("...", end="")
            print()


def print_usage(program_name: str):
    """Print usage information."""
    print(f"""Usage: {program_name} <command> [options]

Commands:
  analyze    Analyze a PCAP file (packet parsing only)
  dpi        Run DPI analysis with blocking capabilities
  generate   Generate a test PCAP file
  
Examples:
  {program_name} analyze capture.pcap
  {program_name} analyze capture.pcap 10
  {program_name} dpi test_dpi.pcap -o output.pcap
  {program_name} dpi test_dpi.pcap --block facebook --block twitter
""")


def cmd_analyze(args):
    """Analyze a PCAP file - packet parsing only."""
    print("====================================")
    print("     Packet Analyzer v1.0 (Python)")
    print("====================================\n")
    
    filename = args.pcap_file
    max_packets = args.max_packets
    
    # Open the PCAP file
    reader = PcapReader()
    if not reader.open(filename):
        return 1
    
    print("\n--- Reading packets ---\n")
    
    # Read and parse packets
    packet_count = 0
    parse_errors = 0
    
    while True:
        raw_packet = reader.read_next_packet()
        if raw_packet is None:
            break
        
        packet_count += 1
        
        # Parse the packet
        parsed = PacketParser.parse(raw_packet)
        
        if parsed:
            print_packet_summary(parsed, packet_count)
        else:
            print(f"Warning: Failed to parse packet #{packet_count}")
            parse_errors += 1
        
        # Check if we've reached the limit
        if max_packets > 0 and packet_count >= max_packets:
            print(f"\n(Stopped after {max_packets} packets)")
            break
    
    # Summary
    print("\n====================================")
    print("Summary:")
    print(f"  Total packets read:  {packet_count}")
    print(f"  Parse errors:        {parse_errors}")
    print("====================================")
    
    reader.close()
    return 0


def cmd_dpi(args):
    """Run DPI analysis with blocking capabilities."""
    print("====================================")
    print("     DPI Engine v1.0 (Python)")
    print("====================================\n")
    
    # Create configuration
    config = DPIConfig(
        num_load_balancers=2,
        fps_per_lb=2,
        queue_size=10000,
        rules_file=args.rules if args.rules else "",
        verbose=args.verbose
    )
    
    # Create engine
    engine = SimpleDPIEngine()
    
    # Apply blocking rules from command line
    if args.block:
        for item in args.block:
            # Check if it's a known app name
            apps = ['facebook', 'twitter', 'instagram', 'youtube', 'netflix', 
                   'tiktok', 'whatsapp', 'telegram', 'discord', 'zoom',
                   'spotify', 'github', 'amazon', 'microsoft', 'apple']
            if item.lower() in apps:
                engine.block_app(item.lower())
            else:
                # Assume it's a domain
                engine.block_domain(item)
    
    # Apply IP blocking
    if args.block_ip:
        for ip in args.block_ip:
            engine.block_ip(ip)
    
    # Process the file
    output_file = args.output if args.output else None
    
    print(f"Processing: {args.pcap_file}")
    if output_file:
        print(f"Output to:   {output_file}")
    print()
    
    success = engine.process_file(args.pcap_file, output_file)
    
    if not success:
        print("Error: Failed to process file")
        return 1
    
    # Print reports
    print("\n" + engine.generate_report())
    print("\n" + engine.generate_classification_report())
    
    return 0


def cmd_generate(args):
    """Generate a test PCAP file."""
    # This functionality already exists in generate_test_pcap.py
    print("Use generate_test_pcap.py to generate test PCAP files")
    return 1


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Packet Analyzer / DPI Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze a PCAP file (packet parsing)')
    analyze_parser.add_argument('pcap_file', help='Path to PCAP file')
    analyze_parser.add_argument('max_packets', nargs='?', type=int, default=-1, 
                               help='Maximum number of packets to display')
    
    # DPI command
    dpi_parser = subparsers.add_parser('dpi', help='Run DPI analysis')
    dpi_parser.add_argument('pcap_file', help='Path to input PCAP file')
    dpi_parser.add_argument('-o', '--output', help='Path to output PCAP file')
    dpi_parser.add_argument('-b', '--block', action='append', help='Block application/domain')
    dpi_parser.add_argument('--block-ip', action='append', help='Block IP address')
    dpi_parser.add_argument('-r', '--rules', help='Rules file')
    dpi_parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    # Generate command
    gen_parser = subparsers.add_parser('generate', help='Generate test PCAP file')
    
    args = parser.parse_args()
    
    if args.command == 'analyze':
        return cmd_analyze(args)
    elif args.command == 'dpi':
        return cmd_dpi(args)
    elif args.command == 'generate':
        return cmd_generate(args)
    else:
        print_usage(sys.argv[0])
        return 1


if __name__ == '__main__':
    sys.exit(main())

