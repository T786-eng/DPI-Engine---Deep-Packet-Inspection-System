#!/usr/bin/env python3


import struct
from dataclasses import dataclass
from typing import Optional
from dpi_types import (
    FiveTuple, ip_str_to_int, ip_int_to_str,
    Protocol, EtherType, TCPFlags
)


# ============================================================================
# Parsed Packet Structure
# ============================================================================

@dataclass
class ParsedPacket:
    """Parsed packet information - human-readable format."""
    # Timestamps
    timestamp_sec: int = 0
    timestamp_usec: int = 0
    
    # Ethernet layer
    src_mac: str = ""
    dest_mac: str = ""
    ether_type: int = 0
    
    # IP layer (if present)
    has_ip: bool = False
    ip_version: int = 0
    src_ip: str = ""
    dest_ip: str = ""
    protocol: int = 0
    ttl: int = 0
    
    # Transport layer (if present)
    has_tcp: bool = False
    has_udp: bool = False
    src_port: int = 0
    dest_port: int = 0
    
    # TCP-specific
    tcp_flags: int = 0
    seq_number: int = 0
    ack_number: int = 0
    
    # Payload
    payload_length: int = 0
    payload_data: Optional[bytes] = None


# ============================================================================
# Packet Parser Class
# ============================================================================

class PacketParser:
    """Class to parse raw packets."""
    
    @staticmethod
    def parse(raw) -> ParsedPacket:
        """Parse a raw packet and fill in the ParsedPacket structure."""
        parsed = ParsedPacket()
        
        # Get timestamp from pcap header
        if hasattr(raw, 'header'):
            parsed.timestamp_sec = raw.header.ts_sec
            parsed.timestamp_usec = raw.header.ts_usec
        
        data = raw.data if isinstance(raw, bytes) else (raw.data if hasattr(raw, 'data') else raw)
        length = len(data)
        offset = 0
        
        # Parse Ethernet header first
        if not PacketParser._parse_ethernet(data, length, parsed, offset):
            return parsed
        
        offset = 14  # Ethernet header is 14 bytes
        
        # Parse IP layer if it's an IPv4 packet
        if parsed.ether_type == EtherType.IPv4:
            if not PacketParser._parse_ipv4(data, length, parsed, offset):
                return parsed
            
            # Update offset based on actual IP header length (IHL field, not version)
            # Get IHL from the IP header first byte (lower 4 bits)
            if length > offset:
                ip_first_byte = data[offset]
                ihl = ip_first_byte & 0x0F  # IHL in 32-bit words
                ip_header_len = ihl * 4
            else:
                ip_header_len = 20  # Default
            
            offset += ip_header_len
            
            # Parse transport layer based on protocol
            if parsed.protocol == Protocol.TCP:
                if not PacketParser._parse_tcp(data, length, parsed, offset):
                    return parsed
                # Update offset based on TCP header length (data offset field)
                # The data offset is stored in ParsedPacket after _parse_tcp
                tcp_header_len = parsed._tcp_data_offset * 4 if hasattr(parsed, '_tcp_data_offset') and parsed._tcp_data_offset else 20
                offset += tcp_header_len
            elif parsed.protocol == Protocol.UDP:
                if not PacketParser._parse_udp(data, length, parsed, offset):
                    return parsed
                offset += 8  # UDP header is always 8 bytes
        
        # Set payload information
        if offset < length:
            parsed.payload_length = length - offset
            parsed.payload_data = data[offset:]
        
        return parsed
    
    @staticmethod
    def _parse_ethernet(data: bytes, length: int, parsed: ParsedPacket, offset: int) -> bool:
        """Parse Ethernet header."""
        if length < offset + 14:
            return False
        
        # Parse destination MAC (bytes 0-5)
        parsed.dest_mac = PacketParser._mac_to_string(data[0:6])
        
        # Parse source MAC (bytes 6-11)
        parsed.src_mac = PacketParser._mac_to_string(data[6:12])
        
        # Parse EtherType (bytes 12-13, big-endian)
        parsed.ether_type = struct.unpack('>H', data[12:14])[0]
        
        return True
    
    @staticmethod
    def _parse_ipv4(data: bytes, length: int, parsed: ParsedPacket, offset: int) -> bool:
        """Parse IPv4 header."""
        if length < offset + 20:
            return False
        
        ip_data = data[offset:]
        
        # First byte: version (4 bits) + IHL (4 bits)
        version_ihl = ip_data[0]
        parsed.ip_version = (version_ihl >> 4) & 0x0F
        ihl = version_ihl & 0x0F  # Header length in 32-bit words
        
        if parsed.ip_version != 4:
            return False  # Not IPv4
        
        ip_header_len = ihl * 4  # Convert to bytes (should be 20 for standard IP header)
        if ip_header_len < 20 or length < offset + ip_header_len:
            return False
        
        # Parse fields
        parsed.ttl = ip_data[8]
        parsed.protocol = ip_data[9]
        
        # Source IP (bytes 12-15)
        src_ip = struct.unpack('>I', ip_data[12:16])[0]
        parsed.src_ip = ip_int_to_str(src_ip)
        
        # Destination IP (bytes 16-19)
        dst_ip = struct.unpack('>I', ip_data[16:20])[0]
        parsed.dest_ip = ip_int_to_str(dst_ip)
        
        parsed.has_ip = True
        
        # Store IHL for later use in calculating transport layer offset
        parsed._ip_header_len = ip_header_len
        
        return True
    
    @staticmethod
    def _parse_tcp(data: bytes, length: int, parsed: ParsedPacket, offset: int) -> bool:
        """Parse TCP header."""
        if length < offset + 20:
            return False
        
        tcp_data = data[offset:]
        
        # Source port (bytes 0-1)
        parsed.src_port = struct.unpack('>H', tcp_data[0:2])[0]
        
        # Destination port (bytes 2-3)
        parsed.dest_port = struct.unpack('>H', tcp_data[2:4])[0]
        
        # Sequence number (bytes 4-7)
        parsed.seq_number = struct.unpack('>I', tcp_data[4:8])[0]
        
        # Acknowledgment number (bytes 8-11)
        parsed.ack_number = struct.unpack('>I', tcp_data[8:12])[0]
        
        # Data offset (upper 4 bits of byte 12) - header length in 32-bit words
        data_offset = (tcp_data[12] >> 4) & 0x0F
        
        # Flags (byte 13)
        parsed.tcp_flags = tcp_data[13]
        
        # Store data offset for later use
        parsed._tcp_data_offset = data_offset
        
        tcp_header_len = data_offset * 4
        if tcp_header_len < 20 or length < offset + tcp_header_len:
            return False
        
        parsed.has_tcp = True
        
        return True
    
    @staticmethod
    def _parse_udp(data: bytes, length: int, parsed: ParsedPacket, offset: int) -> bool:
        """Parse UDP header."""
        if length < offset + 8:
            return False
        
        udp_data = data[offset:]
        
        # Source port (bytes 0-1)
        parsed.src_port = struct.unpack('>H', udp_data[0:2])[0]
        
        # Destination port (bytes 2-3)
        parsed.dest_port = struct.unpack('>H', udp_data[2:4])[0]
        
        parsed.has_udp = True
        
        return True
    
    # =========================================================================
    # Helper Functions
    # =========================================================================
    
    @staticmethod
    def _mac_to_string(mac: bytes) -> str:
        """Convert MAC address bytes to string."""
        return ':'.join(f'{b:02x}' for b in mac)
    
    @staticmethod
    def mac_to_string(mac) -> str:
        """Convert MAC address bytes to string (public interface)."""
        if isinstance(mac, bytes):
            return PacketParser._mac_to_string(mac)
        return str(mac)
    
    @staticmethod
    def ip_to_string(ip: int) -> str:
        """Convert IP integer to string."""
        return ip_int_to_str(ip)
    
    @staticmethod
    def protocol_to_string(protocol: int) -> str:
        """Convert protocol number to string."""
        if protocol == Protocol.ICMP:
            return "ICMP"
        elif protocol == Protocol.TCP:
            return "TCP"
        elif protocol == Protocol.UDP:
            return "UDP"
        else:
            return f"Unknown({protocol})"
    
    @staticmethod
    def tcp_flags_to_string(flags: int) -> str:
        """Convert TCP flags to string."""
        result = []
        if flags & TCPFlags.SYN:
            result.append("SYN")
        if flags & TCPFlags.ACK:
            result.append("ACK")
        if flags & TCPFlags.FIN:
            result.append("FIN")
        if flags & TCPFlags.RST:
            result.append("RST")
        if flags & TCPFlags.PSH:
            result.append("PSH")
        if flags & TCPFlags.URG:
            result.append("URG")
        
        if not result:
            return "none"
        return " ".join(result)
    
    @staticmethod
    def create_five_tuple(parsed: ParsedPacket) -> Optional[FiveTuple]:
        """Create a FiveTuple from a parsed packet."""
        if not parsed.has_ip:
            return None
        
        return FiveTuple(
            src_ip=ip_str_to_int(parsed.src_ip),
            dst_ip=ip_str_to_int(parsed.dest_ip),
            src_port=parsed.src_port,
            dst_port=parsed.dest_port,
            protocol=parsed.protocol
        )

