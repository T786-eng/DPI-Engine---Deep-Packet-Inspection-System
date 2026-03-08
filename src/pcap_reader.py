#!/usr/bin/env python3


import struct
from dataclasses import dataclass
from typing import List, Optional


# ============================================================================
# PCAP Structures
# ============================================================================

# PCAP Magic Numbers
PCAP_MAGIC_NATIVE = 0xa1b2c3d4  # Native byte order
PCAP_MAGIC_SWAPPED = 0xd4c3b2a1  # Swapped byte order


@dataclass
class PcapGlobalHeader:
    """PCAP Global Header (24 bytes)."""
    magic_number: int
    version_major: int
    version_minor: int
    thiszone: int
    sigfigs: int
    snaplen: int
    network: int


@dataclass
class PcapPacketHeader:
    """PCAP Packet Header (16 bytes)."""
    ts_sec: int      # Timestamp seconds
    ts_usec: int     # Timestamp microseconds
    incl_len: int    # Number of bytes saved in file
    orig_len: int    # Actual length of packet


@dataclass
class RawPacket:
    """Represents a single captured packet."""
    header: PcapPacketHeader
    data: bytes


# ============================================================================
# PCAP Reader Class
# ============================================================================

class PcapReader:
    """Class to read PCAP files."""
    
    def __init__(self):
        self.file = None
        self.global_header = None
        self.needs_byte_swap = False
        self.filename = ""
    
    def open(self, filename: str) -> bool:
        """Open a pcap file for reading."""
        self.close()
        
        try:
            self.file = open(filename, 'rb')
            self.filename = filename
        except IOError as e:
            print(f"Error: Could not open file: {filename} - {e}")
            return False
        
        # Read the global header (first 24 bytes)
        header_data = self.file.read(24)
        if len(header_data) < 24:
            print("Error: Could not read PCAP global header")
            self.close()
            return False
        
        # Parse global header
        self.global_header = self._parse_global_header(header_data)
        if self.global_header is None:
            self.close()
            return False
        
        # Check the magic number to determine byte order
        if self.global_header.magic_number == PCAP_MAGIC_NATIVE:
            self.needs_byte_swap = False
        elif self.global_header.magic_number == PCAP_MAGIC_SWAPPED:
            self.needs_byte_swap = True
        else:
            print(f"Error: Invalid PCAP magic number: 0x{self.global_header.magic_number:08x}")
            self.close()
            return False
        
        print(f"Opened PCAP file: {filename}")
        print(f"  Version: {self.global_header.version_major}.{self.global_header.version_minor}")
        print(f"  Snaplen: {self.global_header.snaplen} bytes")
        link_type = "Ethernet" if self.global_header.network == 1 else str(self.global_header.network)
        print(f"  Link type: {link_type}")
        
        return True
    
    def _parse_global_header(self, data: bytes) -> Optional[PcapGlobalHeader]:
        """Parse the global header."""
        if len(data) < 24:
            return None
        
        # Try native format first
        try:
            magic, v_major, v_minor, zone, sigfigs, snaplen, network = struct.unpack('<IHHIIII', data)
            return PcapGlobalHeader(magic, v_major, v_minor, zone, sigfigs, snaplen, network)
        except struct.error:
            pass
        
        # Try swapped format
        try:
            magic, v_major, v_minor, zone, sigfigs, snaplen, network = struct.unpack('>IHHIIII', data)
            return PcapGlobalHeader(magic, v_major, v_minor, zone, sigfigs, snaplen, network)
        except struct.error:
            pass
        
        return None
    
    def close(self):
        """Close the file."""
        if self.file:
            self.file.close()
            self.file = None
        self.needs_byte_swap = False
    
    def is_open(self) -> bool:
        """Check if file is open."""
        return self.file is not None
    
    def needs_byte_swap(self) -> bool:
        """Check if we need to swap byte order."""
        return self.needs_byte_swap
    
    def read_next_packet(self) -> Optional[RawPacket]:
        """Read the next packet, returns None if no more packets."""
        if not self.file:
            return None
        
        # Read the packet header (16 bytes)
        header_data = self.file.read(16)
        if len(header_data) < 16:
            # End of file or error
            return None
        
        # Parse packet header
        packet_header = self._parse_packet_header(header_data)
        if packet_header is None:
            return None
        
        # Read the packet data
        packet_data = self.file.read(packet_header.incl_len)
        if len(packet_data) < packet_header.incl_len:
            print("Error: Could not read packet data")
            return None
        
        return RawPacket(packet_header, packet_data)
    
    def _parse_packet_header(self, data: bytes) -> Optional[PcapPacketHeader]:
        """Parse packet header."""
        if len(data) < 16:
            return None
        
        try:
            if self.needs_byte_swap:
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack('>IIII', data)
            else:
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', data)
            
            return PcapPacketHeader(ts_sec, ts_usec, incl_len, orig_len)
        except struct.error:
            return None
    
    def get_global_header(self) -> Optional[PcapGlobalHeader]:
        """Get the global header info."""
        return self.global_header
    
    def __iter__(self):
        """Iterator support."""
        return self
    
    def __next__(self) -> Optional[RawPacket]:
        """Next packet for iteration."""
        packet = self.read_next_packet()
        if packet is None:
            raise StopIteration
        return packet
    
    def __del__(self):
        """Cleanup."""
        self.close()

