#!/usr/bin/env python3


import struct
import hashlib
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Dict, Set, List
from datetime import datetime


# ============================================================================
# Five-Tuple: Uniquely identifies a connection/flow
# ============================================================================
class FiveTuple:
    """Five-tuple that uniquely identifies a network connection."""
    
    def __init__(self, src_ip: int, dst_ip: int, src_port: int, dst_port: int, protocol: int):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol  # TCP=6, UDP=17
    
    def __eq__(self, other) -> bool:
        if not isinstance(other, FiveTuple):
            return False
        return (self.src_ip == other.src_ip and
                self.dst_ip == other.dst_ip and
                self.src_port == other.src_port and
                self.dst_port == other.dst_port and
                self.protocol == other.protocol)
    
    def __hash__(self) -> int:
        """Hash function for use in dictionaries."""
        # Simple but effective hash combining all fields
        h = 0
        h ^= hash(self.src_ip) + 0x9e3779b9 + (h << 6) + (h >> 2)
        h ^= hash(self.dst_ip) + 0x9e3779b9 + (h << 6) + (h >> 2)
        h ^= hash(self.src_port) + 0x9e3779b9 + (h << 6) + (h >> 2)
        h ^= hash(self.dst_port) + 0x9e3779b9 + (h << 6) + (h >> 2)
        h ^= hash(self.protocol) + 0x9e3779b9 + (h << 6) + (h >> 2)
        return h
    
    def reverse(self) -> 'FiveTuple':
        """Create reverse tuple (for matching bidirectional flows)."""
        return FiveTuple(self.dst_ip, self.src_ip, self.dst_port, self.src_port, self.protocol)
    
    def to_string(self) -> str:
        src = ip_int_to_str(self.src_ip)
        dst = ip_int_to_str(self.dst_ip)
        proto = "TCP" if self.protocol == 6 else "UDP" if self.protocol == 17 else str(self.protocol)
        return f"{src}:{self.src_port} -> {dst}:{self.dst_port} ({proto})"


# ============================================================================
# Application Classification
# ============================================================================
class AppType(Enum):
    """Application type detected by DPI."""
    UNKNOWN = 0
    HTTP = 1
    HTTPS = 2
    DNS = 3
    TLS = 4
    QUIC = 5
    # Specific applications (detected via SNI)
    GOOGLE = 10
    FACEBOOK = 11
    YOUTUBE = 12
    TWITTER = 13
    INSTAGRAM = 14
    NETFLIX = 15
    AMAZON = 16
    MICROSOFT = 17
    APPLE = 18
    WHATSAPP = 19
    TELEGRAM = 20
    TIKTOK = 21
    SPOTIFY = 22
    ZOOM = 23
    DISCORD = 24
    GITHUB = 25
    CLOUDFLARE = 26
    APP_COUNT = 27  # Keep this last for counting


# SNI to AppType mapping
SNI_APP_MAPPING = {
    "google": AppType.GOOGLE,
    "www.google": AppType.GOOGLE,
    "facebook": AppType.FACEBOOK,
    "www.facebook": AppType.FACEBOOK,
    "youtube": AppType.YOUTUBE,
    "www.youtube": AppType.YOUTUBE,
    "twitter": AppType.TWITTER,
    "www.twitter": AppType.TWITTER,
    "instagram": AppType.INSTAGRAM,
    "www.instagram": AppType.INSTAGRAM,
    "netflix": AppType.NETFLIX,
    "www.netflix": AppType.NETFLIX,
    "amazon": AppType.AMAZON,
    "www.amazon": AppType.AMAZON,
    "microsoft": AppType.MICROSOFT,
    "www.microsoft": AppType.MICROSOFT,
    "apple": AppType.APPLE,
    "www.apple": AppType.APPLE,
    "whatsapp": AppType.WHATSAPP,
    "telegram": AppType.TELEGRAM,
    "tiktok": AppType.TIKTOK,
    "www.tiktok": AppType.TIKTOK,
    "spotify": AppType.SPOTIFY,
    "open.spotify": AppType.SPOTIFY,
    "zoom": AppType.ZOOM,
    "www.zoom": AppType.ZOOM,
    "discord": AppType.DISCORD,
    "www.discord": AppType.DISCORD,
    "github": AppType.GITHUB,
    "www.github": AppType.GITHUB,
    "cloudflare": AppType.CLOUDFLARE,
    "www.cloudflare": AppType.CLOUDFLARE,
}


def app_type_to_string(app_type: AppType) -> str:
    """Convert AppType to string."""
    names = {
        AppType.UNKNOWN: "Unknown",
        AppType.HTTP: "HTTP",
        AppType.HTTPS: "HTTPS",
        AppType.DNS: "DNS",
        AppType.TLS: "TLS",
        AppType.QUIC: "QUIC",
        AppType.GOOGLE: "Google",
        AppType.FACEBOOK: "Facebook",
        AppType.YOUTUBE: "YouTube",
        AppType.TWITTER: "Twitter",
        AppType.INSTAGRAM: "Instagram",
        AppType.NETFLIX: "Netflix",
        AppType.AMAZON: "Amazon",
        AppType.MICROSOFT: "Microsoft",
        AppType.APPLE: "Apple",
        AppType.WHATSAPP: "WhatsApp",
        AppType.TELEGRAM: "Telegram",
        AppType.TIKTOK: "TikTok",
        AppType.SPOTIFY: "Spotify",
        AppType.ZOOM: "Zoom",
        AppType.DISCORD: "Discord",
        AppType.GITHUB: "GitHub",
        AppType.CLOUDFLARE: "Cloudflare",
    }
    return names.get(app_type, f"Unknown({app_type.value})")


def sni_to_app_type(sni: str) -> AppType:
    """Map SNI to AppType."""
    if not sni:
        return AppType.UNKNOWN
    
    sni_lower = sni.lower()
    
    # Check exact match first
    if sni_lower in SNI_APP_MAPPING:
        return SNI_APP_MAPPING[sni_lower]
    
    # Check suffix match (e.g., "www.google.com" -> "google")
    parts = sni_lower.split('.')
    if len(parts) >= 2:
        # Check second-level domain
        if parts[-2] in SNI_APP_MAPPING:
            return SNI_APP_MAPPING[parts[-2]]
    
    return AppType.UNKNOWN


# ============================================================================
# Connection State
# ============================================================================
class ConnectionState(Enum):
    """Connection state."""
    NEW = 0
    ESTABLISHED = 1
    CLASSIFIED = 2
    BLOCKED = 3
    CLOSED = 4


# ============================================================================
# Packet Action
# ============================================================================
class PacketAction(Enum):
    """What to do with the packet."""
    FORWARD = 0  # Send to internet
    DROP = 1    # Block/drop the packet
    INSPECT = 2 # Needs further inspection
    LOG_ONLY = 3  # Forward but log


# ============================================================================
# Connection Entry
# ============================================================================
@dataclass
class Connection:
    """Connection entry tracked per flow."""
    tuple: FiveTuple
    state: ConnectionState = ConnectionState.NEW
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    
    packets_in: int = 0
    packets_out: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    
    action: PacketAction = PacketAction.FORWARD
    
    # For TCP state tracking
    syn_seen: bool = False
    syn_ack_seen: bool = False
    fin_seen: bool = False


# ============================================================================
# Packet Job
# ============================================================================
@dataclass
class PacketJob:
    """Packet wrapper for queue passing."""
    packet_id: int
    tuple: FiveTuple
    data: bytes
    eth_offset: int = 0
    ip_offset: int = 0
    transport_offset: int = 0
    payload_offset: int = 0
    payload_length: int = 0
    tcp_flags: int = 0
    payload_data: Optional[bytes] = None
    
    # Timestamps
    ts_sec: int = 0
    ts_usec: int = 0


# ============================================================================
# Statistics
# ============================================================================
class DPIStats:
    """Statistics for the DPI engine."""
    
    def __init__(self):
        self.total_packets = 0
        self.total_bytes = 0
        self.forwarded_packets = 0
        self.dropped_packets = 0
        self.tcp_packets = 0
        self.udp_packets = 0
        self.other_packets = 0
        self.active_connections = 0
    
    def increment(self, attr: str, value: int = 1):
        """Thread-safe increment."""
        setattr(self, attr, getattr(self, attr) + value)
    
    def to_dict(self) -> dict:
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "forwarded_packets": self.forwarded_packets,
            "dropped_packets": self.dropped_packets,
            "tcp_packets": self.tcp_packets,
            "udp_packets": self.udp_packets,
            "other_packets": self.other_packets,
            "active_connections": self.active_connections,
        }


# ============================================================================
# Helper Functions
# ============================================================================
def ip_str_to_int(ip: str) -> int:
    """Convert IP string to integer."""
    parts = ip.split('.')
    return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])


def ip_int_to_str(ip: int) -> str:
    """Convert IP integer to string."""
    return f"{(ip >> 24) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 8) & 0xFF}.{ip & 0xFF}"


# ============================================================================
# Protocol Constants
# ============================================================================
class Protocol:
    """Protocol numbers."""
    ICMP = 1
    TCP = 6
    UDP = 17


class EtherType:
    """EtherType values."""
    IPv4 = 0x0800
    IPv6 = 0x86DD
    ARP = 0x0806


class TCPFlags:
    """TCP flag constants."""
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20

