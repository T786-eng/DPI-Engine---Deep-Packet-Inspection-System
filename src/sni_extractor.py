#!/usr/bin/env python3
"""
SNI Extractor - Extracts Server Name Indication from TLS Client Hello.

"""

import struct
from typing import Optional, List, Tuple


# ============================================================================
# TLS Constants
# ============================================================================

CONTENT_TYPE_HANDSHAKE = 0x16
HANDSHAKE_CLIENT_HELLO = 0x01
EXTENSION_SNI = 0x0000
SNI_TYPE_HOSTNAME = 0x00


# ============================================================================
# SNI Extractor Class
# ============================================================================

class SNIExtractor:
    """Extract SNI from a TLS Client Hello packet."""
    
    @staticmethod
    def extract(payload: bytes, length: int) -> Optional[str]:
        """Extract SNI from a TLS Client Hello packet.
        
        Args:
            payload: The TCP payload (after TCP header)
            length: Length of the payload
            
        Returns:
            The SNI hostname if found, None otherwise
        """
        if length < 6:
            return None
        
        # Check if this is a TLS Handshake record
        if payload[0] != CONTENT_TYPE_HANDSHAKE:
            return None
        
        # Check TLS version (bytes 1-2)
        # TLS 1.0 = 0x0301, TLS 1.1 = 0x0302, TLS 1.2 = 0x0303, TLS 1.3 = 0x0303
        tls_version = struct.unpack('>H', payload[1:3])[0]
        if tls_version < 0x0301 or tls_version > 0x0303:
            return None
        
        # TLS Record Header is 5 bytes:
        # - Byte 0: Content Type
        # - Bytes 1-2: TLS Version
        # - Bytes 3-4: Record Length (16-bit, not 24-bit!)
        
        # Handshake message starts at byte 5
        # Check handshake type at byte 5
        if length < 6:
            return None
        
        handshake_type = payload[5]
        if handshake_type != HANDSHAKE_CLIENT_HELLO:
            return None
        
        # Now we're at the handshake layer (after 5-byte record header)
        # Client Hello starts at offset 5, skip handshake type (1 byte) + length (3 bytes)
        offset = 5 + 4  # Skip handshake type (1) and handshake length (3)
        
        if offset + 2 > length:
            return None
        
        # Client Version (2 bytes)
        client_version = struct.unpack('>H', payload[offset:offset+2])[0]
        offset += 2
        
        # Random (32 bytes)
        offset += 32
        
        # Session ID
        if offset >= length:
            return None
        session_id_len = payload[offset]
        offset += 1 + session_id_len
        
        # Cipher Suites
        if offset + 2 > length:
            return None
        cipher_suites_len = struct.unpack('>H', payload[offset:offset+2])[0]
        offset += 2 + cipher_suites_len
        
        # Compression Methods
        if offset >= length:
            return None
        compression_len = payload[offset]
        offset += 1 + compression_len
        
        # Extensions (if present)
        if offset + 2 > length:
            return None
        
        extensions_len = struct.unpack('>H', payload[offset:offset+2])[0]
        offset += 2
        
        if offset + extensions_len > length:
            return None
        
        # Parse extensions to find SNI
        end_offset = offset + extensions_len
        while offset + 4 <= end_offset:
            ext_type = struct.unpack('>H', payload[offset:offset+2])[0]
            ext_len = struct.unpack('>H', payload[offset+2:offset+4])[0]
            
            # Check for SNI before advancing offset
            if ext_type == EXTENSION_SNI:
                # Found SNI extension! Extract data BEFORE advancing offset
                ext_data = payload[offset+4:offset+4+ext_len]
                return SNIExtractor._parse_sni_extension(ext_data)
            
            offset += 4 + ext_len
        
        return None
    
    @staticmethod
    def _parse_sni_extension(ext_data: bytes) -> Optional[str]:
        """Parse the SNI extension data."""
        if len(ext_data) < 5:
            return None
        
        # SNI List Length (2 bytes)
        sni_list_len = struct.unpack('>H', ext_data[0:2])[0]
        
        # SNI Type (1 byte) - should be 0x00 (hostname)
        sni_type = ext_data[2]
        if sni_type != SNI_TYPE_HOSTNAME:
            return None
        
        # SNI Length (2 bytes)
        sni_len = struct.unpack('>H', ext_data[3:5])[0]
        
        # SNI Value (variable)
        if 5 + sni_len > len(ext_data):
            return None
        
        sni = ext_data[5:5+sni_len].decode('ascii', errors='ignore')
        return sni
    
    @staticmethod
    def is_tls_client_hello(payload: bytes, length: int) -> bool:
        """Check if this looks like a TLS Client Hello."""
        if length < 6:
            return False
        
        # Check if it's a TLS handshake record
        if payload[0] != CONTENT_TYPE_HANDSHAKE:
            return False
        
        # Check TLS version
        tls_version = struct.unpack('>H', payload[1:3])[0]
        if tls_version < 0x0301 or tls_version > 0x0303:
            return False
        
        # Check handshake type
        if length < 6:
            return False
        handshake_type = payload[5]
        
        return handshake_type == HANDSHAKE_CLIENT_HELLO
    
    @staticmethod
    def _read_uint16_be(data: bytes) -> int:
        """Read big-endian 16-bit integer."""
        return struct.unpack('>H', data[:2])[0]
    
    @staticmethod
    def _read_uint24_be(data: bytes) -> int:
        """Read big-endian 24-bit integer."""
        return (data[0] << 16) | (data[1] << 8) | data[2]
    
    @staticmethod
    def extract_extensions(payload: bytes, length: int) -> List[Tuple[int, str]]:
        """Extract all extensions (for debugging/logging)."""
        results = []
        
        if length < 6 or payload[0] != CONTENT_TYPE_HANDSHAKE:
            return results
        
        # Skip TLS record header
        offset = 5
        
        if offset + 4 > length:
            return results
        
        # Check handshake type
        if payload[offset] != HANDSHAKE_CLIENT_HELLO:
            return results
        
        offset += 4  # Skip handshake type and length
        
        # Client Version
        offset += 2
        # Random
        offset += 32
        # Session ID
        if offset >= length:
            return results
        session_id_len = payload[offset]
        offset += 1 + session_id_len
        # Cipher Suites
        if offset + 2 > length:
            return results
        cipher_suites_len = struct.unpack('>H', payload[offset:offset+2])[0]
        offset += 2 + cipher_suites_len
        # Compression
        if offset >= length:
            return results
        compression_len = payload[offset]
        offset += 1 + compression_len
        # Extensions
        if offset + 2 > length:
            return results
        extensions_len = struct.unpack('>H', payload[offset:offset+2])[0]
        offset += 2
        
        end_offset = offset + extensions_len
        while offset + 4 <= end_offset:
            ext_type = struct.unpack('>H', payload[offset:offset+2])[0]
            ext_len = struct.unpack('>H', payload[offset+2:offset+4])[0]
            offset += 4
            
            if offset + ext_len > end_offset:
                break
            
            # Try to extract SNI from this extension
            if ext_type == EXTENSION_SNI:
                sni = SNIExtractor._parse_sni_extension(payload[offset:offset+ext_len])
                if sni:
                    results.append((ext_type, sni))
            else:
                results.append((ext_type, f"<{ext_len} bytes>"))
            
            offset += ext_len
        
        return results


# ============================================================================
# HTTP Host Header Extractor
# ============================================================================

class HTTPHostExtractor:
    """Extract Host header from HTTP request (for unencrypted HTTP)."""
    
    @staticmethod
    def extract(payload: bytes, length: int) -> Optional[str]:
        """Extract Host header from HTTP request."""
        if length < 10:
            return None
        
        # Try to decode as ASCII
        try:
            http_data = payload[:length].decode('ascii', errors='ignore')
        except:
            return None
        
        # Check if it looks like an HTTP request
        http_methods = [b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ', b'OPTIONS ', b'PATCH ']
        is_http = any(http_data.startswith(m.decode()) for m in http_methods)
        if not is_http:
            return None
        
        # Find Host header
        lines = http_data.split('\r\n')
        for line in lines:
            if line.lower().startswith('host:'):
                host = line[5:].strip()
                # Remove port if present
                if ':' in host:
                    host = host.split(':')[0]
                return host
        
        return None
    
    @staticmethod
    def is_http_request(payload: bytes, length: int) -> bool:
        """Check if this looks like an HTTP request."""
        if length < 4:
            return False
        
        http_methods = [b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'OPTIONS', b'PATCH']
        
        for method in http_methods:
            if payload[:len(method)] == method:
                return True
        
        return False


# ============================================================================
# DNS Query Extractor
# ============================================================================

class DNSExtractor:
    """Extract queried domain from DNS request."""
    
    @staticmethod
    def extract_query(payload: bytes, length: int) -> Optional[str]:
        """Extract queried domain from DNS request."""
        if length < 12:
            return None
        
        # Check if it's a DNS query (QR bit = 0 in flags)
        # Flags are at bytes 2-3
        flags = struct.unpack('>H', payload[2:4])[0]
        is_query = (flags & 0x8000) == 0
        
        if not is_query:
            return None
        
        # Question count is at bytes 4-5
        qd_count = struct.unpack('>H', payload[4:6])[0]
        if qd_count == 0:
            return None
        
        # Start parsing questions after header (12 bytes)
        offset = 12
        domain = ""
        
        while offset < length:
            label_len = payload[offset]
            if label_len == 0:
                offset += 1
                break
            if offset + label_len + 1 > length:
                return None
            label = payload[offset+1:offset+1+label_len].decode('ascii', errors='ignore')
            if domain:
                domain += "."
            domain += label
            offset += 1 + label_len
        
        return domain if domain else None
    
    @staticmethod
    def is_dns_query(payload: bytes, length: int) -> bool:
        """Check if this is a DNS query (not response)."""
        if length < 4:
            return False
        
        # Check DNS header
        # Port should be 53 (but we already know this from transport)
        # QR bit = 0 means query
        flags = struct.unpack('>H', payload[2:4])[0]
        
        return (flags & 0x8000) == 0


# ============================================================================
# QUIC SNI Extractor
# ============================================================================

class QUICSNIExtractor:
    """QUIC Initial packet SNI extractor (for QUIC/HTTP3 traffic)."""
    
    @staticmethod
    def extract(payload: bytes, length: int) -> Optional[str]:
        """Extract SNI from QUIC Initial packet.
        
        QUIC is more complex as it has its own framing.
        This is a simplified version that looks for TLS Client Hello
        inside CRYPTO frames.
        """
        # QUIC Initial packets also contain TLS Client Hello in CRYPTO frames
        # For simplicity, we'll try the regular TLS extraction first
        # A full implementation would need to parse QUIC frames
        
        return SNIExtractor.extract(payload, length)
    
    @staticmethod
    def is_quic_initial(payload: bytes, length: int) -> bool:
        """Check if this looks like a QUIC Initial packet."""
        if length < 5:
            return False
        
        # QUIC uses UDP and has specific packet number encoding
        # This is a simplified check
        first_byte = payload[0]
        
        # QUIC long header packet
        if (first_byte & 0xC0) == 0xC0:
            # Packet type 0x0 = Initial
            packet_type = (first_byte >> 4) & 0x03
            return packet_type == 0
        
        return False

