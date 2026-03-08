#!/usr/bin/env python3
"""
Rule Manager - Manages blocking/filtering rules.

"""

import threading
from typing import Optional, List, Set, Dict
from dataclasses import dataclass
from dpi_types import AppType, ip_str_to_int, ip_int_to_str


# ============================================================================
# Block Reason
# ============================================================================

@dataclass
class BlockReason:
    """Reason for blocking a packet/connection."""
    TYPE_IP = "IP"
    TYPE_APP = "APP"
    TYPE_DOMAIN = "DOMAIN"
    TYPE_PORT = "PORT"
    
    type: str
    detail: str


# ============================================================================
# Rule Manager Class
# ============================================================================

class RuleManager:
    """Manages blocking/filtering rules.
    
    Rules can be:
    1. IP-based: Block specific source IPs
    2. App-based: Block specific applications (detected via SNI)
    3. Domain-based: Block specific domains
    4. Port-based: Block specific destination ports
    
    Rules are thread-safe for concurrent access from FP threads.
    """
    
    def __init__(self):
        # Thread-safe containers with locks
        self._ip_lock = threading.RLock()
        self._blocked_ips: Set[int] = set()
        
        self._app_lock = threading.RLock()
        self._blocked_apps: Set[AppType] = set()
        
        self._domain_lock = threading.RLock()
        self._blocked_domains: Set[str] = set()
        
        self._port_lock = threading.RLock()
        self._blocked_ports: Set[int] = set()
    
    # =========================================================================
    # IP Blocking
    # =========================================================================
    
    def block_ip(self, ip: str):
        """Block a specific source IP (string format)."""
        ip_int = ip_str_to_int(ip)
        self.block_ip_int(ip_int)
    
    def block_ip_int(self, ip: int):
        """Block a specific source IP (integer format)."""
        with self._ip_lock:
            self._blocked_ips.add(ip)
    
    def unblock_ip(self, ip: str):
        """Unblock an IP (string format)."""
        ip_int = ip_str_to_int(ip)
        self.unblock_ip_int(ip_int)
    
    def unblock_ip_int(self, ip: int):
        """Unblock an IP (integer format)."""
        with self._ip_lock:
            self._blocked_ips.discard(ip)
    
    def is_ip_blocked(self, ip: int) -> bool:
        """Check if IP is blocked."""
        with self._ip_lock:
            return ip in self._blocked_ips
    
    def get_blocked_ips(self) -> List[str]:
        """Get list of blocked IPs (for display)."""
        with self._ip_lock:
            return [ip_int_to_str(ip) for ip in self._blocked_ips]
    
    # =========================================================================
    # Application Blocking
    # =========================================================================
    
    def block_app(self, app: AppType):
        """Block a specific application type."""
        with self._app_lock:
            self._blocked_apps.add(app)
    
    def unblock_app(self, app: AppType):
        """Unblock an application."""
        with self._app_lock:
            self._blocked_apps.discard(app)
    
    def is_app_blocked(self, app: AppType) -> bool:
        """Check if app is blocked."""
        with self._app_lock:
            return app in self._blocked_apps
    
    def get_blocked_apps(self) -> List[AppType]:
        """Get list of blocked apps."""
        with self._app_lock:
            return list(self._blocked_apps)
    
    # =========================================================================
    # Domain Blocking
    # =========================================================================
    
    def block_domain(self, domain: str):
        """Block a specific domain (or pattern).
        
        Supports wildcards: *.facebook.com blocks all facebook subdomains.
        """
        with self._domain_lock:
            # Normalize to lowercase
            domain = domain.lower()
            self._blocked_domains.add(domain)
    
    def unblock_domain(self, domain: str):
        """Unblock a domain."""
        with self._domain_lock:
            domain = domain.lower()
            self._blocked_domains.discard(domain)
    
    def is_domain_blocked(self, domain: str) -> bool:
        """Check if domain matches any block rule."""
        if not domain:
            return False
        
        domain = domain.lower()
        
        with self._domain_lock:
            # Check exact match
            if domain in self._blocked_domains:
                return True
            
            # Check wildcard patterns
            for pattern in self._blocked_domains:
                if pattern.startswith('*.'):
                    # Wildcard pattern
                    suffix = pattern[2:]
                    if domain.endswith(suffix) or domain == suffix:
                        return True
                elif pattern.startswith('*'):
                    # Other wildcards (simplified)
                    suffix = pattern[1:]
                    if domain.endswith(suffix):
                        return True
            
            return False
    
    def get_blocked_domains(self) -> List[str]:
        """Get list of blocked domains."""
        with self._domain_lock:
            return list(self._blocked_domains)
    
    # =========================================================================
    # Port Blocking
    # =========================================================================
    
    def block_port(self, port: int):
        """Block a specific destination port."""
        with self._port_lock:
            self._blocked_ports.add(port)
    
    def unblock_port(self, port: int):
        """Unblock a port."""
        with self._port_lock:
            self._blocked_ports.discard(port)
    
    def is_port_blocked(self, port: int) -> bool:
        """Check if port is blocked."""
        with self._port_lock:
            return port in self._blocked_ports
    
    # =========================================================================
    # Combined Check
    # =========================================================================
    
    def should_block(self, src_ip: int, dst_port: int, 
                    app: AppType, domain: str) -> Optional[BlockReason]:
        """Check if a packet/connection should be blocked based on all rules.
        
        Returns:
            BlockReason if blocked, None if allowed
        """
        # Check IP blocking
        with self._ip_lock:
            if src_ip in self._blocked_ips:
                return BlockReason(BlockReason.TYPE_IP, ip_int_to_str(src_ip))
        
        # Check port blocking
        with self._port_lock:
            if dst_port in self._blocked_ports:
                return BlockReason(BlockReason.TYPE_PORT, str(dst_port))
        
        # Check app blocking
        with self._app_lock:
            if app in self._blocked_apps:
                return BlockReason(BlockReason.TYPE_APP, app.name)
        
        # Check domain blocking
        if domain and self.is_domain_blocked(domain):
            return BlockReason(BlockReason.TYPE_DOMAIN, domain)
        
        return None
    
    # =========================================================================
    # Rule Persistence
    # =========================================================================
    
    def save_rules(self, filename: str) -> bool:
        """Save rules to file."""
        try:
            with open(filename, 'w') as f:
                # Save blocked IPs
                with self._ip_lock:
                    for ip in self._blocked_ips:
                        f.write(f"ip:{ip_int_to_str(ip)}\n")
                
                # Save blocked apps
                with self._app_lock:
                    for app in self._blocked_apps:
                        f.write(f"app:{app.name}\n")
                
                # Save blocked domains
                with self._domain_lock:
                    for domain in self._blocked_domains:
                        f.write(f"domain:{domain}\n")
                
                # Save blocked ports
                with self._port_lock:
                    for port in self._blocked_ports:
                        f.write(f"port:{port}\n")
            
            return True
        except Exception as e:
            print(f"Error saving rules: {e}")
            return False
    
    def load_rules(self, filename: str) -> bool:
        """Load rules from file."""
        try:
            with open(filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    if ':' not in line:
                        continue
                    
                    parts = line.split(':', 1)
                    rule_type = parts[0]
                    value = parts[1]
                    
                    if rule_type == 'ip':
                        self.block_ip(value)
                    elif rule_type == 'app':
                        try:
                            app = AppType[value]
                            self.block_app(app)
                        except KeyError:
                            pass
                    elif rule_type == 'domain':
                        self.block_domain(value)
                    elif rule_type == 'port':
                        try:
                            port = int(value)
                            self.block_port(port)
                        except ValueError:
                            pass
            
            return True
        except Exception as e:
            print(f"Error loading rules: {e}")
            return False
    
    def clear_all(self):
        """Clear all rules."""
        with self._ip_lock:
            self._blocked_ips.clear()
        with self._app_lock:
            self._blocked_apps.clear()
        with self._domain_lock:
            self._blocked_domains.clear()
        with self._port_lock:
            self._blocked_ports.clear()
    
    # =========================================================================
    # Statistics
    # =========================================================================
    
    def get_stats(self) -> Dict[str, int]:
        """Get rule statistics."""
        return {
            "blocked_ips": len(self._blocked_ips),
            "blocked_apps": len(self._blocked_apps),
            "blocked_domains": len(self._blocked_domains),
            "blocked_ports": len(self._blocked_ports),
        }
    
    # =========================================================================
    # Predefined Block Lists
    # =========================================================================
    
    def block_social_media(self):
        """Block common social media apps."""
        self.block_app(AppType.FACEBOOK)
        self.block_app(AppType.TWITTER)
        self.block_app(AppType.INSTAGRAM)
        self.block_app(AppType.TIKTOK)
        self.block_app(AppType.WHATSAPP)
    
    def block_streaming(self):
        """Block streaming services."""
        self.block_app(AppType.YOUTUBE)
        self.block_app(AppType.NETFLIX)
        self.block_app(AppType.SPOTIFY)
    
    def block_messaging(self):
        """Block messaging apps."""
        self.block_app(AppType.WHATSAPP)
        self.block_app(AppType.TELEGRAM)
        self.block_app(AppType.DISCORD)
        self.block_app(AppType.ZOOM)

