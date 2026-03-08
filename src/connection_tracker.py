#!/usr/bin/env python3

import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dataclasses import dataclass, field

from dpi_types import (
    FiveTuple, Connection, ConnectionState, AppType, 
    PacketAction, ip_int_to_str
)


# ============================================================================
# Connection Tracker Class
# ============================================================================

class ConnectionTracker:
    """Track connection state for all active flows.
    
    Each FP thread has its own ConnectionTracker instance (no sharing needed
    since connections are consistently hashed to the same FP).
    
    Features:
    - Track connection state (NEW -> ESTABLISHED -> CLASSIFIED -> CLOSED)
    - Store classification results (app type, SNI)
    - Maintain per-flow statistics
    - Timeout inactive connections
    """
    
    def __init__(self, fp_id: int = 0, max_connections: int = 100000):
        self.fp_id = fp_id
        self.max_connections = max_connections
        
        # Connection table
        self._connections: Dict[FiveTuple, Connection] = {}
        self._lock = threading.RLock()
        
        # Statistics
        self.total_seen = 0
        self.classified_count = 0
        self.blocked_count = 0
    
    def get_or_create_connection(self, tuple: FiveTuple) -> Connection:
        """Get or create connection entry.
        
        Returns:
            Connection object (existing or newly created)
        """
        with self._lock:
            # Try to get existing connection
            if tuple in self._connections:
                conn = self._connections[tuple]
                conn.last_seen = datetime.now()
                return conn
            
            # Try reverse tuple too (for bidirectional flows)
            reverse_tuple = tuple.reverse()
            if reverse_tuple in self._connections:
                conn = self._connections[reverse_tuple]
                conn.last_seen = datetime.now()
                return conn
            
            # Create new connection
            conn = Connection(
                tuple=tuple,
                first_seen=datetime.now(),
                last_seen=datetime.now()
            )
            
            # Check if we're at max capacity
            if len(self._connections) >= self.max_connections:
                self._evict_oldest()
            
            self._connections[tuple] = conn
            self.total_seen += 1
            
            return conn
    
    def get_connection(self, tuple: FiveTuple) -> Optional[Connection]:
        """Get existing connection (returns None if not found)."""
        with self._lock:
            if tuple in self._connections:
                return self._connections[tuple]
            
            # Try reverse tuple
            reverse_tuple = tuple.reverse()
            if reverse_tuple in self._connections:
                return self._connections[reverse_tuple]
            
            return None
    
    def update_connection(self, conn: Connection, packet_size: int, is_outbound: bool):
        """Update connection with new packet."""
        with self._lock:
            if is_outbound:
                conn.packets_out += 1
                conn.bytes_out += packet_size
            else:
                conn.packets_in += 1
                conn.bytes_in += packet_size
            
            conn.last_seen = datetime.now()
    
    def classify_connection(self, conn: Connection, app: AppType, sni: str):
        """Mark connection as classified."""
        with self._lock:
            conn.app_type = app
            conn.sni = sni
            conn.state = ConnectionState.CLASSIFIED
            self.classified_count += 1
    
    def block_connection(self, conn: Connection):
        """Mark connection as blocked."""
        with self._lock:
            conn.action = PacketAction.DROP
            conn.state = ConnectionState.BLOCKED
            self.blocked_count += 1
    
    def close_connection(self, tuple: FiveTuple):
        """Mark connection as closed."""
        with self._lock:
            if tuple in self._connections:
                self._connections[tuple].state = ConnectionState.CLOSED
            else:
                reverse = tuple.reverse()
                if reverse in self._connections:
                    self._connections[reverse].state = ConnectionState.CLOSED
    
    def cleanup_stale(self, timeout_seconds: int = 300) -> int:
        """Remove timed-out connections.
        
        Args:
            timeout_seconds: Timeout in seconds
            
        Returns:
            Number of connections removed
        """
        timeout = timedelta(seconds=timeout_seconds)
        now = datetime.now()
        removed = 0
        
        with self._lock:
            to_remove = []
            
            for tuple_key, conn in self._connections.items():
                if now - conn.last_seen > timeout:
                    to_remove.append(tuple_key)
            
            for key in to_remove:
                del self._connections[key]
                removed += 1
        
        return removed
    
    def get_all_connections(self) -> List[Connection]:
        """Get all connections (for reporting)."""
        with self._lock:
            return list(self._connections.values())
    
    def get_active_count(self) -> int:
        """Get active connection count."""
        with self._lock:
            return len(self._connections)
    
    def get_stats(self) -> Dict:
        """Get tracker statistics."""
        with self._lock:
            return {
                "active_connections": len(self._connections),
                "total_connections_seen": self.total_seen,
                "classified_connections": self.classified_count,
                "blocked_connections": self.blocked_count,
            }
    
    def clear(self):
        """Clear all connections."""
        with self._lock:
            self._connections.clear()
            self.total_seen = 0
            self.classified_count = 0
            self.blocked_count = 0
    
    def for_each(self, callback):
        """Iteration callback for all connections."""
        with self._lock:
            for conn in self._connections.values():
                callback(conn)
    
    def _evict_oldest(self):
        """Evict oldest connection when at capacity."""
        if not self._connections:
            return
        
        # Find oldest connection
        oldest_tuple = None
        oldest_time = None
        
        for tuple_key, conn in self._connections.items():
            if oldest_time is None or conn.last_seen < oldest_time:
                oldest_tuple = tuple_key
                oldest_time = conn.last_seen
        
        if oldest_tuple:
            del self._connections[oldest_tuple]


# ============================================================================
# Global Connection Table Class
# ============================================================================

class GlobalConnectionTable:
    """Aggregates stats from all FP trackers."""
    
    def __init__(self, num_fps: int):
        self.num_fps = num_fps
        self._trackers: Dict[int, ConnectionTracker] = {}
        self._lock = threading.RLock()
    
    def register_tracker(self, fp_id: int, tracker: ConnectionTracker):
        """Register an FP's tracker."""
        with self._lock:
            self._trackers[fp_id] = tracker
    
    def get_global_stats(self) -> Dict:
        """Get aggregated statistics."""
        total_active = 0
        total_seen = 0
        app_distribution: Dict[AppType, int] = {}
        domains: Dict[str, int] = {}
        
        with self._lock:
            for tracker in self._trackers.values():
                stats = tracker.get_stats()
                total_active += stats["active_connections"]
                total_seen += stats["total_connections_seen"]
                
                # Collect app distribution
                for conn in tracker.get_all_connections():
                    if conn.app_type != AppType.UNKNOWN:
                        app_distribution[conn.app_type] = app_distribution.get(conn.app_type, 0) + 1
                    
                    if conn.sni:
                        domains[conn.sni] = domains.get(conn.sni, 0) + 1
        
        # Sort domains by count
        top_domains = sorted(domains.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            "total_active_connections": total_active,
            "total_connections_seen": total_seen,
            "app_distribution": app_distribution,
            "top_domains": top_domains,
        }
    
    def generate_report(self) -> str:
        """Generate a report of all connections."""
        stats = self.get_global_stats()
        
        lines = []
        lines.append("=" * 60)
        lines.append("Global Connection Table Report")
        lines.append("=" * 60)
        lines.append(f"Total Active Connections: {stats['total_active_connections']}")
        lines.append(f"Total Connections Seen:   {stats['total_connections_seen']}")
        
        lines.append("\n--- Application Distribution ---")
        if stats['app_distribution']:
            for app_type, count in sorted(stats['app_distribution'].items(), key=lambda x: x[1], reverse=True):
                lines.append(f"  {app_type.name}: {count}")
        else:
            lines.append("  No classified connections")
        
        lines.append("\n--- Top Domains ---")
        if stats['top_domains']:
            for domain, count in stats['top_domains']:
                lines.append(f"  {domain}: {count}")
        else:
            lines.append("  No domains detected")
        
        return "\n".join(lines)

