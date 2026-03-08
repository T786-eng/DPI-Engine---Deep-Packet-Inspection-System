#!/usr/bin/env python3

import threading
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from datetime import datetime

from dpi_types import (
    FiveTuple, PacketJob, PacketAction, Connection, 
    ConnectionState, AppType, TCPFlags, ip_str_to_int
)
from thread_safe_queue import ThreadSafeQueue
from connection_tracker import ConnectionTracker
from rule_manager import RuleManager
from sni_extractor import SNIExtractor, HTTPHostExtractor, DNSExtractor


# ============================================================================
# Fast Path Processor Class
# ============================================================================

class FastPathProcessor:
    """Fast Path Processor Thread.
    
    Each FP thread is responsible for:
    1. Receiving packets from its input queue (fed by LB)
    2. Connection tracking (maintaining flow state)
    3. Deep Packet Inspection (SNI extraction, protocol detection)
    4. Rule matching (blocking decisions)
    5. Forwarding or dropping packets
    
    FP threads are the workhorses of the DPI engine. They do the heavy lifting
    of actually inspecting packet contents and making decisions.
    """
    
    def __init__(self, fp_id: int, rule_manager: RuleManager,
                 output_callback: Callable[[PacketJob, PacketAction], None]):
        """Initialize the Fast Path processor.
        
        Args:
            fp_id: ID of this FP (0, 1, 2, ...)
            rule_manager: Shared rule manager (read-only from FP perspective)
            output_callback: Called when packet should be forwarded
        """
        self.fp_id = fp_id
        
        # Input queue from LB
        self.input_queue = ThreadSafeQueue()
        
        # Connection tracker (per-FP, no sharing needed)
        self.conn_tracker = ConnectionTracker(fp_id)
        
        # Rule manager (shared, read-only)
        self.rule_manager = rule_manager
        
        # Output callback
        self.output_callback = output_callback
        
        # Statistics
        self.packets_processed = 0
        self.packets_forwarded = 0
        self.packets_dropped = 0
        self.sni_extractions = 0
        self.classification_hits = 0
        self.lock = threading.Lock()
        
        # Thread control
        self.running = False
        self.thread = None
    
    def start(self):
        """Start the FP thread."""
        if self.running:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
    
    def stop(self):
        """Stop the FP thread."""
        self.running = False
        
        if self.thread:
            self.thread.join(timeout=2.0)
    
    def get_input_queue(self) -> ThreadSafeQueue:
        """Get input queue (for LB to push packets)."""
        return self.input_queue
    
    def get_connection_tracker(self) -> ConnectionTracker:
        """Get connection tracker (for reporting)."""
        return self.conn_tracker
    
    def get_stats(self) -> Dict:
        """Get FP statistics."""
        with self.lock:
            tracker_stats = self.conn_tracker.get_stats()
            return {
                "packets_processed": self.packets_processed,
                "packets_forwarded": self.packets_forwarded,
                "packets_dropped": self.packets_dropped,
                "connections_tracked": tracker_stats["active_connections"],
                "sni_extractions": self.sni_extractions,
                "classification_hits": self.classification_hits,
            }
    
    def is_running(self) -> bool:
        """Check if running."""
        return self.running
    
    def _run(self):
        """Main processing loop."""
        while self.running:
            # Pop packet from input queue
            job = self.input_queue.pop(block=True, timeout=0.1)
            
            if job is None:
                continue
            
            # Process the packet
            action = self._process_packet(job)
            
            # Update statistics
            with self.lock:
                self.packets_processed += 1
                if action == PacketAction.FORWARD:
                    self.packets_forwarded += 1
                elif action == PacketAction.DROP:
                    self.packets_dropped += 1
            
            # Send to output
            if self.output_callback:
                self.output_callback(job, action)
    
    def _process_packet(self, job: PacketJob) -> PacketAction:
        """Process a single packet.
        
        Args:
            job: The packet job to process
            
        Returns:
            The action to take on the packet
        """
        # Get or create connection
        conn = self.conn_tracker.get_or_create_connection(job.tuple)
        
        # Update connection with packet
        is_outbound = True  # Assume outbound for now
        self.conn_tracker.update_connection(conn, len(job.data), is_outbound)
        
        # Update TCP state
        if job.tuple.protocol == 6:  # TCP
            self._update_tcp_state(conn, job.tcp_flags)
        
        # Inspect payload if we have TCP data
        if job.payload_data and len(job.payload_data) > 0:
            self._inspect_payload(job, conn)
        
        # Check rules
        action = self._check_rules(job, conn)
        
        # Update connection action
        conn.action = action
        
        return action
    
    def _inspect_payload(self, job: PacketJob, conn: Connection):
        """Inspect packet payload for classification.
        
        Args:
            job: The packet job
            conn: The connection
        """
        payload = job.payload_data
        length = len(payload)
        
        # Try to extract SNI from TLS Client Hello
        if job.tuple.dst_port == 443:  # HTTPS
            sni = SNIExtractor.extract(payload, length)
            if sni:
                self.sni_extractions += 1
                conn.sni = sni
                
                # Map SNI to app type
                from dpi_types import sni_to_app_type
                app = sni_to_app_type(sni)
                
                if app != AppType.UNKNOWN:
                    conn.app_type = AppType.HTTPS
                    self.conn_tracker.classify_connection(conn, app, sni)
                    self.classification_hits += 1
                    return
        
        # Try to extract HTTP Host
        if job.tuple.dst_port == 80:  # HTTP
            host = HTTPHostExtractor.extract(payload, length)
            if host:
                from dpi_types import sni_to_app_type
                app = sni_to_app_type(host)
                
                if app != AppType.UNKNOWN:
                    conn.app_type = AppType.HTTP
                    conn.sni = host
                    self.conn_tracker.classify_connection(conn, app, host)
                    self.classification_hits += 1
                    return
        
        # Try to extract DNS query
        if job.tuple.dst_port == 53:  # DNS
            domain = DNSExtractor.extract_query(payload, length)
            if domain:
                from dpi_types import sni_to_app_type
                app = sni_to_app_type(domain)
                
                if app != AppType.UNKNOWN:
                    conn.app_type = AppType.DNS
                    conn.sni = domain
                    self.conn_tracker.classify_connection(conn, app, domain)
                    self.classification_hits += 1
    
    def _check_rules(self, job: PacketJob, conn: Connection) -> PacketAction:
        """Check if packet matches any blocking rules.
        
        Args:
            job: The packet job
            conn: The connection
            
        Returns:
            The action to take
        """
        # Check if connection is already blocked
        if conn.state == ConnectionState.BLOCKED:
            return PacketAction.DROP
        
        # Get source IP
        src_ip = job.tuple.src_ip
        
        # Get destination port
        dst_port = job.tuple.dst_port
        
        # Get app type and domain
        app = conn.app_type
        domain = conn.sni
        
        # Check rules
        block_reason = self.rule_manager.should_block(
            src_ip, dst_port, app, domain
        )
        
        if block_reason:
            self.conn_tracker.block_connection(conn)
            return PacketAction.DROP
        
        return PacketAction.FORWARD
    
    def _update_tcp_state(self, conn: Connection, tcp_flags: int):
        """Update TCP connection state.
        
        Args:
            conn: The connection
            tcp_flags: TCP flags from the packet
        """
        if tcp_flags & TCPFlags.SYN:
            conn.syn_seen = True
            if conn.state == ConnectionState.NEW:
                conn.state = ConnectionState.ESTABLISHED
        
        if tcp_flags & 0x12 == 0x12:  # SYN-ACK
            conn.syn_ack_seen = True
        
        if tcp_flags & TCPFlags.FIN:
            conn.fin_seen = True
            conn.state = ConnectionState.CLOSED
        
        if tcp_flags & TCPFlags.RST:
            conn.state = ConnectionState.CLOSED


# ============================================================================
# FP Manager Class
# ============================================================================

class FPManager:
    """FP Manager - Creates and manages multiple FP threads."""
    
    def __init__(self, num_fps: int, rule_manager: RuleManager,
                 output_callback: Callable[[PacketJob, PacketAction], None]):
        """Create FP manager.
        
        Args:
            num_fps: Number of FP threads
            rule_manager: Shared rule manager
            output_callback: Shared output callback
        """
        self.num_fps = num_fps
        
        # Create FP processors
        self.fps: List[FastPathProcessor] = []
        
        for i in range(num_fps):
            fp = FastPathProcessor(i, rule_manager, output_callback)
            self.fps.append(fp)
    
    def start_all(self):
        """Start all FP threads."""
        for fp in self.fps:
            fp.start()
    
    def stop_all(self):
        """Stop all FP threads."""
        for fp in self.fps:
            fp.stop()
    
    def get_fp(self, fp_id: int) -> FastPathProcessor:
        """Get specific FP."""
        return self.fps[fp_id]
    
    def get_fp_queue(self, fp_id: int) -> ThreadSafeQueue:
        """Get FP input queue."""
        return self.fps[fp_id].get_input_queue()
    
    def get_queue_ptrs(self) -> List[ThreadSafeQueue]:
        """Get all FP queues as list."""
        return [fp.get_input_queue() for fp in self.fps]
    
    def get_num_fps(self) -> int:
        """Get number of FPs."""
        return self.num_fps
    
    def get_aggregated_stats(self) -> Dict:
        """Get aggregated stats from all FPs."""
        total_processed = 0
        total_forwarded = 0
        total_dropped = 0
        total_connections = 0
        
        for fp in self.fps:
            stats = fp.get_stats()
            total_processed += stats["packets_processed"]
            total_forwarded += stats["packets_forwarded"]
            total_dropped += stats["packets_dropped"]
            total_connections += stats["connections_tracked"]
        
        return {
            "total_processed": total_processed,
            "total_forwarded": total_forwarded,
            "total_dropped": total_dropped,
            "total_connections": total_connections,
        }
    
    def generate_classification_report(self) -> str:
        """Generate classification report."""
        from dpi_types import app_type_to_string
        
        app_counts: Dict[AppType, int] = {}
        
        for fp in self.fps:
            for conn in fp.get_connection_tracker().get_all_connections():
                if conn.app_type != AppType.UNKNOWN:
                    app_counts[conn.app_type] = app_counts.get(conn.app_type, 0) + 1
        
        lines = []
        lines.append("=" * 60)
        lines.append("Classification Report")
        lines.append("=" * 60)
        
        if app_counts:
            for app_type, count in sorted(app_counts.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"  {app_type_to_string(app_type)}: {count}")
        else:
            lines.append("  No classified connections")
        
        return "\n".join(lines)

