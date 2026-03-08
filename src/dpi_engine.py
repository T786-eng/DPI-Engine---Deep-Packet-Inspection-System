#!/usr/bin/env python3

import threading
import time
import struct
from typing import Optional, Dict, List
from dataclasses import dataclass
from datetime import datetime

from dpi_types import (
    FiveTuple, PacketJob, PacketAction, DPIStats, AppType,
    ip_str_to_int, ip_int_to_str
)
from pcap_reader import PcapReader, PcapGlobalHeader
from packet_parser import PacketParser, ParsedPacket
from rule_manager import RuleManager
from connection_tracker import GlobalConnectionTable, ConnectionTracker
from load_balancer import LBManager, LoadBalancer
from fast_path import FPManager, FastPathProcessor
from thread_safe_queue import ThreadSafeQueue


# ============================================================================
# DPI Engine Configuration
# ============================================================================

@dataclass
class DPIConfig:
    """Configuration for the DPI Engine."""
    num_load_balancers: int = 2
    fps_per_lb: int = 2
    queue_size: int = 10000
    rules_file: str = ""
    verbose: bool = False


# ============================================================================
# DPI Engine Class
# ============================================================================

class DPIEngine:
    """DPI Engine - Main orchestrator.
    
    Architecture:
    
      +------------------+
      |   PCAP Reader    |  (Reads packets from input file)
      +--------+---------+
               |
               v (hash to select LB)
      +--------+----------+
      |   Load Balancers  |  (2 LB threads)
      |   LB0      LB1    |
      +----+--------+-----+
           |        |
           v        v (hash to select FP within LB's pool)
      +----+--------+-----+
      |  Fast Path Procs  |  (4 FP threads, 2 per LB)
      |  FP0 FP1  FP2 FP3 |
      +----+--------+-----+
           |        |
           v        v
      +----+--------+-----+
      |   Output Queue    |  (Packets to forward)
      +----+--------+-----+
           |
           v
      +----+--------+-----+
      |   Output Writer   |  (Writes to output PCAP)
      +-------------------+
    """
    
    def __init__(self, config: DPIConfig):
        self.config = config
        
        # Shared components
        self.rule_manager = RuleManager()
        self.global_conn_table = None
        
        # Thread pools
        self.fp_manager = None
        self.lb_manager = None
        
        # Output handling
        self.output_queue = ThreadSafeQueue()
        self.output_thread = None
        self.output_file = None
        self.output_lock = threading.Lock()
        
        # Statistics
        self.stats = DPIStats()
        
        # Control
        self.running = False
        self.processing_complete = False
        
        # Reader thread
        self.reader_thread = None
        
        # Load rules if specified
        if config.rules_file:
            self.rule_manager.load_rules(config.rules_file)
    
    def initialize(self) -> bool:
        """Initialize the engine (create threads, queues)."""
        num_fps = self.config.num_load_balancers * self.config.fps_per_lb
        
        # Create global connection table
        self.global_conn_table = GlobalConnectionTable(num_fps)
        
        # Create FP manager
        self.fp_manager = FPManager(
            num_fps=num_fps,
            rule_manager=self.rule_manager,
            output_callback=self._handle_output
        )
        
        # Register FP trackers with global table
        for i in range(num_fps):
            self.global_conn_table.register_tracker(
                i, self.fp_manager.get_fp(i).get_connection_tracker()
            )
        
        # Create LB manager
        fp_queues = self.fp_manager.get_queue_ptrs()
        self.lb_manager = LBManager(
            num_lbs=self.config.num_load_balancers,
            fps_per_lb=self.config.fps_per_lb,
            fp_queues=fp_queues
        )
        
        return True
    
    def process_file(self, input_file: str, output_file: str) -> bool:
        """Process a PCAP file.
        
        Args:
            input_file: Path to input PCAP (user traffic)
            output_file: Path to output PCAP (forwarded traffic)
            
        Returns:
            True if successful
        """
        # Open input file
        reader = PcapReader()
        if not reader.open(input_file):
            return False
        
        # Get global header for output
        global_header = reader.get_global_header()
        
        # Open output file
        try:
            self.output_file = open(output_file, 'wb')
            self._write_output_header(global_header)
        except IOError as e:
            print(f"Error: Could not open output file: {e}")
            reader.close()
            return False
        
        # Start the engine
        self.start()
        
        # Read and process packets
        packet_id = 0
        while True:
            raw_packet = reader.read_next_packet()
            if raw_packet is None:
                break
            
            # Parse the packet
            parsed = PacketParser.parse(raw_packet)
            
            # Create five-tuple
            five_tuple = PacketParser.create_five_tuple(parsed)
            if five_tuple is None:
                continue
            
            # Create packet job
            job = PacketJob(
                packet_id=packet_id,
                tuple=five_tuple,
                data=raw_packet.data,
                payload_data=parsed.payload_data,
                payload_length=parsed.payload_length,
                tcp_flags=parsed.tcp_flags if parsed.has_tcp else 0,
                ts_sec=parsed.timestamp_sec,
                ts_usec=parsed.timestamp_usec
            )
            
            # Get LB for this packet and push to its queue
            lb = self.lb_manager.get_lb_for_packet(five_tuple)
            lb.get_input_queue().try_push(job)
            
            packet_id += 1
            
            # Update stats
            self.stats.total_packets += 1
            self.stats.total_bytes += len(raw_packet.data)
            
            if parsed.has_tcp:
                self.stats.tcp_packets += 1
            elif parsed.has_udp:
                self.stats.udp_packets += 1
            else:
                self.stats.other_packets += 1
        
        reader.close()
        
        # Wait for processing to complete
        self.wait_forCompletion()
        
        # Stop the engine
        self.stop()
        
        # Close output file
        if self.output_file:
            self.output_file.close()
            self.output_file = None
        
        return True
    
    def start(self):
        """Start the engine (starts all threads)."""
        if self.running:
            return
        
        self.running = True
        
        # Start FP threads
        self.fp_manager.start_all()
        
        # Start LB threads
        self.lb_manager.start_all()
        
        # Start output thread
        self.output_thread = threading.Thread(target=self._output_thread_func, daemon=True)
        self.output_thread.start()
    
    def stop(self):
        """Stop the engine (stops all threads)."""
        self.running = False
        
        # Stop LBs
        if self.lb_manager:
            self.lb_manager.stop_all()
        
        # Stop FPs
        if self.fp_manager:
            self.fp_manager.stop_all()
        
        # Stop output thread
        if self.output_thread:
            self.output_thread.join(timeout=2.0)
    
    def wait_forCompletion(self):
        """Wait for processing to complete."""
        # Wait for queues to drain
        max_wait = 30  # seconds
        start_time = time.time()
        
        while self.running:
            # Check if all queues are empty
            all_empty = True
            
            # Check LB queues
            for lb in self.lb_manager.lbs:
                if not lb.input_queue.empty():
                    all_empty = False
                    break
            
            # Check FP queues
            if all_empty:
                for fp in self.fp_manager.fps:
                    if not fp.input_queue.empty():
                        all_empty = False
                        break
            
            if all_empty:
                break
            
            # Timeout check
            if time.time() - start_time > max_wait:
                break
            
            time.sleep(0.1)
        
        self.processing_complete = True
    
    # =========================================================================
    # Rule Management
    # =========================================================================
    
    def block_ip(self, ip: str):
        """Block an IP address."""
        self.rule_manager.block_ip(ip)
    
    def unblock_ip(self, ip: str):
        """Unblock an IP address."""
        self.rule_manager.unblock_ip(ip)
    
    def block_app(self, app):
        """Block an application."""
        if isinstance(app, str):
            try:
                app = AppType[app.upper()]
            except KeyError:
                return
        self.rule_manager.block_app(app)
    
    def unblock_app(self, app):
        """Unblock an application."""
        if isinstance(app, str):
            try:
                app = AppType[app.upper()]
            except KeyError:
                return
        self.rule_manager.unblock_app(app)
    
    def block_domain(self, domain: str):
        """Block a domain."""
        self.rule_manager.block_domain(domain)
    
    def unblock_domain(self, domain: str):
        """Unblock a domain."""
        self.rule_manager.unblock_domain(domain)
    
    def load_rules(self, filename: str) -> bool:
        """Load rules from file."""
        return self.rule_manager.load_rules(filename)
    
    def save_rules(self, filename: str) -> bool:
        """Save rules to file."""
        return self.rule_manager.save_rules(filename)
    
    # =========================================================================
    # Reporting
    # =========================================================================
    
    def generate_report(self) -> str:
        """Generate full statistics report."""
        lines = []
        lines.append("=" * 60)
        lines.append("DPI Engine Statistics Report")
        lines.append("=" * 60)
        
        stats = self.stats.to_dict()
        lines.append(f"Total Packets:      {stats['total_packets']}")
        lines.append(f"Total Bytes:        {stats['total_bytes']}")
        lines.append(f"Forwarded Packets:  {stats['forwarded_packets']}")
        lines.append(f"Dropped Packets:    {stats['dropped_packets']}")
        lines.append(f"TCP Packets:        {stats['tcp_packets']}")
        lines.append(f"UDP Packets:        {stats['udp_packets']}")
        lines.append(f"Other Packets:      {stats['other_packets']}")
        lines.append(f"Active Connections: {stats['active_connections']}")
        
        # Add FP stats
        if self.fp_manager:
            fp_stats = self.fp_manager.get_aggregated_stats()
            lines.append("")
            lines.append("Fast Path Statistics:")
            lines.append(f"  Total Processed:  {fp_stats['total_processed']}")
            lines.append(f"  Total Forwarded:  {fp_stats['total_forwarded']}")
            lines.append(f"  Total Dropped:    {fp_stats['total_dropped']}")
        
        return "\n".join(lines)
    
    def generate_classification_report(self) -> str:
        """Generate classification report (app distribution)."""
        if self.fp_manager:
            return self.fp_manager.generate_classification_report()
        return "No classification data"
    
    def get_stats(self) -> DPIStats:
        """Get real-time statistics."""
        return self.stats
    
    def print_status(self):
        """Print live status."""
        print(self.generate_report())
    
    def get_rule_manager(self) -> RuleManager:
        """Get the rule manager."""
        return self.rule_manager
    
    def is_running(self) -> bool:
        """Check if engine is running."""
        return self.running
    
    # =========================================================================
    # Output Handling
    # =========================================================================
    
    def _handle_output(self, job: PacketJob, action: PacketAction):
        """Handle packet output (forward or drop)."""
        if action == PacketAction.FORWARD:
            self.output_queue.push(job)
            self.stats.forwarded_packets += 1
        elif action == PacketAction.DROP:
            self.stats.dropped_packets += 1
    
    def _output_thread_func(self):
        """Output thread function."""
        while self.running:
            job = self.output_queue.pop(block=True, timeout=0.1)
            
            if job is None:
                continue
            
            self._write_output_packet(job)
    
    def _write_output_header(self, header: PcapGlobalHeader):
        """Write PCAP header to output file."""
        if not self.output_file or not header:
            return
        
        # Write global header
        data = struct.pack('<IHHIIII',
            header.magic_number,
            header.version_major,
            header.version_minor,
            header.thiszone,
            header.sigfigs,
            header.snaplen,
            header.network
        )
        self.output_file.write(data)
    
    def _write_output_packet(self, job: PacketJob):
        """Write a packet to output file."""
        if not self.output_file:
            return
        
        with self.output_lock:
            # Write packet header
            header = struct.pack('<IIII',
                job.ts_sec,
                job.ts_usec,
                len(job.data),
                len(job.data)
            )
            self.output_file.write(header)
            
            # Write packet data
            self.output_file.write(job.data)


# ============================================================================
# Simple DPI Engine (single-threaded for simpler use cases)
# ============================================================================

class SimpleDPIEngine:
    """Simple single-threaded DPI engine for basic usage."""
    
    def __init__(self):
        self.rule_manager = RuleManager()
        self.conn_tracker = ConnectionTracker(0)
        self.stats = DPIStats()
    
    def process_file(self, input_file: str, output_file: str = None) -> bool:
        """Process a PCAP file.
        
        Args:
            input_file: Path to input PCAP
            output_file: Optional path to output PCAP
            
        Returns:
            True if successful
        """
        # Open input file
        reader = PcapReader()
        if not reader.open(input_file):
            return False
        
        # Open output file if specified
        output_pcap = None
        global_header = None
        if output_file:
            try:
                output_pcap = open(output_file, 'wb')
                global_header = reader.get_global_header()
                if global_header:
                    data = struct.pack('<IHHIIII',
                        global_header.magic_number,
                        global_header.version_major,
                        global_header.version_minor,
                        global_header.thiszone,
                        global_header.sigfigs,
                        global_header.snaplen,
                        global_header.network
                    )
                    output_pcap.write(data)
            except IOError as e:
                print(f"Error: Could not open output file: {e}")
                reader.close()
                return False
        
        # Process packets
        packet_id = 0
        while True:
            raw_packet = reader.read_next_packet()
            if raw_packet is None:
                break
            
            # Parse the packet
            parsed = PacketParser.parse(raw_packet)
            
            # Create five-tuple
            five_tuple = PacketParser.create_five_tuple(parsed)
            if five_tuple is None:
                continue
            
            # Get or create connection
            conn = self.conn_tracker.get_or_create_connection(five_tuple)
            
            # Update stats
            self.stats.total_packets += 1
            self.stats.total_bytes += len(raw_packet.data)
            
            if parsed.has_tcp:
                self.stats.tcp_packets += 1
            elif parsed.has_udp:
                self.stats.udp_packets += 1
            
            # Update connection
            self.conn_tracker.update_connection(conn, len(raw_packet.data), True)
            
            # Extract SNI if TLS
            if parsed.payload_data and parsed.dest_port == 443:
                from sni_extractor import SNIExtractor
                sni = SNIExtractor.extract(parsed.payload_data, parsed.payload_length)
                if sni:
                    from dpi_types import sni_to_app_type
                    app = sni_to_app_type(sni)
                    conn.sni = sni
                    if app != AppType.UNKNOWN:
                        conn.app_type = AppType.HTTPS
                        self.conn_tracker.classify_connection(conn, app, sni)
            
            # Check if should be blocked
            block_reason = self.rule_manager.should_block(
                five_tuple.src_ip,
                five_tuple.dst_port,
                conn.app_type,
                conn.sni
            )
            
            if block_reason:
                self.stats.dropped_packets += 1
            else:
                self.stats.forwarded_packets += 1
                # Write to output if available
                if output_pcap:
                    header = struct.pack('<IIII',
                        parsed.timestamp_sec,
                        parsed.timestamp_usec,
                        len(raw_packet.data),
                        len(raw_packet.data)
                    )
                    output_pcap.write(header)
                    output_pcap.write(raw_packet.data)
            
            packet_id += 1
        
        reader.close()
        
        if output_pcap:
            output_pcap.close()
        
        return True
    
    def generate_report(self) -> str:
        """Generate statistics report."""
        lines = []
        lines.append("=" * 60)
        lines.append("DPI Engine Statistics Report")
        lines.append("=" * 60)
        
        stats = self.stats.to_dict()
        lines.append(f"Total Packets:      {stats['total_packets']}")
        lines.append(f"Total Bytes:        {stats['total_bytes']}")
        lines.append(f"Forwarded Packets:  {stats['forwarded_packets']}")
        lines.append(f"Dropped Packets:    {stats['dropped_packets']}")
        lines.append(f"TCP Packets:        {stats['tcp_packets']}")
        lines.append(f"UDP Packets:        {stats['udp_packets']}")
        
        tracker_stats = self.conn_tracker.get_stats()
        lines.append(f"Active Connections: {tracker_stats['active_connections']}")
        
        return "\n".join(lines)
    
    def generate_classification_report(self) -> str:
        """Generate classification report."""
        from dpi_types import app_type_to_string
        
        app_counts = {}
        for conn in self.conn_tracker.get_all_connections():
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
    
    def block_app(self, app_name: str):
        """Block an application by name."""
        try:
            app = AppType[app_name.upper()]
            self.rule_manager.block_app(app)
        except KeyError:
            pass
    
    def block_domain(self, domain: str):
        """Block a domain."""
        self.rule_manager.block_domain(domain)
    
    def block_ip(self, ip: str):
        """Block an IP address."""
        self.rule_manager.block_ip(ip)
    
    def unblock_app(self, app_name: str):
        """Unblock an application."""
        try:
            app = AppType[app_name.upper()]
            self.rule_manager.unblock_app(app)
        except KeyError:
            pass
    
    def get_rule_manager(self) -> RuleManager:
        """Get the rule manager."""
        return self.rule_manager

