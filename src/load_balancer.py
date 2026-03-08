#!/usr/bin/env python3

import threading
from typing import List, Dict
from dataclasses import dataclass, field

from dpi_types import FiveTuple, PacketJob
from thread_safe_queue import ThreadSafeQueue


# ============================================================================
# Load Balancer Class
# ============================================================================

class LoadBalancer:
    """Load Balancer Thread.
    
    Architecture:
      Reader Thread -> LB Queues -> LB Threads -> FP Queues -> FP Threads
    
    Each LB thread:
    1. Receives packets from its input queue (fed by reader)
    2. Extracts five-tuple from packet
    3. Hashes the tuple to determine target FP
    4. Forwards packet to appropriate FP queue
    
    Load Balancing Strategy:
    - Consistent hashing ensures same flow always goes to same FP
    - This is critical for proper connection tracking and DPI
    
    Example with 2 LBs and 4 FPs:
      LB0 handles FP0, FP1 (hash % 2 == 0 or 1)
      LB1 handles FP2, FP3 (hash % 2 == 0 or 1, but offset by 2)
    """
    
    def __init__(self, lb_id: int, fp_queues: List[ThreadSafeQueue], 
                 fp_start_id: int = 0):
        """Initialize the load balancer.
        
        Args:
            lb_id: ID of this load balancer (0, 1, ...)
            fp_queues: List of FP input queues that this LB serves
            fp_start_id: Starting FP ID for this LB's pool
        """
        self.lb_id = lb_id
        self.fp_start_id = fp_start_id
        self.num_fps = len(fp_queues)
        
        # Input queue from reader
        self.input_queue = ThreadSafeQueue()
        
        # Output queues to FP threads
        self.fp_queues = fp_queues
        
        # Statistics
        self.packets_received = 0
        self.packets_dispatched = 0
        self.per_fp_counts = [0] * self.num_fps
        
        # Thread control
        self.running = False
        self.thread = None
        self.lock = threading.Lock()
    
    def start(self):
        """Start the LB thread."""
        if self.running:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
    
    def stop(self):
        """Stop the LB thread."""
        self.running = False
        
        if self.thread:
            self.thread.join(timeout=2.0)
    
    def get_input_queue(self) -> ThreadSafeQueue:
        """Get input queue (for reader to push packets)."""
        return self.input_queue
    
    def get_stats(self) -> Dict:
        """Get LB statistics."""
        with self.lock:
            return {
                "packets_received": self.packets_received,
                "packets_dispatched": self.packets_dispatched,
                "per_fp_packets": list(self.per_fp_counts),
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
            
            with self.lock:
                self.packets_received += 1
            
            # Determine target FP
            target_fp = self._select_fp(job.tuple)
            
            # Forward to FP queue
            if target_fp >= 0 and target_fp < self.num_fps:
                if self.fp_queues[target_fp].try_push(job):
                    with self.lock:
                        self.packets_dispatched += 1
                        self.per_fp_counts[target_fp] += 1
    
    def _select_fp(self, tuple: FiveTuple) -> int:
        """Determine target FP for a packet based on five-tuple hash.
        
        Args:
            tuple: The five-tuple of the packet
            
        Returns:
            FP index to send the packet to
        """
        # Hash the five-tuple
        h = hash(tuple)
        
        # Use hash to select FP within this LB's pool
        # Adding fp_start_id to get the actual FP ID
        return (h % self.num_fps)


# ============================================================================
# LB Manager Class
# ============================================================================

class LBManager:
    """LB Manager - Creates and manages multiple LB threads."""
    
    def __init__(self, num_lbs: int, fps_per_lb: int, 
                 fp_queues: List[ThreadSafeQueue]):
        """Create LB manager.
        
        Args:
            num_lbs: Number of load balancer threads
            fps_per_lb: Number of FP threads per LB
            fp_queues: List of FP input queues
        """
        self.num_lbs = num_lbs
        self.fps_per_lb = fps_per_lb
        self.total_fps = len(fp_queues)
        
        # Create LBs
        self.lbs: List[LoadBalancer] = []
        
        for i in range(num_lbs):
            # Calculate which FPs this LB handles
            start_fp = i * fps_per_lb
            end_fp = min(start_fp + fps_per_lb, self.total_fps)
            fp_subset = fp_queues[start_fp:end_fp]
            
            lb = LoadBalancer(i, fp_subset, start_fp)
            self.lbs.append(lb)
    
    def start_all(self):
        """Start all LB threads."""
        for lb in self.lbs:
            lb.start()
    
    def stop_all(self):
        """Stop all LB threads."""
        for lb in self.lbs:
            lb.stop()
    
    def get_lb_for_packet(self, tuple: FiveTuple) -> LoadBalancer:
        """Get LB for a given packet (based on hash).
        
        Args:
            tuple: Five-tuple of the packet
            
        Returns:
            Load balancer to handle the packet
        """
        # Hash to select LB
        h = hash(tuple)
        lb_index = h % self.num_lbs
        return self.lbs[lb_index]
    
    def get_lb(self, lb_id: int) -> LoadBalancer:
        """Get specific LB."""
        return self.lbs[lb_id]
    
    def get_num_lbs(self) -> int:
        """Get number of LBs."""
        return self.num_lbs
    
    def get_aggregated_stats(self) -> Dict:
        """Get aggregated stats from all LBs."""
        total_received = 0
        total_dispatched = 0
        
        for lb in self.lbs:
            stats = lb.get_stats()
            total_received += stats["packets_received"]
            total_dispatched += stats["packets_dispatched"]
        
        return {
            "total_received": total_received,
            "total_dispatched": total_dispatched,
        }

