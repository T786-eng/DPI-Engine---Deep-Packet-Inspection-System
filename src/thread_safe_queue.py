#!/usr/bin/env python3
"""
Thread-safe queue for passing packets between threads.
"""

import queue
import threading
from typing import TypeVar, Optional
from dataclasses import dataclass


T = TypeVar('T')


class ThreadSafeQueue:
    """Thread-safe queue for passing packets between threads.
    
    Used for: Reader -> LB -> FP communication
    """
    
    def __init__(self, max_size: int = 10000):
        """Initialize the queue.
        
        Args:
            max_size: Maximum number of items in the queue
        """
        self._queue = queue.Queue(maxsize=max_size)
        self._max_size = max_size
        self._shutdown = False
        self._lock = threading.Lock()
    
    def push(self, item: T, block: bool = True, timeout: Optional[float] = None) -> bool:
        """Push item to queue.
        
        Args:
            item: Item to push
            block: Whether to block if queue is full
            timeout: Timeout in seconds
            
        Returns:
            True if pushed, False if shutdown
        """
        if self._shutdown:
            return False
        
        try:
            self._queue.put(item, block=block, timeout=timeout)
            return True
        except queue.Full:
            return False
    
    def try_push(self, item: T) -> bool:
        """Try to push without blocking.
        
        Args:
            item: Item to push
            
        Returns:
            True if pushed, False if queue full or shutdown
        """
        if self._shutdown:
            return False
        
        try:
            self._queue.put_nowait(item)
            return True
        except queue.Full:
            return False
    
    def pop(self, block: bool = True, timeout: Optional[float] = None) -> Optional[T]:
        """Pop item from queue.
        
        Args:
            block: Whether to block if queue is empty
            timeout: Timeout in seconds
            
        Returns:
            Item if available, None if empty or shutdown
        """
        if self._shutdown:
            return None
        
        try:
            return self._queue.get(block=block, timeout=timeout)
        except queue.Empty:
            return None
    
    def empty(self) -> bool:
        """Check if queue is empty."""
        return self._queue.empty()
    
    def size(self) -> int:
        """Get current size of queue."""
        return self._queue.qsize()
    
    def full(self) -> bool:
        """Check if queue is full."""
        return self._queue.full()
    
    def shutdown(self):
        """Signal shutdown (wake up all waiting threads)."""
        with self._lock:
            self._shutdown = True
        
        # Drain the queue
        try:
            while True:
                self._queue.get_nowait()
        except queue.Empty:
            pass
    
    def is_shutdown(self) -> bool:
        """Check if shutdown has been signaled."""
        return self._shutdown
    
    def clear(self):
        """Clear all items from queue."""
        try:
            while True:
                self._queue.get_nowait()
        except queue.Empty:
            pass


# Simple alias for the class
ThreadSafeQueueType = ThreadSafeQueue

