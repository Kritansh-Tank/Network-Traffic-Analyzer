from scapy.all import sniff, conf
import threading
import time
from utils import print_info, print_error, print_warning, get_timestamp

class PacketCapture:
    """
    Class to handle packet capturing functionality.
    """
    
    def __init__(self):
        self.packets = []
        self.running = False
        self.capture_thread = None
        self.start_time = None
        self.filter = None
        self.interface = None
        self.packet_count = 0
        self.callback = None
        
    def set_filter(self, filter_str):
        """Set BPF filter for packet capture."""
        self.filter = filter_str
        
    def set_interface(self, interface):
        """Set the interface to capture packets from."""
        self.interface = interface
        
    def set_callback(self, callback):
        """Set a callback function that will be called for each packet."""
        self.callback = callback
        
    def packet_handler(self, packet):
        """Handle each captured packet."""
        self.packets.append(packet)
        self.packet_count += 1
        
        if self.callback:
            self.callback(packet)
            
        return packet
    
    def start_capture(self, count=None, timeout=None):
        """
        Start capturing packets.
        
        Args:
            count: Number of packets to capture. None for unlimited.
            timeout: Timeout in seconds. None for no timeout.
        """
        if self.running:
            print_warning("Packet capture already running!")
            return
        
        self.running = True
        self.start_time = time.time()
        self.packets = []
        self.packet_count = 0
        
        # Define the capture function for threading
        def capture_function():
            try:
                print_info(f"[{get_timestamp()}] Starting packet capture...")
                if self.interface:
                    print_info(f"Interface: {self.interface}")
                if self.filter:
                    print_info(f"Filter: {self.filter}")
                
                # Start packet sniffing
                sniff(
                    prn=self.packet_handler,
                    filter=self.filter,
                    iface=self.interface,
                    count=count,
                    timeout=timeout,
                    store=False  # Don't store packets in memory (we handle this in packet_handler)
                )
                
                if self.running:  # If we haven't manually stopped
                    self.running = False
                    print_info(f"[{get_timestamp()}] Packet capture completed.")
                    print_info(f"Captured {self.packet_count} packets in {time.time() - self.start_time:.2f} seconds.")
            except Exception as e:
                print_error(f"Error in packet capture: {e}")
                self.running = False
        
        # Start capture in a separate thread
        self.capture_thread = threading.Thread(target=capture_function)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
    def stop_capture(self):
        """Stop packet capturing."""
        if not self.running:
            print_warning("No packet capture is running!")
            return
        
        self.running = False
        conf.sniff_promisc = 0  # Turn off promiscuous mode
        
        # Wait for capture thread to join
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=1.0)
            
        duration = time.time() - self.start_time if self.start_time else 0
        print_info(f"[{get_timestamp()}] Packet capture stopped.")
        print_info(f"Captured {self.packet_count} packets in {duration:.2f} seconds.")
        
        return self.packets
    
    def get_packets(self):
        """Return the list of captured packets."""
        return self.packets 