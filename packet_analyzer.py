from scapy.all import IP, TCP, UDP, ICMP, ARP, Ether, DNS
from collections import defaultdict, Counter
import time
from utils import format_bytes, resolve_hostname

class PacketAnalyzer:
    """
    Class to analyze captured network packets.
    """
    
    def __init__(self):
        # Tracking metrics
        self.packet_count = 0
        self.start_time = None
        self.total_bytes = 0
        
        # Protocol statistics
        self.protocols = Counter()
        self.ip_src = Counter()
        self.ip_dst = Counter()
        self.ports_src = Counter()
        self.ports_dst = Counter()
        self.tcp_flags = Counter()
        
        # Connection tracking
        self.connections = defaultdict(lambda: {'bytes': 0, 'packets': 0, 'start_time': None, 'last_time': None})
        
        # DNS tracking
        self.dns_queries = defaultdict(list)
        
        # TCP flow tracking
        self.tcp_flows = defaultdict(list)
        
        # Anomaly detection
        self.port_scan_threshold = 15  # Number of different ports to consider as potential port scan
        self.potential_port_scans = defaultdict(set)
        
    def reset_stats(self):
        """Reset all collected statistics."""
        self.__init__()
        
    def process_packet(self, packet):
        """
        Process a single packet and update statistics.
        
        Args:
            packet: Scapy packet object
        """
        if self.start_time is None:
            self.start_time = time.time()
            
        self.packet_count += 1
        current_time = time.time()
        
        # Calculate packet size
        packet_size = len(packet)
        self.total_bytes += packet_size
        
        # Ethernet layer analysis
        if Ether in packet:
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            
        # IP layer analysis
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
            
            self.ip_src[src_ip] += 1
            self.ip_dst[dst_ip] += 1
            
            # Create connection key
            if TCP in packet or UDP in packet:
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    self.protocols['TCP'] += 1
                    self.ports_src[f"TCP/{src_port}"] += 1
                    self.ports_dst[f"TCP/{dst_port}"] += 1
                    
                    # TCP flag analysis
                    flags = packet[TCP].flags
                    self.tcp_flags[flags] += 1
                    
                    # Track potential port scans
                    if flags & 0x02:  # SYN flag
                        self.potential_port_scans[src_ip].add(dst_port)
                    
                    # Track TCP flows
                    flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                    self.tcp_flows[flow_key].append((current_time, len(packet), 'TCP', flags))
                    
                elif UDP in packet:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    self.protocols['UDP'] += 1
                    self.ports_src[f"UDP/{src_port}"] += 1
                    self.ports_dst[f"UDP/{dst_port}"] += 1
                
                conn_key = f"{src_ip}:{src_port}<->{dst_ip}:{dst_port}"
                alt_key = f"{dst_ip}:{dst_port}<->{src_ip}:{src_port}"
                
                # Use existing connection key if it exists
                key = conn_key if conn_key in self.connections else alt_key if alt_key in self.connections else conn_key
                
                if key not in self.connections:
                    self.connections[key]['start_time'] = current_time
                
                self.connections[key]['bytes'] += packet_size
                self.connections[key]['packets'] += 1
                self.connections[key]['last_time'] = current_time
            
            elif ICMP in packet:
                self.protocols['ICMP'] += 1
                icmp_type = packet[ICMP].type
                icmp_code = packet[ICMP].code
                self.protocols[f'ICMP-{icmp_type}/{icmp_code}'] += 1
        
        # ARP layer analysis
        elif ARP in packet:
            self.protocols['ARP'] += 1
            src_ip = packet[ARP].psrc
            dst_ip = packet[ARP].pdst
            self.ip_src[src_ip] += 1
            self.ip_dst[dst_ip] += 1
            
        # DNS analysis
        if DNS in packet:
            self.protocols['DNS'] += 1
            
            if packet.haslayer(DNS) and packet[DNS].qr == 0:  # Query
                query_name = packet[DNS].qd.qname.decode('utf-8')
                self.dns_queries[query_name].append(current_time)
    
    def process_packets(self, packets):
        """
        Process multiple packets at once.
        
        Args:
            packets: List of Scapy packet objects
        """
        for packet in packets:
            self.process_packet(packet)
    
    def get_summary(self):
        """Return a summary of the traffic analysis."""
        duration = time.time() - self.start_time if self.start_time else 0
        
        # Calculate bytes per second
        bytes_per_sec = self.total_bytes / duration if duration > 0 else 0
        
        summary = {
            'packet_count': self.packet_count,
            'duration': f"{duration:.2f}s",
            'total_bytes': format_bytes(self.total_bytes),
            'bytes_per_sec': format_bytes(bytes_per_sec) + "/s",
            'protocols': dict(self.protocols.most_common(10)),
            'top_sources': dict(self.ip_src.most_common(10)),
            'top_destinations': dict(self.ip_dst.most_common(10)),
            'top_source_ports': dict(self.ports_src.most_common(10)),
            'top_destination_ports': dict(self.ports_dst.most_common(10)),
            'active_connections': len(self.connections),
            'dns_queries': len(self.dns_queries)
        }
        
        return summary
    
    def get_potential_threats(self):
        """Identify potential threat activities in the analyzed traffic."""
        threats = []
        
        # Check for potential port scans
        for ip, ports in self.potential_port_scans.items():
            if len(ports) >= self.port_scan_threshold:
                threats.append({
                    'type': 'Port Scan',
                    'source_ip': ip,
                    'target_ports': len(ports),
                    'severity': 'Medium' if len(ports) < 50 else 'High'
                })
        
        # Look for unusual protocols
        unusual_protocols = [proto for proto, count in self.protocols.items() 
                            if count < self.packet_count * 0.01 and count > 1]
        if unusual_protocols:
            threats.append({
                'type': 'Unusual Protocols',
                'protocols': unusual_protocols,
                'severity': 'Low'
            })
        
        # Look for connections with high traffic volume
        high_volume = []
        avg_bytes = sum(conn['bytes'] for conn in self.connections.values()) / len(self.connections) if self.connections else 0
        for conn_key, details in self.connections.items():
            if details['bytes'] > avg_bytes * 5:  # 5 times the average
                src, dst = conn_key.split('<->')
                high_volume.append({
                    'connection': conn_key,
                    'bytes': format_bytes(details['bytes']),
                    'packets': details['packets']
                })
        
        if high_volume:
            threats.append({
                'type': 'High Volume Traffic',
                'connections': high_volume,
                'severity': 'Medium'
            })
        
        return threats
    
    def get_connection_details(self):
        """Return detailed information about active connections."""
        detailed_connections = []
        
        for conn_key, details in self.connections.items():
            src, dst = conn_key.split('<->')
            src_ip, src_port = src.split(':')
            dst_ip, dst_port = dst.split(':')
            
            duration = details['last_time'] - details['start_time'] if details['start_time'] and details['last_time'] else 0
            
            conn_details = {
                'source': {
                    'ip': src_ip,
                    'hostname': resolve_hostname(src_ip),
                    'port': src_port
                },
                'destination': {
                    'ip': dst_ip,
                    'hostname': resolve_hostname(dst_ip),
                    'port': dst_port
                },
                'statistics': {
                    'bytes': format_bytes(details['bytes']),
                    'packets': details['packets'],
                    'duration': f"{duration:.2f}s",
                    'bytes_per_sec': format_bytes(details['bytes'] / duration if duration > 0 else 0) + "/s"
                }
            }
            
            detailed_connections.append(conn_details)
        
        return detailed_connections
    
    def get_export_data(self):
        """Prepare data for export to CSV or other formats."""
        data = []
        
        # Connection data
        for conn_key, details in self.connections.items():
            src, dst = conn_key.split('<->')
            src_ip, src_port = src.split(':')
            dst_ip, dst_port = dst.split(':')
            
            data.append({
                'connection': conn_key,
                'source_ip': src_ip,
                'source_port': src_port,
                'destination_ip': dst_ip,
                'destination_port': dst_port,
                'bytes': details['bytes'],
                'packets': details['packets'],
                'start_time': details['start_time'],
                'last_time': details['last_time'],
                'duration': details['last_time'] - details['start_time'] if details['start_time'] and details['last_time'] else 0
            })
        
        return data 