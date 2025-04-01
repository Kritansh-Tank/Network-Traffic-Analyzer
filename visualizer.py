import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from collections import defaultdict
import time
import numpy as np
from utils import format_bytes

class TrafficVisualizer:
    """
    Class to create visual representations of network traffic data.
    """
    
    def __init__(self):
        # Configure plot style
        plt.style.use('ggplot')
        self.colors = plt.cm.tab10.colors
        
        # Traffic history for time-series plots
        self.traffic_history = defaultdict(list)
        self.time_points = []
        self.last_time = None
        self.start_time = None
    
    def update_traffic_history(self, analyzer, interval=1.0):
        """
        Update traffic history for time-series plots.
        
        Args:
            analyzer: PacketAnalyzer instance with current statistics
            interval: Time interval in seconds between updates
        """
        current_time = time.time()
        
        if self.start_time is None:
            self.start_time = current_time
            
        if self.last_time is None or (current_time - self.last_time) >= interval:
            elapsed = current_time - self.start_time
            self.time_points.append(elapsed)
            
            # Add protocol counts
            for proto, count in analyzer.protocols.items():
                self.traffic_history[f'proto_{proto}'].append(count)
            
            # Add total bytes
            self.traffic_history['total_bytes'].append(analyzer.total_bytes)
            
            # Add packet count
            self.traffic_history['packet_count'].append(analyzer.packet_count)
            
            self.last_time = current_time
    
    def plot_protocol_distribution(self, protocols, title='Protocol Distribution', filename=None):
        """
        Create a pie chart showing protocol distribution.
        
        Args:
            protocols: Dict of protocol counts (e.g., analyzer.protocols)
            title: Plot title
            filename: If provided, saves the plot to this filename
        """
        # Get top 5 protocols, combine others
        top_n = 5
        sorted_protocols = sorted(protocols.items(), key=lambda x: x[1], reverse=True)
        
        if len(sorted_protocols) > top_n:
            top_protocols = sorted_protocols[:top_n]
            other_count = sum(count for _, count in sorted_protocols[top_n:])
            if other_count > 0:
                top_protocols.append(('Other', other_count))
        else:
            top_protocols = sorted_protocols
        
        labels = [f"{proto} ({count})" for proto, count in top_protocols]
        sizes = [count for _, count in top_protocols]
        
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=self.colors)
        ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
        ax.set_title(title)
        
        if filename:
            plt.savefig(filename, dpi=300, bbox_inches='tight')
            plt.close()
        else:
            plt.tight_layout()
            plt.show()
    
    def plot_top_talkers(self, ip_counts, title='Top IP Addresses', filename=None):
        """
        Create a bar chart showing the top IP addresses.
        
        Args:
            ip_counts: Counter object with IP addresses (e.g., analyzer.ip_src)
            title: Plot title
            filename: If provided, saves the plot to this filename
        """
        # Get top 10 IPs
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        ips = [ip for ip, _ in top_ips]
        counts = [count for _, count in top_ips]
        
        fig, ax = plt.subplots(figsize=(12, 6))
        bars = ax.barh(ips, counts, color=self.colors)
        
        # Add count labels to the right of each bar
        for bar in bars:
            width = bar.get_width()
            ax.text(width + 0.5, bar.get_y() + bar.get_height()/2, 
                    f'{int(width)}', ha='left', va='center')
        
        ax.set_xlabel('Packet Count')
        ax.set_title(title)
        ax.invert_yaxis()  # Invert y-axis to show highest count at the top
        
        if filename:
            plt.savefig(filename, dpi=300, bbox_inches='tight')
            plt.close()
        else:
            plt.tight_layout()
            plt.show()
    
    def plot_traffic_over_time(self, title='Network Traffic Over Time', filename=None):
        """
        Create a time-series plot of network traffic.
        
        Args:
            title: Plot title
            filename: If provided, saves the plot to this filename
        """
        if not self.time_points:
            return  # No data to plot
        
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8), sharex=True)
        
        # Plot bytes over time
        bytes_data = self.traffic_history['total_bytes']
        if bytes_data:
            # Convert to MB for better readability
            mb_data = [b / (1024*1024) for b in bytes_data]
            ax1.plot(self.time_points, mb_data, 'b-', label='Total Traffic')
            ax1.set_ylabel('Traffic (MB)')
            ax1.set_title(f'{title} - Cumulative Data')
            ax1.legend()
            
            # Calculate traffic rate
            if len(self.time_points) > 1:
                rates = []
                for i in range(1, len(self.time_points)):
                    time_diff = self.time_points[i] - self.time_points[i-1]
                    byte_diff = bytes_data[i] - bytes_data[i-1]
                    if time_diff > 0:
                        # Convert to KB/s
                        rate = (byte_diff / time_diff) / 1024
                        rates.append(rate)
                    else:
                        rates.append(0)
                
                rate_times = self.time_points[1:]
                ax2.plot(rate_times, rates, 'r-', label='Traffic Rate')
                ax2.set_ylabel('Rate (KB/s)')
                ax2.set_xlabel('Time (seconds)')
                ax2.set_title('Traffic Rate')
                ax2.legend()
        
        if filename:
            plt.savefig(filename, dpi=300, bbox_inches='tight')
            plt.close()
        else:
            plt.tight_layout()
            plt.show()
    
    def plot_port_activity(self, port_counts, title='Top Ports', filename=None):
        """
        Create a bar chart showing the most active ports.
        
        Args:
            port_counts: Counter object with port counts
            title: Plot title
            filename: If provided, saves the plot to this filename
        """
        # Get top 10 ports
        top_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        ports = [str(port) for port, _ in top_ports]
        counts = [count for _, count in top_ports]
        
        fig, ax = plt.subplots(figsize=(12, 6))
        bars = ax.barh(ports, counts, color=self.colors)
        
        # Add count labels
        for bar in bars:
            width = bar.get_width()
            ax.text(width + 0.5, bar.get_y() + bar.get_height()/2, 
                    f'{int(width)}', ha='left', va='center')
        
        ax.set_xlabel('Packet Count')
        ax.set_title(title)
        ax.invert_yaxis()  # Invert y-axis to show highest count at the top
        
        if filename:
            plt.savefig(filename, dpi=300, bbox_inches='tight')
            plt.close()
        else:
            plt.tight_layout()
            plt.show()
    
    def plot_connection_statistics(self, connections, title='Connection Statistics', filename=None):
        """
        Create visualizations for connection statistics.
        
        Args:
            connections: List of connection details
            title: Plot title
            filename: If provided, saves the plot to this filename
        """
        if not connections:
            return  # No data to plot
        
        # Extract duration and bytes from connections
        durations = []
        bytes_values = []
        packet_counts = []
        labels = []
        
        for i, conn in enumerate(connections):
            stats = conn['statistics']
            # Convert formatted byte string back to numeric
            bytes_str = stats['bytes'].split(' ')[0]
            try:
                bytes_val = float(bytes_str)
                unit = stats['bytes'].split(' ')[1]
                if unit == 'KB':
                    bytes_val *= 1024
                elif unit == 'MB':
                    bytes_val *= 1024 * 1024
                elif unit == 'GB':
                    bytes_val *= 1024 * 1024 * 1024
            except:
                bytes_val = 0
            
            # Convert duration string to numeric
            try:
                duration = float(stats['duration'].replace('s', ''))
            except:
                duration = 0
            
            durations.append(duration)
            bytes_values.append(bytes_val)
            packet_counts.append(stats['packets'])
            
            # Create a label for the connection
            src = f"{conn['source']['ip']}:{conn['source']['port']}"
            dst = f"{conn['destination']['ip']}:{conn['destination']['port']}"
            labels.append(f"Conn {i+1}: {src} -> {dst}")
        
        # Create a scatter plot of duration vs. bytes
        fig, ax = plt.subplots(figsize=(12, 8))
        
        # Normalize sizes for scatter plot
        if packet_counts:
            sizes = [50 * (count / max(packet_counts)) for count in packet_counts]
        else:
            sizes = [50] * len(durations)
        
        scatter = ax.scatter(durations, bytes_values, s=sizes, alpha=0.6, 
                            c=range(len(durations)), cmap='viridis')
        
        # Add labels for notable points
        if len(durations) > 0:
            # Find top 3 connections by byte volume
            top_indices = sorted(range(len(bytes_values)), key=lambda i: bytes_values[i], reverse=True)[:3]
            
            for idx in top_indices:
                ax.annotate(labels[idx], 
                            (durations[idx], bytes_values[idx]),
                            textcoords="offset points",
                            xytext=(0, 10),
                            ha='center')
        
        ax.set_xlabel('Duration (seconds)')
        ax.set_ylabel('Data Transfer (bytes)')
        ax.set_title(f'{title} - Duration vs. Data Transfer')
        
        # Add logarithmic scale for better visualization
        if min([b for b in bytes_values if b > 0]) < max(bytes_values) / 100:
            ax.set_yscale('log')
        
        # Add colorbar as a legend
        if len(durations) > 1:
            cbar = plt.colorbar(scatter, ax=ax)
            cbar.set_label('Connection Index')
        
        if filename:
            plt.savefig(filename, dpi=300, bbox_inches='tight')
            plt.close()
        else:
            plt.tight_layout()
            plt.show()
    
    def generate_dashboard(self, analyzer, filename='network_dashboard.png'):
        """
        Create a comprehensive dashboard with multiple visualizations.
        
        Args:
            analyzer: PacketAnalyzer instance with traffic statistics
            filename: Filename to save dashboard image
        """
        fig = plt.figure(figsize=(16, 12))
        
        # Create a 2x2 grid of subplots
        gs = fig.add_gridspec(2, 2)
        
        # Protocol distribution (top left)
        ax1 = fig.add_subplot(gs[0, 0])
        self._plot_protocol_distribution_on_axis(ax1, analyzer.protocols)
        
        # Traffic overview (top right)
        ax2 = fig.add_subplot(gs[0, 1])
        self._plot_traffic_summary_on_axis(ax2, analyzer)
        
        # Top source IPs (bottom left)
        ax3 = fig.add_subplot(gs[1, 0])
        self._plot_top_ips_on_axis(ax3, analyzer.ip_src, 'Top Source IP Addresses')
        
        # Top destination ports (bottom right)
        ax4 = fig.add_subplot(gs[1, 1])
        self._plot_top_ports_on_axis(ax4, analyzer.ports_dst, 'Top Destination Ports')
        
        plt.suptitle('Network Traffic Analysis Dashboard', fontsize=16)
        plt.tight_layout()
        
        if filename:
            plt.savefig(filename, dpi=300, bbox_inches='tight')
            plt.close()
        else:
            plt.show()
    
    # Helper methods for dashboard generation
    def _plot_protocol_distribution_on_axis(self, ax, protocols):
        """Plot protocol distribution on the given axis."""
        # Get top protocols
        top_n = 5
        sorted_protocols = sorted(protocols.items(), key=lambda x: x[1], reverse=True)
        
        if len(sorted_protocols) > top_n:
            top_protocols = sorted_protocols[:top_n]
            other_count = sum(count for _, count in sorted_protocols[top_n:])
            if other_count > 0:
                top_protocols.append(('Other', other_count))
        else:
            top_protocols = sorted_protocols
        
        labels = [f"{proto}" for proto, _ in top_protocols]
        sizes = [count for _, count in top_protocols]
        
        ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=self.colors[:len(labels)])
        ax.axis('equal')
        ax.set_title('Protocol Distribution')
    
    def _plot_traffic_summary_on_axis(self, ax, analyzer):
        """Plot traffic summary statistics on the given axis."""
        summary = analyzer.get_summary()
        
        # Create a text-based summary
        text = f"""
        Traffic Summary:
        ----------------
        Packets: {summary['packet_count']}
        Duration: {summary['duration']}
        Total Data: {summary['total_bytes']}
        Data Rate: {summary['bytes_per_sec']}
        Active Connections: {summary['active_connections']}
        DNS Queries: {summary['dns_queries']}
        """
        
        ax.text(0.1, 0.5, text, fontsize=12, va='center', linespacing=1.5)
        ax.axis('off')
    
    def _plot_top_ips_on_axis(self, ax, ip_counts, title):
        """Plot top IP addresses on the given axis."""
        # Get top 5 IPs
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        ips = [ip for ip, _ in top_ips]
        counts = [count for _, count in top_ips]
        
        y_pos = range(len(ips))
        ax.barh(y_pos, counts, color=self.colors[:len(ips)])
        ax.set_yticks(y_pos)
        ax.set_yticklabels(ips)
        ax.invert_yaxis()
        ax.set_xlabel('Packet Count')
        ax.set_title(title)
    
    def _plot_top_ports_on_axis(self, ax, port_counts, title):
        """Plot top ports on the given axis."""
        # Get top 5 ports
        top_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        ports = [str(port) for port, _ in top_ports]
        counts = [count for _, count in top_ports]
        
        y_pos = range(len(ports))
        ax.barh(y_pos, counts, color=self.colors[:len(ports)])
        ax.set_yticks(y_pos)
        ax.set_yticklabels(ports)
        ax.invert_yaxis()
        ax.set_xlabel('Packet Count')
        ax.set_title(title) 