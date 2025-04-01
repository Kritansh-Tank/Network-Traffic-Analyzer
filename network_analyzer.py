#!/usr/bin/env python3
"""
Network Traffic Analyzer - Main Module

A powerful network traffic analyzer that captures and analyzes network packets,
providing detailed insights about network usage, protocols, and potential security issues.
"""

import argparse
import time
import sys
import signal
import os
from datetime import datetime

from packet_capture import PacketCapture
from packet_analyzer import PacketAnalyzer
from visualizer import TrafficVisualizer
from utils import (
    get_available_interfaces, 
    check_privileges, 
    print_info, 
    print_warning, 
    print_error, 
    print_success,
    export_to_csv
)

# Global variables for signal handling
running = True
capture = None
analyzer = None
visualizer = None

def signal_handler(sig, frame):
    """Handle interrupt signals."""
    global running
    print_info("\nStopping capture... (This may take a moment)")
    running = False

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description='Network Traffic Analyzer')
    
    parser.add_argument('--interface', '-i', type=str, help='Network interface to capture packets from')
    parser.add_argument('--time', '-t', type=int, help='Capture duration in seconds')
    parser.add_argument('--count', '-c', type=int, help='Number of packets to capture')
    parser.add_argument('--filter', '-f', type=str, help='BPF filter for packet capture')
    parser.add_argument('--export', '-e', type=str, choices=['csv'], help='Export format')
    parser.add_argument('--output', '-o', type=str, help='Output file name')
    parser.add_argument('--list-interfaces', '-l', action='store_true', help='List available network interfaces')
    parser.add_argument('--visualize', '-v', action='store_true', help='Generate visualizations')
    parser.add_argument('--dashboard', '-d', action='store_true', help='Generate a comprehensive dashboard')
    
    return parser.parse_args()

def list_interfaces():
    """List all available network interfaces."""
    print_info("Available network interfaces:")
    interfaces = get_available_interfaces()
    
    if not interfaces:
        print_warning("No interfaces found or permission denied.")
        return
    
    for i, (iface, ip) in enumerate(interfaces, 1):
        print(f"{i}. {iface} - {ip}")

def main():
    global running, capture, analyzer, visualizer
    
    # Register signal handler for graceful exit
    signal.signal(signal.SIGINT, signal_handler)
    
    # Parse command-line arguments
    args = parse_arguments()
    
    # Check if user just wants to list interfaces
    if args.list_interfaces:
        list_interfaces()
        return
    
    # Check for admin/root privileges
    if not check_privileges():
        print_warning("Warning: This program may need administrator/root privileges to capture packets.")
        print_warning("Try running with elevated privileges if you encounter permission errors.")
    
    # Initialize components
    capture = PacketCapture()
    analyzer = PacketAnalyzer()
    visualizer = TrafficVisualizer()
    
    # Set interface
    if args.interface:
        capture.set_interface(args.interface)
    
    # Set filter
    if args.filter:
        capture.set_filter(args.filter)
    
    # Setup packet processing callback
    def process_packet(packet):
        analyzer.process_packet(packet)
        visualizer.update_traffic_history(analyzer)
    
    capture.set_callback(process_packet)
    
    # Start packet capture
    print_info("Starting network traffic analyzer...")
    capture.start_capture(count=args.count, timeout=args.time)
    
    try:
        # Main capture loop
        refresh_interval = 1.0  # seconds
        last_refresh = time.time()
        refresh_count = 0
        
        while running and (capture.running or args.time is None):
            if args.time is None and args.count is None:
                # For continuous capture, show periodic updates
                current_time = time.time()
                if (current_time - last_refresh) >= refresh_interval:
                    refresh_count += 1
                    summary = analyzer.get_summary()
                    
                    # Clear screen and print summary
                    os.system('cls' if os.name == 'nt' else 'clear')
                    print_info(f"Network Traffic Analysis - Running for {summary['duration']}")
                    print_info(f"Packets: {summary['packet_count']} | Data: {summary['total_bytes']} | Rate: {summary['bytes_per_sec']}")
                    print_info(f"Active Connections: {summary['active_connections']} | Top Protocol: {next(iter(summary['protocols']), 'None')}")
                    print_info("Press Ctrl+C to stop capturing and view detailed results")
                    
                    last_refresh = current_time
            
            time.sleep(0.1)  # Reduce CPU usage
    
    except KeyboardInterrupt:
        pass  # Handle in signal_handler
    finally:
        # Stop capture
        if capture.running:
            packets = capture.stop_capture()
        
        # Final analysis
        summary = analyzer.get_summary()
        potential_threats = analyzer.get_potential_threats()
        connection_details = analyzer.get_connection_details()
        
        # Display results
        print_success("\n===== Network Traffic Analysis Results =====")
        print(f"Packets captured: {summary['packet_count']}")
        print(f"Capture duration: {summary['duration']}")
        print(f"Total data transferred: {summary['total_bytes']}")
        print(f"Data transfer rate: {summary['bytes_per_sec']}")
        
        print("\nProtocol Distribution:")
        for proto, count in summary['protocols'].items():
            print(f"  {proto}: {count} packets")
        
        print("\nTop Source IP Addresses:")
        for ip, count in summary['top_sources'].items():
            print(f"  {ip}: {count} packets")
        
        print("\nTop Destination IP Addresses:")
        for ip, count in summary['top_destinations'].items():
            print(f"  {ip}: {count} packets")
        
        print("\nTop Destination Ports:")
        for port, count in summary['top_destination_ports'].items():
            print(f"  {port}: {count} packets")
        
        # Display potential threats
        if potential_threats:
            print_warning("\nPotential Security Concerns:")
            for threat in potential_threats:
                print(f"  {threat['type']} - Severity: {threat['severity']}")
                if 'source_ip' in threat:
                    print(f"    Source: {threat['source_ip']}")
                if 'target_ports' in threat:
                    print(f"    Target Ports: {threat['target_ports']}")
        
        # Generate visualizations if requested
        if args.visualize:
            print_info("\nGenerating visualizations...")
            
            # Create output directory if it doesn't exist
            output_dir = "network_analysis_results"
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"{output_dir}_{timestamp}"
            
            try:
                if not os.path.exists(output_path):
                    os.makedirs(output_path)
                
                # Generate individual visualizations
                visualizer.plot_protocol_distribution(
                    analyzer.protocols, 
                    filename=f"{output_path}/protocol_distribution.png"
                )
                
                visualizer.plot_top_talkers(
                    analyzer.ip_src, 
                    title='Top Source IP Addresses', 
                    filename=f"{output_path}/top_sources.png"
                )
                
                visualizer.plot_top_talkers(
                    analyzer.ip_dst, 
                    title='Top Destination IP Addresses', 
                    filename=f"{output_path}/top_destinations.png"
                )
                
                visualizer.plot_port_activity(
                    analyzer.ports_dst, 
                    title='Top Destination Ports', 
                    filename=f"{output_path}/top_ports.png"
                )
                
                visualizer.plot_traffic_over_time(
                    filename=f"{output_path}/traffic_over_time.png"
                )
                
                visualizer.plot_connection_statistics(
                    connection_details, 
                    filename=f"{output_path}/connection_statistics.png"
                )
                
                print_success(f"Visualizations saved to {output_path}/")
            
            except Exception as e:
                print_error(f"Error generating visualizations: {e}")
        
        # Generate dashboard if requested
        if args.dashboard:
            try:
                dashboard_filename = args.output if args.output else "network_dashboard.png"
                visualizer.generate_dashboard(analyzer, filename=dashboard_filename)
                print_success(f"Dashboard saved as {dashboard_filename}")
            except Exception as e:
                print_error(f"Error generating dashboard: {e}")
        
        # Export data if requested
        if args.export == 'csv':
            try:
                export_filename = args.output if args.output else "network_traffic.csv"
                data = analyzer.get_export_data()
                if export_to_csv(data, export_filename):
                    print_success(f"Data exported to {export_filename}")
            except Exception as e:
                print_error(f"Error exporting data: {e}")

if __name__ == "__main__":
    main() 