import os
import sys
import datetime
import socket
import psutil
import colorama
from colorama import Fore, Style

# Initialize colorama for cross-platform colored terminal output
colorama.init()

def get_available_interfaces():
    """Return a list of available network interfaces."""
    interfaces = []
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    interfaces.append((iface, addr.address))
                    break
    except Exception as e:
        print(f"Error getting network interfaces: {e}")
    
    return interfaces

def check_privileges():
    """Check if the script is running with administrator/root privileges."""
    if os.name == 'nt':  # Windows
        try:
            return os.environ['ADMINISTRATOR'] == 'yes'
        except KeyError:
            return False
    else:  # Unix/Linux/MacOS
        return os.geteuid() == 0

def print_warning(message):
    """Print a warning message in yellow."""
    print(f"{Fore.YELLOW}{message}{Style.RESET_ALL}")

def print_error(message):
    """Print an error message in red."""
    print(f"{Fore.RED}{message}{Style.RESET_ALL}")

def print_success(message):
    """Print a success message in green."""
    print(f"{Fore.GREEN}{message}{Style.RESET_ALL}")

def print_info(message):
    """Print an info message in blue."""
    print(f"{Fore.BLUE}{message}{Style.RESET_ALL}")

def format_bytes(size):
    """Format byte size to human readable format."""
    power = 2**10
    n = 0
    units = {0: 'B', 1: 'KB', 2: 'MB', 3: 'GB', 4: 'TB'}
    while size > power and n <= 4:
        size /= power
        n += 1
    return f"{size:.2f} {units[n]}"

def get_timestamp():
    """Return current timestamp in a readable format."""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

def export_to_csv(data, filename="network_traffic.csv"):
    """Export data to CSV format."""
    try:
        import pandas as pd
        df = pd.DataFrame(data)
        df.to_csv(filename, index=False)
        return True
    except Exception as e:
        print_error(f"Error exporting to CSV: {e}")
        return False

def resolve_hostname(ip):
    """Resolve IP address to hostname."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return ip 