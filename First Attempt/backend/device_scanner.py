# device_scanner.py
import socket
import json
import sys
import argparse
import subprocess
import re
import time # Import the time module

def is_valid_ipv4(ip):
    """Checks if the string is a valid IPv4 address."""
    pattern = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
    if pattern.match(ip):
        parts = list(map(int, ip.split('.')))
        return all(0 <= part <= 255 for part in parts)
    return False

def is_valid_hostname(hostname):
    """Checks if the string is a basic valid hostname."""
    # Hostnames can contain letters, numbers, hyphens, and periods.
    # Cannot start or end with a hyphen.
    # Max length for a label is 63, total hostname 255.
    if len(hostname) > 255:
        return False
    if hostname.endswith('.') or hostname.startswith('-'):
        return False
    if ' ' in hostname: # No spaces allowed
        return False
    # Basic check for valid characters (alphanumeric, hyphen, period)
    if not re.match(r"^[a-zA-Z0-9.-]+$", hostname):
        return False
    return True

def scan_port(target_host, port, timeout=1):
    """
    Attempts to connect to a specific port on a target host.
    Returns True if the port is open, False otherwise.
    """
    try:
        # Create a socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout) # Set a timeout for the connection attempt

        # Attempt to connect to the target host and port
        result = sock.connect_ex((target_host, port))
        sock.close() # Close the socket

        if result == 0:
            try:
                # Attempt to get service name for open ports
                service_name = socket.getservbyport(port)
            except OSError:
                service_name = "unknown"
            return {"status": True, "service": service_name} # Port is open
        else:
            return {"status": False, "service": None} # Port is closed or filtered
    except socket.gaierror:
        return {"error": f"Hostname '{target_host}' could not be resolved."}
    except socket.error as e:
        return {"error": f"Could not connect to '{target_host}': {e}"}
    except Exception as e:
        return {"error": f"An unexpected error occurred during port scan: {str(e)}"}

def perform_port_scan(target_host, port_range_str, port_timeout=1): # ADDED port_timeout parameter
    """
    Performs a port scan on the target host for the specified port range.
    Port range format: "start-end", "single_port", or "comma_separated_list" (e.g., "80,443,22").
    """
    results = {
        "target": target_host,
        "open_ports": [],
        "closed_ports": [],
        "error": None,
        "message": ""
    }

    if not (is_valid_ipv4(target_host) or is_valid_hostname(target_host)):
        results["error"] = "Invalid target IP address or hostname format."
        return results

    ports_to_scan = []
    try:
        if ',' in port_range_str:
            # Handle comma-separated list of ports
            for p in port_range_str.split(','):
                port = int(p.strip())
                if not (1 <= port <= 65535):
                    results["error"] = f"Invalid port number: {port}. Ports must be between 1 and 65535."
                    return results
                ports_to_scan.append(port)
        elif '-' in port_range_str:
            # Handle port range "start-end"
            start_port, end_port = map(int, port_range_str.split('-'))
            if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port):
                results["error"] = "Invalid port range. Ports must be between 1 and 65535, and start port must be less than or equal to end port."
                return results
            ports_to_scan = range(start_port, end_port + 1)
        else:
            # Handle single port
            single_port = int(port_range_str)
            if not (1 <= single_port <= 65535):
                results["error"] = "Invalid single port. Port must be between 1 and 65535."
                return results
            ports_to_scan = [single_port]

    except ValueError:
        results["error"] = "Invalid port or port range format. Use 'start-end', 'single_port', or 'comma_separated_list'."
        return results
    except Exception as e:
        results["error"] = f"An unexpected error occurred during port parsing: {str(e)}"
        return results

    if not ports_to_scan:
        results["error"] = "No valid ports to scan were provided."
        return results

    print(f"Starting port scan for {target_host} on ports: {ports_to_scan}", file=sys.stderr)

    for port in ports_to_scan:
        status_info = scan_port(target_host, port, timeout=port_timeout) # PASSED port_timeout
        if isinstance(status_info, dict) and "error" in status_info:
            results["error"] = status_info["error"]
            results["message"] = f"Port scan aborted due to error: {status_info['error']}"
            return results # Return immediately on resolution or connection error
        elif status_info["status"]:
            results["open_ports"].append({"port": port, "service": status_info["service"]})
            print(f"Port {port} ({status_info['service']}) is OPEN", file=sys.stderr)
        else:
            results["closed_ports"].append(port)
            # print(f"Port {port} is CLOSED", file=sys.stderr) # Suppress for clean stderr

    if not results["open_ports"] and not results["error"]:
        results["message"] = "No open ports found in the scanned range."
    elif results["open_ports"]:
        results["message"] = f"Found {len(results['open_ports'])} open ports."

    return results

def discover_network_hosts(network_prefix, overall_timeout=240): # Default to 4 minutes (240 seconds)
    """
    Performs a basic network discovery by pinging hosts in a given range.
    Includes an overall timeout for the entire scanning process.
    """
    results = {
        "target_range": network_prefix + "1-254",
        "active_hosts": [],
        "error": None,
        "message": ""
    }

    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.$", network_prefix):
        results["error"] = "Invalid network prefix format. Expected 'X.X.X.' (e.g., 192.168.1.)."
        return results

    print(f"Starting network discovery for {network_prefix}1-254...", file=sys.stderr)

    individual_ping_wait_time = 0.2 # Small timeout for each individual ping
    start_time = time.time() # Record the start time

    for i in range(1, 255):
        # Check if overall timeout has been reached
        if time.time() - start_time > overall_timeout:
            results["message"] = f"Network discovery stopped after {overall_timeout} seconds due to timeout."
            print(f"Overall network discovery timeout reached after {overall_timeout} seconds.", file=sys.stderr)
            break # Exit the loop

        ip = f"{network_prefix}{i}"
        try:
            ping_command = ['ping', '-c', '1', '-W', str(individual_ping_wait_time), ip]
            
            # The timeout here is for the individual subprocess call, not the overall script
            process = subprocess.run(ping_command, capture_output=True, text=True, timeout=individual_ping_wait_time + 0.1)

            if process.returncode == 0 and "bytes from" in process.stdout:
                results["active_hosts"].append(ip)
                print(f"Found active host: {ip}", file=sys.stderr)
            else:
                pass # Suppress output for inactive hosts
        except subprocess.TimeoutExpired:
            pass # Individual ping timed out, which is fine
        except Exception as e:
            results["error"] = f"Error pinging {ip}: {str(e)}"
            print(f"Error pinging {ip}: {str(e)}", file=sys.stderr)
            # Continue to next IP even if one fails

    if not results["active_hosts"] and not results["error"] and not results["message"]:
        results["message"] = "No active hosts found in the specified range."
    elif results["active_hosts"] and not results["message"]:
        results["message"] = f"Found {len(results['active_hosts'])} active hosts."

    return results

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Custom Device Scanning Tool")
    parser.add_argument('action', choices=['port_scan', 'network_discovery'], help="Action to perform: port_scan or network_discovery")
    parser.add_argument('target', help="Target IP/Hostname for port_scan or Network Prefix (e.g., 192.168.1.) for network_discovery")
    parser.add_argument('--ports', help="Port or port range (e.g., '80' or '1-1024' or '22,80,443') for port_scan")
    # This timeout is for the overall script execution, passed from Flask
    parser.add_argument('--timeout', type=int, default=240, help="Overall script execution timeout in seconds (default: 240 for 4 minutes)")
    # ADDED: Argument for individual port timeout
    parser.add_argument('--port-timeout', type=int, default=1, help='Timeout for individual port connections in seconds (default: 1)')

    args = parser.parse_args()

    output = {}
    if args.action == 'port_scan':
        if not args.ports:
            output = {"error": "Port or port range is required for port_scan."}
        else:
            # Pass the port_timeout argument
            output = perform_port_scan(args.target, args.ports, args.port_timeout)
    elif args.action == 'network_discovery':
        # Pass the overall script execution timeout here
        output = discover_network_hosts(args.target, args.timeout)

    print(json.dumps(output, indent=2))
