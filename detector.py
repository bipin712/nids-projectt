# Import defaultdict from collections to easily create dictionaries with default values (like lists)
from collections import defaultdict
# Import time module to get current timestamps for tracking packet rates over time
import time

# Create a dictionary to track timestamps of packets for DoS detection, grouped by source IP
_dos_tracker = defaultdict(list)
# Create a dictionary to track unique destination ports accessed by a source IP over time
_port_scan_tracker = defaultdict(lambda: defaultdict(list))
# Create a dictionary to track timestamps of SYN packets for SYN Flood detection, grouped by source IP
_syn_tracker = defaultdict(list)
# Create a dictionary to track timestamps of ICMP packets for ICMP Flood detection, grouped by source IP
_icmp_tracker = defaultdict(list)
# Create a dictionary to track timestamps of RST packets for Brute Force detection, grouped by source IP
_brute_force_tracker = defaultdict(list)

# Define a helper function to clean up old timestamps that are outside our time window
def _clean(timestamps, window):
    # Get the current time in seconds since the epoch
    current_time = time.time()
    # Calculate the cutoff time; anything before this time is too old and should be removed
    cutoff = current_time - window
    # Keep only the timestamps that are greater than the cutoff time, using list comprehension
    return [ts for ts in timestamps if ts > cutoff]

# Define a function to check for DoS attacks (more than 100 packets/sec from same IP)
def check_dos(src_ip):
    # Set the time window to 1 second for DoS detection
    window = 1
    # Set the threshold to 100 packets
    threshold = 100
    # Clean old timestamps from the tracker for this specific source IP
    _dos_tracker[src_ip] = _clean(_dos_tracker[src_ip], window)
    # Add the current timestamp to the tracker since we just received a packet from this IP
    _dos_tracker[src_ip].append(time.time())
    
    # Check if the number of packets in the last second exceeds our threshold
    if len(_dos_tracker[src_ip]) > threshold:
        # If threshold exceeded, clear the tracker for this IP so we don't keep alerting for every single packet
        _dos_tracker[src_ip] = []
        # Return an alert dictionary with the attack details
        return {
            'src_ip': src_ip,
            'attack_type': 'DoS',
            'severity': 'High',
            'method': 'Rule-Based',
            'detail': f'More than {threshold} packets/sec'
        }
    # If threshold is not exceeded, return None meaning no attack detected
    return None

# Define a function to check for Port Scans (more than 20 unique ports in 10 seconds)
def check_port_scan(src_ip, dst_port):
    # If there is no destination port (e.g., for some ICMP packets), we can't check for a port scan
    if dst_port is None:
        # Return None meaning no attack detected
        return None
        
    # Set the time window to 10 seconds for Port Scan detection
    window = 10
    # Set the threshold to 20 unique ports
    threshold = 20
    # Get the current timestamp
    current_time = time.time()
    
    # Add the current timestamp to the list of accesses for this specific destination port by this source IP
    _port_scan_tracker[src_ip][dst_port].append(current_time)
    
    # Create a list to keep track of ports that have recent activity
    active_ports = []
    # Loop through all ports this source IP has accessed
    for port in list(_port_scan_tracker[src_ip].keys()):
        # Clean old timestamps for this port
        _port_scan_tracker[src_ip][port] = _clean(_port_scan_tracker[src_ip][port], window)
        # If the port still has recent timestamps after cleaning
        if len(_port_scan_tracker[src_ip][port]) > 0:
            # Add this port to our list of active ports
            active_ports.append(port)
        # If the port has no recent timestamps
        else:
            # Remove the port entirely from the tracker to save memory
            del _port_scan_tracker[src_ip][port]
            
    # Check if the number of unique active ports exceeds our threshold
    if len(active_ports) > threshold:
        # If threshold exceeded, clear the tracker for this IP so we don't keep alerting
        _port_scan_tracker[src_ip].clear()
        # Return an alert dictionary with the attack details
        return {
            'src_ip': src_ip,
            'attack_type': 'Port Scan',
            'severity': 'Medium',
            'method': 'Rule-Based',
            'detail': f'More than {threshold} unique ports in {window}s'
        }
    # If threshold is not exceeded, return None meaning no attack detected
    return None

# Define a function to check for SYN Floods (more than 200 SYN packets in 10 seconds)
def check_syn_flood(src_ip, flags, protocol):
    # SYN floods only apply to TCP traffic, and we need the flags to check for SYN
    if protocol != 'TCP' or flags is None:
        # Return None if it's not a TCP packet or flags are missing
        return None
        
    # Check if the 'S' (SYN) flag is present in the TCP flags (e.g., 'S', 'SA')
    if 'S' in str(flags):
        # Set the time window to 10 seconds
        window = 10
        # Set the threshold to 200 SYN packets
        threshold = 200
        # Clean old timestamps from the tracker for this source IP
        _syn_tracker[src_ip] = _clean(_syn_tracker[src_ip], window)
        # Add the current timestamp to the tracker
        _syn_tracker[src_ip].append(time.time())
        
        # Check if the number of SYN packets in the window exceeds our threshold
        if len(_syn_tracker[src_ip]) > threshold:
            # Clear the tracker to prevent duplicate alerts
            _syn_tracker[src_ip] = []
            # Return an alert dictionary with the attack details
            return {
                'src_ip': src_ip,
                'attack_type': 'SYN Flood',
                'severity': 'High',
                'method': 'Rule-Based',
                'detail': f'More than {threshold} SYN packets in {window}s'
            }
    # Return None meaning no attack detected
    return None

# Define a function to check for ICMP Floods (more than 50 ICMP packets in 5 seconds)
def check_icmp_flood(src_ip, protocol):
    # We only care about ICMP protocol packets for this check
    if protocol == 'ICMP':
        # Set the time window to 5 seconds
        window = 5
        # Set the threshold to 50 ICMP packets
        threshold = 50
        # Clean old timestamps from the tracker for this source IP
        _icmp_tracker[src_ip] = _clean(_icmp_tracker[src_ip], window)
        # Add the current timestamp to the tracker
        _icmp_tracker[src_ip].append(time.time())
        
        # Check if the number of ICMP packets in the window exceeds our threshold
        if len(_icmp_tracker[src_ip]) > threshold:
            # Clear the tracker to prevent duplicate alerts
            _icmp_tracker[src_ip] = []
            # Return an alert dictionary with the attack details
            return {
                'src_ip': src_ip,
                'attack_type': 'ICMP Flood',
                'severity': 'Medium',
                'method': 'Rule-Based',
                'detail': f'More than {threshold} ICMP packets in {window}s'
            }
    # Return None meaning no attack detected
    return None

# Define a function to check for Brute Force attacks (more than 5 RST packets in 30 seconds)
def check_brute_force(src_ip, flags, protocol):
    # Brute force (in this context) looks at TCP connection resets, so we check for TCP
    if protocol != 'TCP' or flags is None:
        # Return None if it's not a TCP packet or flags are missing
        return None
        
    # Check if the 'R' (RST) flag is present in the TCP flags, indicating a connection reset
    if 'R' in str(flags):
        # Set the time window to 30 seconds
        window = 30
        # Set the threshold to 5 RST packets
        threshold = 5
        # Clean old timestamps from the tracker for this source IP
        _brute_force_tracker[src_ip] = _clean(_brute_force_tracker[src_ip], window)
        # Add the current timestamp to the tracker
        _brute_force_tracker[src_ip].append(time.time())
        
        # Check if the number of RST packets in the window exceeds our threshold
        if len(_brute_force_tracker[src_ip]) > threshold:
            # Clear the tracker to prevent duplicate alerts
            _brute_force_tracker[src_ip] = []
            # Return an alert dictionary with the attack details
            return {
                'src_ip': src_ip,
                'attack_type': 'Brute Force',
                'severity': 'High',
                'method': 'Rule-Based',
                'detail': f'More than {threshold} RST packets in {window}s'
            }
    # Return None meaning no attack detected
    return None

# Define the master function that runs all 5 rules on every incoming packet
def run_all_rules(src_ip, dst_port, flags, protocol):
    # Create an empty list to store any alerts generated by the individual rules
    alerts = []
    
    # Run the DoS check and store the result
    dos_alert = check_dos(src_ip)
    # If the DoS check returned an alert (not None)
    if dos_alert:
        # Add the alert to our list of alerts
        alerts.append(dos_alert)
        
    # Run the Port Scan check and store the result
    port_scan_alert = check_port_scan(src_ip, dst_port)
    # If the Port Scan check returned an alert
    if port_scan_alert:
        # Add the alert to our list of alerts
        alerts.append(port_scan_alert)
        
    # Run the SYN Flood check and store the result
    syn_flood_alert = check_syn_flood(src_ip, flags, protocol)
    # If the SYN Flood check returned an alert
    if syn_flood_alert:
        # Add the alert to our list of alerts
        alerts.append(syn_flood_alert)
        
    # Run the ICMP Flood check and store the result
    icmp_flood_alert = check_icmp_flood(src_ip, protocol)
    # If the ICMP Flood check returned an alert
    if icmp_flood_alert:
        # Add the alert to our list of alerts
        alerts.append(icmp_flood_alert)
        
    # Run the Brute Force check and store the result
    brute_force_alert = check_brute_force(src_ip, flags, protocol)
    # If the Brute Force check returned an alert
    if brute_force_alert:
        # Add the alert to our list of alerts
        alerts.append(brute_force_alert)
        
    # Finally, return the list of all collected alerts (it could be empty if no attacks were found)
    return alerts
