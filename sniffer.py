# Import scapy which is the powerful library we use to capture network packets
import scapy.all as scapy
# Import our custom rule-based detector module
import detector
# Import our custom machine learning classifier module
import ml_classifier
# Import our central alert logger to save and send alerts
import alert_logger
# Import threading to safely update our statistics when multiple packets arrive
import threading

# Create a dictionary to hold running statistics about the sniffer's performance
stats = {
    'packets_captured': 0,
    'alerts_generated': 0,
    'is_running': False,
    'interface': 'eth0'
}

# Create a lock to ensure thread safety when updating the stats dictionary
stats_lock = threading.Lock()

# Define a function to simplify the packet data into 41 numbers for the ML model
def build_features(packet, protocol):
    # Create a list of exactly 41 zeros, which is what the ML model expects by default
    features = [0] * 41
    
    # Feature 0: Duration (we set to 0 for single packet analysis as a simplification)
    features[0] = 0
    
    # Feature 1: Protocol Type (mapped to simple numbers for the ML model)
    if protocol == 'TCP':
        # TCP gets number 1
        features[1] = 1
    elif protocol == 'UDP':
        # UDP gets number 2
        features[1] = 2
    elif protocol == 'ICMP':
        # ICMP gets number 3
        features[1] = 3
    else:
        # Unknown protocols get 0
        features[1] = 0
        
    # Feature 4: Source Bytes (the total length of the packet in bytes)
    # We use len(packet) to get the size
    features[4] = len(packet)
    
    # Return the completed 41-item list ready for the ML classifier
    return features

# Define the main function that runs every single time a packet is captured
def process_packet(packet):
    # Use the global keyword to modify the stats dictionary
    global stats
    
    # Safely lock the stats dictionary before modifying it
    with stats_lock:
        # Increment the total number of packets we've captured by 1
        stats['packets_captured'] += 1
        
    # Check if the packet has an IP layer (we skip non-IP traffic like ARP)
    if not packet.haslayer(scapy.IP):
        # Stop processing this packet and move to the next one
        return
        
    # Extract the Source IP address from the packet's IP layer
    src_ip = packet[scapy.IP].src
    
    # Setup default values for protocol, destination port, and flags
    protocol = 'Unknown'
    dst_port = None
    flags = None
    
    # Check if the packet is a TCP packet
    if packet.haslayer(scapy.TCP):
        # Set protocol name
        protocol = 'TCP'
        # Extract destination port
        dst_port = packet[scapy.TCP].dport
        # Extract TCP flags (like SYN, ACK, RST)
        flags = packet[scapy.TCP].flags
    # Check if the packet is a UDP packet
    elif packet.haslayer(scapy.UDP):
        # Set protocol name
        protocol = 'UDP'
        # Extract destination port
        dst_port = packet[scapy.UDP].dport
    # Check if the packet is an ICMP packet (like a ping)
    elif packet.haslayer(scapy.ICMP):
        # Set protocol name
        protocol = 'ICMP'
        
    # Track if our rule-based detector caught anything
    rule_alert_generated = False
    
    # PATH 1: Send packet info to our rule-based detector
    # It returns a list of alerts (might be empty)
    rule_alerts = detector.run_all_rules(src_ip, dst_port, flags, protocol)
    
    # Loop through any alerts returned by the detector
    if rule_alerts:
        for alert in rule_alerts:
            # Mark that a rule caught an attack so ML doesn't double-alert later
            rule_alert_generated = True
            
            # Send the alert to our logger to be saved and pushed to frontend
            alert_logger.generate_alert(
                alert['src_ip'], 
                alert['attack_type'], 
                alert['severity'], 
                alert['method'], 
                alert['detail']
            )
            
            # Safely lock the stats dictionary to update the alert count
            with stats_lock:
                # Increment the total alerts generated
                stats['alerts_generated'] += 1

    # PATH 2: Machine Learning Detection
    # Only run ML if the rules didn't already catch an attack
    if not rule_alert_generated:
        # Wrap ML in a try block so a math error never crashes the entire sniffer
        try:
            # Build the 41-number feature list for this packet
            features = build_features(packet, protocol)
            # Ask the ML model to classify the features
            prediction = ml_classifier.classify(features)
            
            # If the prediction is NOT 'normal' and NOT 'unknown'
            if prediction != 'normal' and prediction != 'unknown':
                # Generate an alert because the ML found something suspicious
                alert_logger.generate_alert(
                    src_ip, 
                    prediction, 
                    'Medium', # Default ML severity
                    'ML-Model', 
                    f'Confidence: {ml_classifier.get_confidence(features):.2f}'
                )
                
                # Safely update the stats
                with stats_lock:
                    # Increment the total alerts generated
                    stats['alerts_generated'] += 1
        # Catch any errors in the ML classification
        except Exception as e:
            # Silently ignore ML errors so sniffing continues without interruption
            pass

# Define the function to start the actual sniffing process
def start_sniffing(interface='eth0'):
    # Use the global keyword to modify the stats dictionary
    global stats
    
    # Safely lock the stats to update status
    with stats_lock:
        # Set the running flag to True
        stats['is_running'] = True
        # Store the name of the interface we are using
        stats['interface'] = interface
        
    # Print a message saying we are starting
    print(f"[INFO] Sniffer started on interface {interface}...")
    
    # Use a try block to handle user stopping the program (Ctrl+C)
    try:
        # Start Scapy sniff function!
        # iface: the network card to listen on
        # prn: the function to call for every single packet
        # store=False: CRITICAL! Do not save packets in memory or RAM will fill up!
        scapy.sniff(iface=interface, prn=process_packet, store=False)
    # Catch manual interruptions like Ctrl+C
    except KeyboardInterrupt:
        # Print a stopping message
        print("[INFO] Sniffer stopped by user.")
    # Catch any other errors (like wrong interface name or missing admin rights)
    except Exception as e:
        # Print the error
        print(f"[ERROR] Sniffer failed: {e}")
    # Finally block runs no matter what happens
    finally:
        # Safely update stats
        with stats_lock:
            # Mark the sniffer as stopped
            stats['is_running'] = False

# Define a simple function to get a copy of the current statistics
def get_stats():
    # Safely lock stats while reading
    with stats_lock:
        # Return a copy of the dictionary so external code can't accidentally break it
        return stats.copy()
