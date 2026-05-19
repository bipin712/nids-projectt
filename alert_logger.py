# Import threading module to ensure our memory queue is safe when multiple packets arrive at exactly the same time
import threading
# Import our custom database module to save alerts permanently
import database

# Create an empty list to act as our fast, in-memory queue for recent alerts
alert_queue = []
# Set a maximum size for the queue so it doesn't grow forever and use up all computer memory
MAX_QUEUE = 500

# Create a Lock object to prevent two different threads from modifying the queue at the exact same moment
lock = threading.Lock()

# Define a placeholder for a function that will push alerts to the frontend website
# We set it to None here; app.py will replace this with a real WebSocket function later
push_callback = None

# Define the main function to generate and process a new alert
def generate_alert(src_ip, attack_type, severity, method='Rule-Based', detail=''):
    # Step 1: Save the alert permanently to the SQLite database and CSV file
    # We call the save_alert function from our database module and store the returned dictionary
    saved_alert = database.save_alert(src_ip, attack_type, severity, method, detail)
    
    # If the database save failed for some reason, we use a basic dictionary as a fallback
    if saved_alert is None:
        # Create a fallback alert dictionary with the provided information
        saved_alert = {
            'src_ip': src_ip,
            'attack_type': attack_type,
            'severity': severity,
            'method': method,
            'detail': detail
        }
        
    # Step 2: Add the new alert to our fast in-memory queue
    # We use the 'with lock:' statement to safely lock the queue while we change it
    with lock:
        # Insert the new alert at the very beginning (index 0) of the list so newest is first
        alert_queue.insert(0, saved_alert)
        # Check if our queue has grown larger than the maximum allowed size
        if len(alert_queue) > MAX_QUEUE:
            # If it's too big, remove the oldest alert from the very end of the list
            alert_queue.pop()
            
    # Step 3: Print a clear message to the terminal so the user can see it happening live
    print(f"[ALERT] {attack_type} from {src_ip} — {severity}")
    
    # Step 4: Push the alert to the browser frontend if the callback has been set by app.py
    # Check if push_callback is a real function (not None)
    if push_callback is not None:
        # Use a try block because we don't want a WebSocket error to crash the whole detection system
        try:
            # Call the injected function to send the alert to the frontend
            push_callback(saved_alert)
        # Catch any errors that happen during the push
        except Exception as e:
            # Print a warning but keep the system running normally
            print(f"[WARNING] Failed to push alert via WebSocket: {e}")
            
    # Finally, return the alert dictionary back to whatever called this function
    return saved_alert

# Define a function to quickly get the most recent alerts from our fast memory queue
def get_recent(n=50):
    # Use the lock to safely read from the queue without it changing halfway through
    with lock:
        # Return a copy of the first 'n' items from the queue using list slicing
        return list(alert_queue[:n])

# Define a function to get the current statistics (totals, high, medium, low)
def get_stats():
    # We just ask our database module to calculate and return the stats for us
    return database.get_alert_stats()

# Define a function to empty the fast memory queue
def clear_queue():
    # Use the 'global' keyword so we can modify the module-level alert_queue variable
    global alert_queue
    # Use the lock to safely clear the queue
    with lock:
        # Replace the queue with a brand new, empty list
        alert_queue = []
