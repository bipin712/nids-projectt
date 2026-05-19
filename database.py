# Import the os module to handle file paths and directory creation safely
import os
# Import sqlite3, which is built into Python, to manage our local database file
import sqlite3
# Import the csv module to easily write our alerts to a comma-separated values file
import csv
# Import the datetime module so we can record exactly when each alert happened
from datetime import datetime

# Define the folder name where our logs will be stored
LOG_DIR = 'logs'
# Create the full path to the SQLite database file using os.path.join for Windows/Linux compatibility
DB_PATH = os.path.join(LOG_DIR, 'alerts.db')
# Create the full path to the CSV file using os.path.join
CSV_PATH = os.path.join(LOG_DIR, 'alerts.csv')

# Define a function to initialize the database and CSV file
def init_database():
    # Try block to safely handle any file system or database errors
    try:
        # Create the logs folder if it doesn't already exist (exist_ok=True prevents errors if it's there)
        os.makedirs(LOG_DIR, exist_ok=True)
        
        # Connect to the SQLite database file (it will be created if it doesn't exist)
        conn = sqlite3.connect(DB_PATH)
        # Create a cursor object which allows us to execute SQL commands
        cursor = conn.cursor()
        
        # Execute an SQL command to create the alerts table if it doesn't exist yet
        # It includes an auto-incrementing ID and all required columns
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                attack_type TEXT,
                severity TEXT,
                method TEXT,
                detail TEXT
            )
        ''')
        
        # Commit (save) the changes we just made to the database
        conn.commit()
        # Close the connection to the database to free up resources
        conn.close()
        
        # Now prepare the CSV file. Check if it already exists to decide if we need headers
        csv_exists = os.path.exists(CSV_PATH)
        # If the CSV file does not exist yet
        if not csv_exists:
            # Open the CSV file in write mode ('w') with newline='' to prevent blank lines in Windows
            with open(CSV_PATH, 'w', newline='') as f:
                # Create a CSV writer object
                writer = csv.writer(f)
                # Write the header row containing the column names
                writer.writerow(['timestamp', 'src_ip', 'attack_type', 'severity', 'method', 'detail'])
                
    # Catch any unexpected errors that occur during initialization
    except Exception as e:
        # Print a clear error message to the terminal
        print(f"[ERROR] Failed to initialize database: {e}")

# Define a function to save an alert to both the database and the CSV file
def save_alert(src_ip, attack_type, severity, method, detail):
    # Get the current date and time as a nicely formatted string
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Try block to safely handle database/file writing operations
    try:
        # Make sure the logs directory exists before we try to write to it
        os.makedirs(LOG_DIR, exist_ok=True)
        
        # Connect to the SQLite database file
        conn = sqlite3.connect(DB_PATH)
        # Create a cursor to execute SQL
        cursor = conn.cursor()
        
        # Execute an SQL command to insert a new row into the alerts table
        # We use ? as placeholders to safely insert our variables and prevent SQL injection
        cursor.execute('''
            INSERT INTO alerts (timestamp, src_ip, attack_type, severity, method, detail)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (timestamp, src_ip, attack_type, severity, method, detail))
        
        # Get the ID of the newly inserted row to include in our return dictionary
        new_id = cursor.lastrowid
        
        # Commit the changes to save the new alert to the database
        conn.commit()
        # Close the database connection
        conn.close()
        
        # Now, open the CSV file in append mode ('a') to add a new line without deleting old ones
        with open(CSV_PATH, 'a', newline='') as f:
            # Create a CSV writer object
            writer = csv.writer(f)
            # Write a new row containing the alert data
            writer.writerow([timestamp, src_ip, attack_type, severity, method, detail])
            
        # Create a dictionary containing all the alert information, including the new ID
        alert_dict = {
            'id': new_id,
            'timestamp': timestamp,
            'src_ip': src_ip,
            'attack_type': attack_type,
            'severity': severity,
            'method': method,
            'detail': detail
        }
        # Return the dictionary so other parts of the program can use it
        return alert_dict
        
    # Catch any errors that happen while saving
    except Exception as e:
        # Print the error message
        print(f"[ERROR] Failed to save alert: {e}")
        # Return None to indicate the save failed
        return None

# Define a function to retrieve the most recent alerts from the database
def get_recent_alerts(limit=50):
    # Try block for safe database reading
    try:
        # Connect to the database
        conn = sqlite3.connect(DB_PATH)
        # Configure the connection to return rows as dictionaries instead of tuples
        conn.row_factory = sqlite3.Row
        # Create a cursor
        cursor = conn.cursor()
        
        # Execute an SQL command to select alerts, order them newest first (DESC), and limit the number
        cursor.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT ?', (limit,))
        # Fetch all the results from our query
        rows = cursor.fetchall()
        # Close the connection
        conn.close()
        
        # Convert the results into a normal Python list of dictionaries and return it
        return [dict(row) for row in rows]
        
    # Catch any errors during reading
    except Exception as e:
        # Print the error message
        print(f"[ERROR] Failed to fetch recent alerts: {e}")
        # Return an empty list if something goes wrong
        return []

# Define a function to calculate statistics about the alerts in the database
def get_alert_stats():
    # Initialize a dictionary to hold our statistics with default values of 0
    stats = {'total': 0, 'high': 0, 'medium': 0, 'low': 0}
    
    # Try block for safe database reading
    try:
        # Connect to the database
        conn = sqlite3.connect(DB_PATH)
        # Create a cursor
        cursor = conn.cursor()
        
        # Query to count the total number of alerts in the table
        cursor.execute('SELECT COUNT(*) FROM alerts')
        # Update the 'total' stat with the result
        stats['total'] = cursor.fetchone()[0]
        
        # Query to count the number of alerts where severity is 'High'
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'High'")
        # Update the 'high' stat with the result
        stats['high'] = cursor.fetchone()[0]
        
        # Query to count the number of alerts where severity is 'Medium'
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'Medium'")
        # Update the 'medium' stat with the result
        stats['medium'] = cursor.fetchone()[0]
        
        # Query to count the number of alerts where severity is 'Low'
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'Low'")
        # Update the 'low' stat with the result
        stats['low'] = cursor.fetchone()[0]
        
        # Close the database connection
        conn.close()
        
    # Catch any errors during calculation
    except Exception as e:
        # Print the error message
        print(f"[ERROR] Failed to calculate stats: {e}")
        
    # Return the stats dictionary (it will contain 0s if there was an error)
    return stats

# Define a function to delete all alerts from the database and clear the CSV
def clear_alerts():
    # Try block for safe deletion
    try:
        # Connect to the database
        conn = sqlite3.connect(DB_PATH)
        # Create a cursor
        cursor = conn.cursor()
        
        # Execute an SQL command to delete all rows from the alerts table
        cursor.execute('DELETE FROM alerts')
        
        # Commit the deletion to the database
        conn.commit()
        # Close the connection
        conn.close()
        
        # Now clear the CSV file by opening it in write mode ('w') which overwrites it completely
        with open(CSV_PATH, 'w', newline='') as f:
            # Create a CSV writer
            writer = csv.writer(f)
            # Write just the header row back into the file
            writer.writerow(['timestamp', 'src_ip', 'attack_type', 'severity', 'method', 'detail'])
            
    # Catch any errors during clearing
    except Exception as e:
        # Print the error message
        print(f"[ERROR] Failed to clear alerts: {e}")
