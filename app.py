# Import the Flask class to create our web server
from flask import Flask, render_template, jsonify, request
# Import SocketIO to allow real-time communication between server and browser
from flask_socketio import SocketIO
# Import threading so we can run the sniffer in the background without freezing the web server
import threading
# Import os to handle file paths safely
import os

# Import all the backend modules we built in previous phases
import database      # For reading alerts from the database
import alert_logger  # For getting alert queue and stats
import sniffer       # For starting/stopping packet capture

# Create the main Flask application object
# __name__ tells Flask where to look for templates and static files
app = Flask(__name__)

# Set a secret key for Flask to securely sign session cookies
# This is required by Flask-SocketIO
app.config['SECRET_KEY'] = 'nids_secret_key_2024'

# Create the SocketIO object and attach it to our Flask app
# cors_allowed_origins='*' allows the browser to connect from any origin
socketio = SocketIO(app, cors_allowed_origins='*')

# -------------------------------------------------------------------
# CONNECT ALERT LOGGER TO WEBSOCKET (the push_callback pattern)
# We inject our WebSocket push function into alert_logger here.
# Now whenever an alert is generated, it automatically pushes to the browser!
# -------------------------------------------------------------------

# Define the function that will push a new alert to ALL connected browsers
def push_alert_to_browser(alert):
    # Use socketio.emit to send the alert as a 'new_alert' event to all clients
    socketio.emit('new_alert', alert)

# Inject our push function into alert_logger so it can use it
# Now alert_logger knows HOW to send data to the browser without importing Flask
alert_logger.push_callback = push_alert_to_browser

# -------------------------------------------------------------------
# INITIALIZE DATABASE
# -------------------------------------------------------------------

# Call init_database when app.py starts to make sure the database and CSV exist
database.init_database()

# -------------------------------------------------------------------
# PAGE ROUTES (serve HTML pages)
# -------------------------------------------------------------------

# Landing page route (shown when you open the server)
@app.route('/')
def landing():
    return render_template('landing.html')

# Route for the dashboard page
@app.route('/dashboard')
def dashboard_page():
    return render_template('index.html')


# Route for the live alerts page
@app.route('/alerts')
def alerts_page():
    # Render and return the alerts.html template
    return render_template('alerts.html')

# Route for the analysis/charts page
@app.route('/analysis')
def analysis_page():
    # Render and return the analysis.html template
    return render_template('analysis.html')

# Route for the ML model status page
@app.route('/ml_status')
def ml_status_page():
    # Render and return the ml_status.html template
    return render_template('ml_status.html')

# Route for the logs page
@app.route('/logs')
def logs_page():
    # Render and return the logs.html template
    return render_template('logs.html')

# Route for the settings page
@app.route('/settings')
def settings_page():
    # Render and return the settings.html template
    return render_template('settings.html')

# -------------------------------------------------------------------
# API ROUTES (return JSON data for the frontend JavaScript)
# -------------------------------------------------------------------

# API route to get recent alerts as JSON (used by the alerts page)
@app.route('/api/alerts')
def api_get_alerts():
    # Get the 'limit' parameter or 'n' parameter from the URL, defaulting to 50 if not provided
    limit = request.args.get('limit', type=int)
    if limit is None:
        limit = request.args.get('n', 50, type=int)
    # Fetch recent alerts from the alert_logger's fast memory queue
    recent = alert_logger.get_recent(limit)
    # Return the alerts as a JSON response so JavaScript can read them
    return jsonify({'status': 'ok', 'alerts': recent})

# API route to get alert statistics as JSON (used by the dashboard)
@app.route('/api/stats')
def api_get_stats():
    # Get stats from alert_logger (which calls the database internally)
    stats = alert_logger.get_stats()
    # Also get the sniffer stats (packets captured, is it running, etc.)
    sniffer_stats = sniffer.get_stats()
    # Combine both dictionaries and return them as JSON
    return jsonify({'status': 'ok', 'alert_stats': stats, 'sniffer_stats': sniffer_stats})

# API route to start the network sniffer
@app.route('/api/sniffer/start', methods=['POST'])
def api_start_sniffer():
    # Get the interface name from the JSON body of the request, defaulting to 'eth0'
    data = request.get_json() or {}
    # Read the interface key from the JSON body, use 'eth0' if not provided
    interface = data.get('interface', 'eth0')
    
    # Check if the sniffer is already running to avoid starting it twice
    if sniffer.get_stats()['is_running']:
        # Return a message saying it's already active
        return jsonify({'status': 'already_running', 'message': 'Sniffer is already running'})
    
    # Create a new background thread to run the sniffer so it doesn't block the web server
    # daemon=True means the thread will automatically stop when the main program exits
    sniffer_thread = threading.Thread(target=sniffer.start_sniffing, args=(interface,), daemon=True)
    # Start the thread
    sniffer_thread.start()
    # Return a success message
    return jsonify({'status': 'ok', 'message': f'Sniffer started on {interface}'})

# API route to check the sniffer status
@app.route('/api/sniffer/status')
def api_sniffer_status():
    # Get and return the current sniffer stats as JSON
    return jsonify({'status': 'ok', 'sniffer': sniffer.get_stats()})

# API route to clear all alerts from the database and memory queue
@app.route('/api/alerts/clear', methods=['POST'])
def api_clear_alerts():
    # Call the database clear function to wipe the database and CSV
    database.clear_alerts()
    # Also clear the in-memory queue in alert_logger
    alert_logger.clear_queue()
    # Return a success message
    return jsonify({'status': 'ok', 'message': 'All alerts cleared'})

# API route to download all alerts as a CSV file
@app.route('/api/alerts/download')
def api_download_alerts():
    # Import send_file so Flask can send a file as a download to the browser
    from flask import send_file
    # Build the path to the CSV file using os.path.join so it works on all operating systems
    csv_path = os.path.join('logs', 'alerts.csv')
    # Check if the CSV file actually exists before trying to send it
    if not os.path.exists(csv_path):
        # If file does not exist, return an error message as JSON
        return jsonify({'status': 'error', 'message': 'No alerts CSV found. Generate some alerts first.'})
    # Send the CSV file to the browser as a downloadable attachment
    # as_attachment=True tells the browser to download it instead of displaying it
    # download_name sets the filename that appears in the browser's save dialog
    return send_file(csv_path, as_attachment=True, download_name='alerts.csv')

# API route to generate a manual test alert inside the running server process
@app.route('/api/test_alert')
def api_test_alert():
    # Call generate_alert inside the alert_logger to trigger the WebSocket push and queue insert
    alert = alert_logger.generate_alert('192.168.1.99', 'DoS', 'High', 'Rule-Based', 'Manual Test Alert')
    # Return a success message with the alert details
    return jsonify({'status': 'ok', 'alert': alert})

# API route to get the ML model status and information
@app.route('/api/ml-status')
def api_ml_status():
    # Import the ml_classifier module to read model info
    import ml_classifier
    # Check if the ML model is loaded and ready
    ready = ml_classifier.is_ready()
    # Build a response dictionary with all model information
    result = {
        # Whether the model file was loaded successfully
        'ml_ready': ready,
        # The machine learning algorithm used
        'algorithm': 'Random Forest',
        # The dataset used for training
        'dataset': 'NSL-KDD (148,517 combined records)',
        # The accuracy achieved on test data
        'accuracy': '99%',
        # The number of decision trees in the Random Forest
        'trees': 200,
        # The list of attack classes the model can detect
        'classes': ['normal', 'dos', 'probe', 'r2l', 'u2r']
    }
    # Return the result as JSON so the frontend JavaScript can read it
    return jsonify(result)

# -------------------------------------------------------------------
# WEBSOCKET EVENTS
# -------------------------------------------------------------------

# Handle when a browser client successfully connects to the WebSocket
@socketio.on('connect')
def on_connect():
    # Print a message to the terminal
    print('[WS] A browser client connected')
    # Send the current stats immediately to the newly connected client
    socketio.emit('stats_update', alert_logger.get_stats())

# Handle when a browser client disconnects from the WebSocket
@socketio.on('disconnect')
def on_disconnect():
    # Print a message to the terminal
    print('[WS] A browser client disconnected')

# Handle a 'request_stats' event sent by the browser to get a fresh update
@socketio.on('request_stats')
def on_request_stats():
    # Send the latest stats back to the client who asked
    socketio.emit('stats_update', alert_logger.get_stats())

# -------------------------------------------------------------------
# START THE SERVER
# -------------------------------------------------------------------

# This block runs only when we execute this file directly (not when imported)
if __name__ == '__main__':
    # Print a startup banner so we know the server is running
    print("=" * 50)
    print("  NIDS — Network Intrusion Detection System")
    print("  Server starting on http://0.0.0.0:5000")
    print("  Open your browser at: http://localhost:5000")
    print("=" * 50)
    # Start the Flask-SocketIO server
    # host='0.0.0.0' means accept connections from any device on the network
    # port=5000 is the standard Flask port
    # debug=False for production/Kali use (set to True for development)
    # use_reloader=False prevents the server from restarting twice on Kali
    # NOTE: On Windows, eventlet can cause WinError 10048 if the port/address is already in use
    # or if the selected async mode/engine reuses sockets. Force a safer default for this environment.
    socketio.run(app, host='127.0.0.1', port=5000, debug=False, use_reloader=False, allow_unsafe_werkzeug=True)
