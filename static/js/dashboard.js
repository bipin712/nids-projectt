// Connects to the Socket.IO server and registers the event handlers for live updates
function connectWebSocket() { // Start of the connectWebSocket function
    // Establish a WebSocket connection to the backend server using the Socket.IO library
    const socket = io(); // Initialize socket connection
    // Listen for the 'initial_alerts' event sent by the server upon first connection
    socket.on('initial_alerts', function(alerts) { // Register handler for initial_alerts event
        // Populate the alerts table with the initial list of alerts received from the server
        populateAlertsTable(alerts); // Call populateAlertsTable function with alerts array
    }); // End of callback for 'initial_alerts'
    // Listen for the 'new_alert' event triggered when a new intrusion is detected
    socket.on('new_alert', function(alert) { // Register handler for new_alert event
        // Insert the newly received alert at the top of the alerts table
        addAlertToTop(alert); // Call addAlertToTop function with the new alert
        // Refresh the statistics cards to show the updated packet and alert counts
        updateStatsCards(); // Call updateStatsCards with no parameters to trigger a fetch
    }); // End of callback for 'new_alert'
    // Listen for the 'stats_update' event pushed by the server when statistics change
    socket.on('stats_update', function(stats) { // Register handler for stats_update event
        // Update the numbers in the statistics cards using the received stats object
        updateStatsCards(stats); // Call updateStatsCards function with the new stats
    }); // End of callback for 'stats_update'
} // End of the connectWebSocket function

// Clears and populates the alerts table with an array of alerts
function populateAlertsTable(alerts) { // Start of the populateAlertsTable function
    // Find the table body element where alerts are displayed in the DOM by its ID
    const tbody = document.getElementById('alerts-tbody'); // Retrieve the tbody element
    // If the table body element does not exist on this page, exit the function
    if (!tbody) return; // Guard clause to prevent errors
    // Clear all existing table rows from the table body
    tbody.innerHTML = ''; // Empty the inner HTML of the table body
    // Iterate through each alert object in the provided alerts array
    for (let i = 0; i < alerts.length; i++) { // Loop through the alerts array
        // Generate a new HTML table row element for the current alert object
        const row = createAlertRow(alerts[i]); // Call createAlertRow with current alert
        // Append the new table row element to the end of the table body
        tbody.appendChild(row); // Append the row to tbody
    } // End of loop
} // End of the populateAlertsTable function

// Adds a single new alert to the very top of the alerts table and highlights it
function addAlertToTop(alert) { // Start of the addAlertToTop function
    // Find the table body element where alerts are displayed in the DOM by its ID
    const tbody = document.getElementById('alerts-tbody'); // Retrieve the tbody element
    // If the table body element does not exist on this page, exit the function
    if (!tbody) return; // Guard clause to prevent errors
    // Create a new HTML table row element representing the alert details
    const row = createAlertRow(alert); // Call createAlertRow with the new alert
    // Add the CSS class 'new-row' to apply the green highlight animation
    row.classList.add('new-row'); // Add class list entry
    // Insert the new row before the first child of the table body to place it at the top
    if (tbody.firstChild) { // Check if tbody already contains rows
        // Insert the row before the existing first child row
        tbody.insertBefore(row, tbody.firstChild); // Insert before first child
    } else { // If tbody is empty
        // If the table is empty, append the row as the first element
        tbody.appendChild(row); // Append the row to tbody
    } // End of if-else block
    // Set a timer to remove the highlight class after 3 seconds (3000 milliseconds)
    setTimeout(function() { // Start timeout callback function
        // Remove the CSS class to fade out the highlight effect
        row.classList.remove('new-row'); // Remove class list entry
    }, 3000); // Trigger after 3000 milliseconds
    // Get the HTML element displaying the total number of alerts
    const totalAlertsElement = document.getElementById('total-alerts'); // Retrieve element
    // If the element exists and contains a valid number in its text content
    if (totalAlertsElement && !isNaN(parseInt(totalAlertsElement.textContent))) { // Verify element and contents
        // Parse the current text value as an integer, add one, and update the text content
        totalAlertsElement.textContent = parseInt(totalAlertsElement.textContent) + 1; // Increment text content value
    } // End of counter increment block
} // End of the addAlertToTop function

// Creates and returns an HTML table row (tr) element representing an alert
function createAlertRow(alert) { // Start of the createAlertRow function
    // Create a new table row element in the document
    const tr = document.createElement('tr'); // Initialize tr element
    // Initialize a variable to hold the CSS class name for the severity badge
    let severityClass = ''; // Empty severity class string
    // Normalize the severity string to lowercase to prevent case sensitivity issues
    const severityLower = (alert.severity || '').toLowerCase(); // Convert to lowercase
    // Check if the severity is high
    if (severityLower === 'high') { // Compare with 'high'
        // Assign the class for red high-severity badge
        severityClass = 'badge-high'; // Set badge high class
    } else if (severityLower === 'medium') { // Compare with 'medium'
        // Assign the class for orange medium-severity badge
        severityClass = 'badge-medium'; // Set badge medium class
    } else if (severityLower === 'low') { // Compare with 'low'
        // Assign the class for blue low-severity badge
        severityClass = 'badge-low'; // Set badge low class
    } // End of severity checks
    // Initialize a variable to hold the CSS class name for the detection method badge
    let methodClass = ''; // Empty method class string
    // Normalize the detection method string to lowercase
    const methodLower = (alert.method || '').toLowerCase(); // Convert to lowercase
    // Check if the method was rule-based
    if (methodLower === 'rule-based') { // Compare with 'rule-based'
        // Assign the class for grey rule-based badge
        methodClass = 'badge-rule'; // Set badge rule class
    } else if (methodLower === 'ml' || methodLower === 'ml-model') { // Compare with 'ml' variants
        // Assign the class for blue machine learning badge
        methodClass = 'badge-ml'; // Set badge ml class
    } // End of method checks
    // Set the HTML content inside the table row using a template literal with all columns
    tr.innerHTML = `
        <td>${formatTime(alert.timestamp)}</td>
        <td>${alert.src_ip}</td>
        <td>${alert.attack_type}</td>
        <td><span class="${severityClass}">${alert.severity}</span></td>
        <td><span class="${methodClass}">${alert.method}</span></td>
        <td>${alert.detail}</td>
    `; // Inner HTML content injection
    // Return the constructed table row element
    return tr; // Exit function with tr element
} // End of the createAlertRow function

// Normalizes stats from various server formats (nested or flat) into a single flat schema
function normalizeStats(data) { // Start of the normalizeStats function
    // If the data object is null or undefined, return an empty object
    if (!data) return {}; // Guard clause returning empty object
    // Create an empty object to store our standardized, flat properties
    const norm = {}; // Initialize standard stats object
    // Check if the data contains nested alert_stats or sniffer_stats objects
    if (data.alert_stats || data.sniffer_stats) { // If either nested object is present
        // If alert_stats is present
        if (data.alert_stats) { // Check for alert_stats
            // Map the nested 'total' count to the flat alerts_total property
            norm.alerts_total = data.alert_stats.total; // Copy total alerts
            // Map the nested 'high' severity count to the flat alerts_high property
            norm.alerts_high = data.alert_stats.high; // Copy high alerts
            // Map the nested 'medium' severity count to the flat alerts_medium property
            norm.alerts_medium = data.alert_stats.medium; // Copy medium alerts
            // Map the nested 'low' severity count to the flat alerts_low property
            norm.alerts_low = data.alert_stats.low; // Copy low alerts
        } // End of alert_stats check
        // If sniffer_stats is present
        if (data.sniffer_stats) { // Check for sniffer_stats
            // Map the nested 'packets_captured' count to the flat packets_captured property
            norm.packets_captured = data.sniffer_stats.packets_captured; // Copy packets captured
            // Map the nested 'is_running' boolean to the flat sniffer_running property
            norm.sniffer_running = data.sniffer_stats.is_running; // Copy running status
            // Map the nested 'interface' string to the flat interface property
            norm.interface = data.sniffer_stats.interface; // Copy network interface
        } // End of sniffer_stats check
    } // End of nested format handling
    // If packets_captured is directly available in the root data, use it
    if (data.packets_captured !== undefined) { // Check if packets_captured is defined
        // Assign the packets captured count to the normalized object
        norm.packets_captured = data.packets_captured; // Copy property
    } // End of packets_captured check
    // If alerts_total is directly available in the root data, use it
    if (data.alerts_total !== undefined) { // Check if alerts_total is defined
        // Assign the total alerts count to the normalized object
        norm.alerts_total = data.alerts_total; // Copy property
    } // End of alerts_total check
    // If alerts_high is directly available in the root data, use it
    if (data.alerts_high !== undefined) { // Check if alerts_high is defined
        // Assign the high alerts count to the normalized object
        norm.alerts_high = data.alerts_high; // Copy property
    } // End of alerts_high check
    // If alerts_medium is directly available in the root data, use it
    if (data.alerts_medium !== undefined) { // Check if alerts_medium is defined
        // Assign the medium alerts count to the normalized object
        norm.alerts_medium = data.alerts_medium; // Copy property
    } // End of alerts_medium check
    // If alerts_low is directly available in the root data, use it
    if (data.alerts_low !== undefined) { // Check if alerts_low is defined
        // Assign the low alerts count to the normalized object
        norm.alerts_low = data.alerts_low; // Copy property
    } // End of alerts_low check
    // If sniffer_running is directly available in the root data, use it
    if (data.sniffer_running !== undefined) { // Check if sniffer_running is defined
        // Assign the sniffer running flag to the normalized object
        norm.sniffer_running = data.sniffer_running; // Copy property
    } // End of sniffer_running check
    // If ml_ready is directly available in the root data, use it
    if (data.ml_ready !== undefined) { // Check if ml_ready is defined
        // Assign the machine learning ready flag to the normalized object
        norm.ml_ready = data.ml_ready; // Copy property
    } // End of ml_ready check
    // If interface is directly available in the root data, use it
    if (data.interface !== undefined) { // Check if interface is defined
        // Assign the interface name to the normalized object
        norm.interface = data.interface; // Copy property
    } // End of interface check
    // If total count is directly in the root data (e.g. from the raw alert logger dictionary)
    if (data.total !== undefined) { // Check if total is defined
        // Assign the total count to the normalized object
        norm.alerts_total = data.total; // Copy property to alerts_total
    } // End of total check
    // If high count is directly in the root data
    if (data.high !== undefined) { // Check if high is defined
        // Assign the high count to the normalized object
        norm.alerts_high = data.high; // Copy property to alerts_high
    } // End of high check
    // If medium count is directly in the root data
    if (data.medium !== undefined) { // Check if medium is defined
        // Assign the medium count to the normalized object
        norm.alerts_medium = data.medium; // Copy property to alerts_medium
    } // End of medium check
    // If low count is directly in the root data
    if (data.low !== undefined) { // Check if low is defined
        // Assign the low count to the normalized object
        norm.alerts_low = data.low; // Copy property to alerts_low
    } // End of low check
    // If is_running flag is directly in the root data
    if (data.is_running !== undefined) { // Check if is_running is defined
        // Assign the is_running flag to the normalized object
        norm.sniffer_running = data.is_running; // Copy property to sniffer_running
    } // End of is_running check
    // If ml_ready is still undefined, default it to true since the backend starts with ML active
    if (norm.ml_ready === undefined) { // Check if ml_ready is missing
        // Set the ml_ready flag to true as a default value
        norm.ml_ready = true; // Set default value
    } // End of ml_ready default check
    // Return the standard, flat statistics object
    return norm; // Exit function with normalized stats object
} // End of the normalizeStats function

// Updates the values displayed on the dashboard statistics cards
async function updateStatsCards(stats) { // Start of the updateStatsCards async function
    // Wrap the operation in a try block to handle any network or parsing errors
    try { // Start of try block
        // If the stats parameter is not passed, fetch the latest data from the backend API
        if (!stats) { // Check if stats parameter is falsy
            // Perform an asynchronous HTTP GET request to the statistics API endpoint
            const response = await fetch('/api/stats'); // Fetch from stats URL
            // If the server response status is not successful, throw an error
            if (!response.ok) { // Check if response status is not ok
                // Throw an error with a descriptive message
                throw new Error('Failed to fetch statistics from server'); // Throw error
            } // End of response ok check
            // Parse the response body as a JSON object
            const data = await response.json(); // Wait for JSON parsing
            // Normalize the raw JSON data to ensure we have a flat format
            stats = normalizeStats(data); // Call normalizeStats with API data
        } else { // If stats parameter is provided
            // Normalize the passed stats object (e.g. from the WebSocket event) to match our flat format
            stats = normalizeStats(stats); // Call normalizeStats with passed object
        } // End of stats presence check
        // Find the HTML element showing the total packets captured
        const tp = document.getElementById('total-packets'); // Retrieve element
        // If the element exists and the normalized stats contain packets_captured
        if (tp && stats.packets_captured !== undefined) { // Check element and packets captured
            // Update its text content with the captured packets count
            tp.textContent = stats.packets_captured; // Set text content
        } // End of packets captured card update
        // Find the HTML element displaying the total number of alerts
        const ta = document.getElementById('total-alerts'); // Retrieve element
        // If the element exists and the stats contain alerts_total
        if (ta && stats.alerts_total !== undefined) { // Check element and alerts total
            // Update its text content with the total alert count
            ta.textContent = stats.alerts_total; // Set text content
        } // End of total alerts card update
        // Find the HTML element showing the number of high-severity alerts
        const ha = document.getElementById('high-alerts'); // Retrieve element
        // If the element exists and the stats contain alerts_high
        if (ha && stats.alerts_high !== undefined) { // Check element and alerts high
            // Update its text content with the high-severity alert count
            ha.textContent = stats.alerts_high; // Set text content
        } // End of high alerts card update
        // Find the HTML element showing the number of medium-severity alerts
        const ma = document.getElementById('medium-alerts'); // Retrieve element
        // If the element exists and the stats contain alerts_medium
        if (ma && stats.alerts_medium !== undefined) { // Check element and alerts medium
            // Update its text content with the medium-severity alert count
            ma.textContent = stats.alerts_medium; // Set text content
        } // End of medium alerts card update
        // Find the HTML element representing the machine learning model status
        const ms = document.getElementById('ml-status'); // Retrieve element
        // If the element exists and the stats contain the ml_ready flag
        if (ms && stats.ml_ready !== undefined) { // Check element and ml ready flag
            // Set the text content to 'Active' if the model is ready, otherwise 'Offline'
            ms.textContent = stats.ml_ready ? 'Active' : 'Offline'; // Set status text
        } // End of ML status update
        // Find the HTML element showing the packet sniffer status
        const ss = document.getElementById('sniffer-status'); // Retrieve element
        // If the element exists and the stats contain the sniffer_running flag
        if (ss && stats.sniffer_running !== undefined) { // Check element and sniffer running flag
            // Set the text content to 'Running' if sniffing, otherwise 'Stopped'
            ss.textContent = stats.sniffer_running ? 'Running' : 'Stopped'; // Set status text
        } // End of sniffer status update
    } catch (error) { // Catch block for error handling
        // Log the error to the web browser's console for debugging purposes
        console.error('Error updating stats cards:', error); // Log error message
        // Define an array of card element IDs that display numerical statistics
        const cardIds = ['total-packets', 'total-alerts', 'high-alerts', 'medium-alerts']; // Initialize array
        // Iterate through each card element ID
        cardIds.forEach(function(id) { // Loop over IDs
            // Find the element by its ID
            const el = document.getElementById(id); // Retrieve element
            // If the element exists on the page
            if (el) { // Check element existence
                // Update its text content to show a user-friendly error message
                el.textContent = 'Error loading data'; // Set error text
            } // End of element check
        }); // End of array loop
    } // End of try-catch block
} // End of the updateStatsCards function

// Formats a full timestamp string to display only the time portion
function formatTime(timestamp) { // Start of the formatTime function
    // If the timestamp argument is falsy or empty, return an empty string
    if (!timestamp) return ''; // Guard clause returning empty string
    // Split the timestamp string at the space character into an array of substrings
    const parts = timestamp.split(' '); // Split by space
    // Check if the split operation resulted in exactly two parts (date and time)
    if (parts.length === 2) { // Compare parts array length
        // Return only the second part which is the time portion (HH:MM:SS)
        return parts[1]; // Return time string
    } // End of length check
    // If the string format was unexpected, return the original string as a fallback
    return timestamp; // Return fallback value
} // End of the formatTime function

// Periodically updates the statistics cards as a fallback when WebSockets are disconnected
function pollStats() { // Start of the pollStats function
    // Set up an interval timer that runs every 5000 milliseconds (5 seconds)
    setInterval(function() { // Start of setInterval callback
        // Fetch and refresh the statistics cards by calling the update function
        updateStatsCards(); // Call updateStatsCards with no parameters
    }, 5000); // Trigger every 5000 milliseconds
} // End of the pollStats function

// Main initialization function to set up the dashboard features on page load
function init() { // Start of the init function
    // Establish a WebSocket connection to start receiving real-time server updates
    connectWebSocket(); // Call connectWebSocket function
    // Trigger an immediate fetch of statistics to populate the cards on page load
    updateStatsCards(); // Call updateStatsCards with no parameters
    // Start the periodic statistics polling as a fallback mechanism
    pollStats(); // Call pollStats function
    // Fetch the initial alerts list from the REST API to populate the table quickly
    fetch('/api/alerts') // Fetch from alerts URL
        // Convert the API response object to a JSON promise
        .then(function(response) { // Start of response callback function
            // Return parsed JSON data
            return response.json(); // Return json parse promise
        }) // End of response callback
        // Process the parsed JSON data containing the alerts list
        .then(function(data) { // Start of data callback function
            // Check if the parsed data has a status of ok and contains alerts list
            if (data && data.alerts) { // Verify data and alerts list existence
                // Populate the alerts table with the list of alerts
                populateAlertsTable(data.alerts); // Call populateAlertsTable function
            } // End of verification check
        }) // End of data callback
        // Handle any errors that occur during the REST API fetch process
        .catch(function(error) { // Start of catch callback function
            // Log the error message to the browser console for debugging
            console.error("Could not fetch initial alerts from API:", error); // Log error message
        }); // End of catch callback
} // End of the init function

// Register the init function to run as soon as the DOM content is fully parsed and loaded
document.addEventListener('DOMContentLoaded', init); // Register event listener
