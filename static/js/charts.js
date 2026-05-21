// Store the Chart.js instance for the attack type distribution chart
let attackTypeChart = null; // Declare global variable for pie chart
// Store the Chart.js instance for the alerts severity bar chart
let severityChart = null; // Declare global variable for bar chart

// Asynchronously fetches recent alert data from the REST API
async function fetchAlertsData() { // Start of the fetchAlertsData async function
    // Perform a fetch request to the alerts API, requesting up to 200 alerts
    const response = await fetch('/api/alerts?limit=200&n=200'); // Fetch alerts array
    // If the HTTP response is not successful, throw a network error
    if (!response.ok) { // Check if response status is not ok
        // Throw an error to trigger the catch block in the calling function
        throw new Error('Failed to fetch alerts from database'); // Throw error
    } // End of if statement for response check
    // Parse the server response body as a JSON object
    const data = await response.json(); // Wait for JSON parsing to complete
    // Return the alerts array from the parsed JSON, or an empty array if missing
    return data.alerts || []; // Extract and return alerts list
} // End of the fetchAlertsData function

// Groups and counts the alerts by their attack type
function countByAttackType(alerts) { // Start of the countByAttackType function
    // Initialize an empty object to store the counts for each attack type
    const counts = {}; // Create empty counts object
    // Loop through each alert in the retrieved alerts array
    for (let i = 0; i < alerts.length; i++) { // Loop over alerts array
        // Get the attack type of the current alert, default to 'Unknown' if missing
        const type = alerts[i].attack_type || 'Unknown'; // Get attack type value
        // If this attack type is not yet registered in our counts object
        if (counts[type] === undefined) { // Check for undefined property
            // Initialize the count for this attack type to zero
            counts[type] = 0; // Initialize property to 0
        } // End of undefined check
        // Increment the count for this specific attack type by one
        counts[type]++; // Increment the counter
    } // End of the for loop
    // Return the completed counts object containing the distribution of attack types
    return counts; // Return counts object
} // End of the countByAttackType function

// Groups and counts the alerts by their severity level
function countBySeverity(alerts) { // Start of the countBySeverity function
    // Initialize counts object with zero counts for High, Medium, and Low severity
    const counts = { High: 0, Medium: 0, Low: 0 }; // Create counts object with keys
    // Loop through each alert in the retrieved alerts array
    for (let i = 0; i < alerts.length; i++) { // Loop over alerts array
        // Get the severity value of the current alert (e.g. 'High', 'Medium', 'Low')
        const severity = alerts[i].severity; // Extract severity value
        // If the severity value matches one of our predefined keys
        if (counts[severity] !== undefined) { // Verify key exists in counts
            // Increment the count for this severity level by one
            counts[severity]++; // Increment the counter
        } // End of validity check
    } // End of the for loop
    // Return the counts object containing severity distribution
    return counts; // Return counts object
} // End of the countBySeverity function

// Helper function to return the correct hex color for a given attack type
function getColorForAttackType(type) { // Start of the getColorForAttackType function
    // Convert the attack type string to lowercase to make parsing case-insensitive
    const lower = type.toLowerCase(); // Convert to lowercase
    // Check if the type string contains 'dos'
    if (lower.includes('dos')) { // Match 'dos'
        // Return red color for DoS attacks
        return '#e24b4a'; // Red hex code
    } // End of DoS check
    // Check if the type string contains 'port scan'
    if (lower.includes('port scan') || lower.includes('portscan')) { // Match 'port scan'
        // Return orange color for Port Scans
        return '#ef9f27'; // Orange hex code
    } // End of Port Scan check
    // Check if the type string contains 'syn flood'
    if (lower.includes('syn flood') || lower.includes('synflood')) { // Match 'syn flood'
        // Return red color for SYN Flood attacks
        return '#e24b4a'; // Red hex code
    } // End of SYN Flood check
    // Check if the type string contains 'icmp flood'
    if (lower.includes('icmp flood') || lower.includes('icmpflood')) { // Match 'icmp flood'
        // Return orange color for ICMP Flood attacks
        return '#ef9f27'; // Orange hex code
    } // End of ICMP Flood check
    // Check if the type string contains 'brute force'
    if (lower.includes('brute force') || lower.includes('bruteforce')) { // Match 'brute force'
        // Return purple color for Brute Force attacks
        return '#7f77dd'; // Purple hex code
    } // End of Brute Force check
    // Return blue as the default fallback color for other attack types
    return '#378add'; // Blue hex code
} // End of the getColorForAttackType function

// Renders the attack type distribution pie chart using Chart.js
function drawAttackTypePieChart(counts) { // Start of the drawAttackTypePieChart function
    // Get the 2D context of the attack-type-chart canvas element
    const ctx = document.getElementById('attack-type-chart').getContext('2d'); // Retrieve 2D context
    // Extract the attack type names (keys) from the counts object
    const keys = Object.keys(counts); // Get keys array
    // Map each attack type name to its corresponding data value (count)
    const values = keys.map(function(key) { // Start of values mapping
        // Return count value
        return counts[key]; // Return numerical count
    }); // End of values mapping
    // Calculate the total number of alerts to compute percentage representation
    const total = values.reduce(function(a, b) { // Start of values summation
        // Sum values
        return a + b; // Return current sum
    }, 0); // End of values summation with initial value 0
    // Generate label strings containing the attack type name and its percentage
    const labels = keys.map(function(key) { // Start of labels mapping
        // Get count
        const val = counts[key]; // Retrieve count
        // Calculate percentage representation
        const pct = ((val / total) * 100).toFixed(1); // Compute percentage to one decimal place
        // Return formatted label string with percentage
        return key + ' (' + pct + '%)'; // Return merged string
    }); // End of labels mapping
    // Generate background color array by mapping each attack type key to its defined color
    const colors = keys.map(function(key) { // Start of colors mapping
        // Return color
        return getColorForAttackType(key); // Return mapped color
    }); // End of colors mapping
    // Create a new Chart.js Pie Chart instance and store it globally
    attackTypeChart = new Chart(ctx, { // Initialize pie chart
        // Specify that this chart is a pie chart
        type: 'pie', // Set chart type
        // Provide the data object containing labels and datasets
        data: { // Data property
            // Assign the percentage-formatted labels
            labels: labels, // Set labels
            // Assign datasets containing chart numbers and styles
            datasets: [{ // Datasets array
                // Assign the numerical count values for each slice
                data: values, // Set data values
                // Assign the background colors for each slice
                backgroundColor: colors, // Set slice background colors
                // Assign the border colors for each slice
                borderColor: colors, // Set slice border colors
                // Set slice border width to 1 pixel
                borderWidth: 1 // Set border width
            }] // End of datasets array
        }, // End of data object
        // Configure options to customize appearance and responsiveness
        options: { // Options property
            // Allow the chart to resize responsively to fit its container
            responsive: true, // Enable responsive sizing
            // Disable aspect ratio maintenance so it fits the custom container height
            maintainAspectRatio: false, // Disable fixed ratio
            // Configure plugin options for title and legend custom styles
            plugins: { // Plugins property
                // Configure the title of the pie chart
                title: { // Title configuration
                    // Enable displaying the chart title
                    display: true, // Display title
                    // Set the title text
                    text: 'Attack Type Distribution', // Set title text
                    // Set title font color to match dark theme styling
                    color: '#e0e0e0', // Light grey color
                    // Configure font properties
                    font: { // Font styling
                        // Set font size to 16 pixels
                        size: 16 // Font size
                    } // End of font settings
                }, // End of title configuration
                // Configure the chart legend positioning
                legend: { // Legend configuration
                    // Place the chart legend below the pie chart
                    position: 'bottom', // Position legend at bottom
                    // Configure legend labels
                    labels: { // Labels configuration
                        // Set legend label font color to match dark theme styling
                        color: '#aaa' // Medium grey color
                    } // End of legend labels settings
                } // End of legend configuration
            } // End of plugins settings
        } // End of options object
    }); // End of Pie Chart instantiation
} // End of the drawAttackTypePieChart function

// Renders the alerts by severity bar chart using Chart.js
function drawSeverityBarChart(counts) { // Start of the drawSeverityBarChart function
    // Get the 2D context of the severity-chart canvas element
    const ctx = document.getElementById('severity-chart').getContext('2d'); // Retrieve 2D context
    // Create a new Chart.js Bar Chart instance and store it globally
    severityChart = new Chart(ctx, { // Initialize bar chart
        // Specify that this chart is a bar chart
        type: 'bar', // Set chart type
        // Provide the data object containing labels and datasets
        data: { // Data property
            // Assign labels for the severity levels
            labels: ['High', 'Medium', 'Low'], // Set x-axis labels
            // Assign datasets containing chart numbers and styles
            datasets: [{ // Datasets array
                // Hide the dataset label from the legend
                label: 'Alerts', // Set dataset label
                // Assign numerical counts for High, Medium, and Low severity levels
                data: [counts.High || 0, counts.Medium || 0, counts.Low || 0], // Set bar heights
                // Assign specific background colors (Red for High, Orange for Medium, Blue for Low)
                backgroundColor: ['#e24b4a', '#ef9f27', '#378add'], // Set bar colors
                // Assign matching border colors for consistency
                borderColor: ['#e24b4a', '#ef9f27', '#378add'], // Set bar border colors
                // Set bar border width to 1 pixel
                borderWidth: 1 // Set border width
            }] // End of datasets array
        }, // End of data object
        // Configure options to customize appearance and responsiveness
        options: { // Options property
            // Allow the chart to resize responsively to fit its container
            responsive: true, // Enable responsive sizing
            // Disable aspect ratio maintenance so it fits the custom container height
            maintainAspectRatio: false, // Disable fixed ratio
            // Configure plugins for title and legend options
            plugins: { // Plugins property
                // Configure the title of the bar chart
                title: { // Title configuration
                    // Enable displaying the chart title
                    display: true, // Display title
                    // Set the title text
                    text: 'Alerts by Severity', // Set title text
                    // Set title font color to match dark theme styling
                    color: '#e0e0e0', // Light grey color
                    // Configure font properties
                    font: { // Font styling
                        // Set font size to 16 pixels
                        size: 16 // Font size
                    } // End of font settings
                }, // End of title configuration
                // Hide the dataset legend since the bar colors represent categories
                legend: { // Legend configuration
                    // Do not display the legend box
                    display: false // Disable legend display
                } // End of legend configuration
            }, // End of plugins settings
            // Configure scales for axis custom labels and grid colors
            scales: { // Scales property
                // Configure the y-axis (vertical axis)
                y: { // Y-axis configuration
                    // Start y-axis values from zero
                    beginAtZero: true, // Start at 0
                    // Configure axis title
                    title: { // Title configuration
                        // Enable displaying y-axis title
                        display: true, // Display title
                        // Set the axis label text
                        text: 'Number of Alerts', // Set axis title text
                        // Set label font color to match dark theme styling
                        color: '#aaa' // Medium grey color
                    }, // End of axis title settings
                    // Configure axis ticks (value markers)
                    ticks: { // Ticks configuration
                        // Set tick font color
                        color: '#aaa', // Medium grey color
                        // Force ticks to display whole numbers only
                        precision: 0 // Whole numbers only
                    }, // End of ticks settings
                    // Configure axis grid lines
                    grid: { // Grid configuration
                        // Set grid line color to match dark theme styling
                        color: '#333' // Dark grey grid lines
                    } // End of grid settings
                }, // End of y-axis configuration
                // Configure the x-axis (horizontal axis)
                x: { // X-axis configuration
                    // Configure axis ticks
                    ticks: { // Ticks configuration
                        // Set tick font color
                        color: '#aaa' // Medium grey color
                    }, // End of ticks settings
                    // Configure axis grid lines
                    grid: { // Grid configuration
                        // Set grid line color to match dark theme styling
                        color: '#333' // Dark grey grid lines
                    } // End of grid settings
                } // End of x-axis configuration
            } // End of scales settings
        } // End of options object
    }); // End of Bar Chart instantiation
} // End of the drawSeverityBarChart function

// Fetches the latest data and redrafts both charts on the page
async function refreshCharts() { // Start of the refreshCharts function
    // Wrap the operations in a try-catch block to handle any network or Chart.js errors
    try { // Start of try block
        // Fetch the fresh alerts array from the REST API
        const alerts = await fetchAlertsData(); // Wait for data retrieval
        // Find the attack type chart canvas element by its ID
        const attackCanvas = document.getElementById('attack-type-chart'); // Retrieve canvas element
        // Find the severity chart canvas element by its ID
        const severityCanvas = document.getElementById('severity-chart'); // Retrieve canvas element
        // Find the no-data placeholder element by its ID
        const noDataMessage = document.getElementById('no-data-message'); // Retrieve placeholder element
        // Check if there are no alerts returned from the database
        if (!alerts || alerts.length === 0) { // Check if empty
            // Display the 'No attacks detected yet' message on the screen
            if (noDataMessage) noDataMessage.style.display = 'block'; // Make message visible
            // Hide the attack type canvas element to prevent a blank canvas box
            if (attackCanvas) attackCanvas.style.display = 'none'; // Hide canvas
            // Hide the severity canvas element to prevent a blank canvas box
            if (severityCanvas) severityCanvas.style.display = 'none'; // Hide canvas
            // Destroy any existing attack type chart to free up browser memory
            if (attackTypeChart) { // Check if chart exists
                // Call the destroy method
                attackTypeChart.destroy(); // Destroy chart
                // Reset the global variable to null
                attackTypeChart = null; // Clear reference
            } // End of attack chart destruction check
            // Destroy any existing severity chart to free up browser memory
            if (severityChart) { // Check if chart exists
                // Call the destroy method
                severityChart.destroy(); // Destroy chart
                // Reset the global variable to null
                severityChart = null; // Clear reference
            } // End of severity chart destruction check
            // Exit the function early as there is no data to plot
            return; // Exit function
        } // End of empty data check
        // Hide the 'No attacks detected yet' message if alerts exist
        if (noDataMessage) noDataMessage.style.display = 'none'; // Hide message
        // Make the attack type chart canvas element visible
        if (attackCanvas) attackCanvas.style.display = 'block'; // Show canvas
        // Make the severity chart canvas element visible
        if (severityCanvas) severityCanvas.style.display = 'block'; // Show canvas
        // Group the alerts and calculate counts for each attack type
        const attackCounts = countByAttackType(alerts); // Aggregate attack types
        // Group the alerts and calculate counts for each severity level
        const severityCounts = countBySeverity(alerts); // Aggregate severities
        // Destroy the existing attack type chart if one is already rendered
        if (attackTypeChart) { // Check if chart exists
            // Call the destroy method to prevent duplicate overlays and memory leaks
            attackTypeChart.destroy(); // Destroy chart
        } // End of chart destruction check
        // Destroy the existing severity chart if one is already rendered
        if (severityChart) { // Check if chart exists
            // Call the destroy method to prevent duplicate overlays and memory leaks
            severityChart.destroy(); // Destroy chart
        } // End of chart destruction check
        // Render the new attack type pie chart with the aggregated data
        drawAttackTypePieChart(attackCounts); // Call pie chart renderer
        // Render the new severity bar chart with the aggregated data
        drawSeverityBarChart(severityCounts); // Call bar chart renderer
    } catch (error) { // Catch block for error handling
        // Log the error details to the browser console for developer troubleshooting
        console.error('Error refreshing charts:', error); // Log error message
    } // End of try-catch block
} // End of the refreshCharts function

// Sets up the initial chart display and registers the polling timer on page load
function init() { // Start of the init function
    // Perform an immediate fetch and draw of the charts on initial page load
    refreshCharts(); // Trigger first chart draw
    // Set a recurring interval to refresh the charts every 30 seconds (30000 milliseconds)
    setInterval(function() { // Start of setInterval callback
        // Periodically refresh charts with fresh database data
        refreshCharts(); // Trigger periodic update
    }, 30000); // 30-second interval
} // End of the init function

// Register the init function to run as soon as the DOM content is fully loaded
document.addEventListener('DOMContentLoaded', init); // Register event listener
