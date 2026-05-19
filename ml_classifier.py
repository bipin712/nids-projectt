# Import the os module to handle file paths properly across different operating systems
import os
# Import numpy library to handle numerical operations and array reshaping
import numpy as np
# Import joblib to load the pre-trained machine learning model file
import joblib

# Define the relative path to the machine learning model file using os.path.join for safety
MODEL_PATH = os.path.join('models', 'rf_model.pkl')

# Create a global variable to hold the loaded model, initially set to None
_model = None
# Create a global flag to easily check if the model is ready to use, initially False
ML_READY = False

# Try block to safely attempt loading the model without crashing the whole program if it fails
try:
    # Check if the model file actually exists at the specified path
    if os.path.exists(MODEL_PATH):
        # Load the model from the file using joblib.load and store it in our global variable
        _model = joblib.load(MODEL_PATH)
        # Set the readiness flag to True since the model loaded successfully
        ML_READY = True
        
        # Try to get the classes from the model to print a nice success message
        try:
            # Extract the classes that the model was trained on
            _classes = _model.classes_
            # Print a success message showing the model is loaded and listing its classes
            print(f"[ML] Model loaded — classes: {_classes}")
        # If getting the classes fails for some reason
        except:
            # Just print a generic success message
            print("[ML] Model loaded successfully.")
    # If the file does not exist at the path
    else:
        # Print a warning message telling the user the file is missing
        print(f"[WARNING] ML model file not found at {MODEL_PATH}. ML features disabled.")
# Catch any unexpected errors that happen during the loading process
except Exception as e:
    # Print a warning message showing the exact error that occurred
    print(f"[WARNING] Failed to load ML model: {str(e)}. ML features disabled.")

# Define the classify function that takes a list of 41 numbers (features)
def classify(feature_vector):
    # Check if the model is actually loaded and ready
    if not ML_READY:
        # If not ready, return a safe default answer 'normal'
        return 'normal'
    
    # Try block to safely attempt prediction without crashing on bad data
    try:
        # Convert the Python list of numbers into a numpy array
        features_array = np.array(feature_vector)
        # Reshape the array to be a 2D array with 1 row, which the model expects
        features_reshaped = features_array.reshape(1, -1)
        
        # Use the model to predict the class of the traffic
        prediction = _model.predict(features_reshaped)
        # The prediction comes back as a list/array, so we get the first item and convert it to string
        return str(prediction[0])
    # Catch any errors that happen during prediction (like wrong number of features)
    except Exception as e:
        # Print an error message to help debugging
        print(f"[ERROR] Classification failed: {str(e)}")
        # Return a safe default answer 'normal' if something goes wrong
        return 'normal'

# Define the get_confidence function that takes a list of 41 numbers
def get_confidence(feature_vector):
    # Check if the model is actually loaded and ready
    if not ML_READY:
        # If not ready, return 0.0 confidence
        return 0.0
    
    # Try block to safely attempt confidence calculation
    try:
        # Convert the Python list of numbers into a numpy array
        features_array = np.array(feature_vector)
        # Reshape the array to be a 2D array with 1 row, which the model expects
        features_reshaped = features_array.reshape(1, -1)
        
        # Check if the model has the predict_proba method (most classifiers do)
        if hasattr(_model, 'predict_proba'):
            # Get the probabilities for all classes
            probabilities = _model.predict_proba(features_reshaped)
            # Find the highest probability among all classes and return it as a float
            return float(np.max(probabilities[0]))
        # If the model doesn't support probability
        else:
            # Just return 1.0 (100%) since it made a prediction but can't give exact probability
            return 1.0
    # Catch any errors that happen during confidence calculation
    except:
        # Return 0.0 confidence if something goes wrong
        return 0.0

# Define a simple function to check if the ML system is working
def is_ready():
    # Return the current value of the global ML_READY flag (True or False)
    return ML_READY
