"""
========================================
CYBERGUARD PENETRATION TESTING PLATFORM
========================================

Backend Flask Application for Automated Security Testing

This application provides a comprehensive backend API for:
- OSINT (Open Source Intelligence) gathering
- Network and device scanning
- Web application vulnerability assessment
- File management and reporting
- AI-powered chatbot with Gemini API integration

Author: Haroon Allahdad & Khyam Javed
Project: Final Year Project - International Islamic University Islamabad
"""

# ========================================
# IMPORTS AND DEPENDENCIES
# ========================================

# Standard library imports
import os
import sys
import json
import time
import uuid
import html
import logging
import re
import threading
import subprocess
import mimetypes
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("Warning: nmap module not available. Network discovery features will be disabled.")
from datetime import datetime
from collections import defaultdict
from urllib.parse import urlparse
from phone_tracker import track_phone_number
from osint_checker import validate_number


# Third-party imports
import requests
import phonenumbers
from zapv2 import ZAPv2

# Flask and extensions
from flask import (
    Flask, request, jsonify, send_from_directory,
    render_template, url_for, send_file, current_app
)
from werkzeug.utils import safe_join, secure_filename
from flask_cors import CORS
from flask_socketio import SocketIO, emit





# ========================================
# FLASK APPLICATION INITIALIZATION
# ========================================

app = Flask(__name__, template_folder='../')

# CORS configuration
CORS_ORIGINS = [
    "http://127.0.0.1:5500",  # Live Server
    "http://localhost:5500",   # Live Server alternative
    "http://127.0.0.1:3000",  # React dev server
    "http://localhost:3000",   # React dev server alternative
    "http://127.0.0.1:8080",  # Common dev port
    "http://localhost:8080"    # Common dev port alternative
]

# Configure CORS for development
CORS(app, 
     resources={r"/*": {"origins": CORS_ORIGINS}},
     supports_credentials=True,
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])

# Initialize SocketIO with CORS support (This is the correct, single initialization)
socketio = SocketIO(app, 
                     cors_allowed_origins=CORS_ORIGINS,
                     async_mode='threading')
                     
# Add CORS headers to all responses
@app.after_request
def after_request(response):
    """Add CORS headers to all responses"""
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# Configure logging for Flask app
logging.basicConfig(level=logging.INFO)  # Basic config for console output
app.logger.setLevel(logging.INFO)  # Set to INFO for general messages, DEBUG for verbose scan updates

# ========================================
# DIRECTORY AND FILE CONFIGURATION
# ========================================

# Define base directory as the directory where app.py resides
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Directory for uploaded files and generated reports
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')  # For manual file uploads
REPORTS_FOLDER = os.path.join(BASE_DIR, 'reports')  # For ZAP-generated security reports
TEMPLATES_FOLDER = os.path.join(BASE_DIR, 'templates')  # For HTML templates

# Ensure all required directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)
os.makedirs(TEMPLATES_FOLDER, exist_ok=True)

# Configure Flask app with directory paths
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['REPORTS_FOLDER'] = REPORTS_FOLDER
app.template_folder = TEMPLATES_FOLDER  # Tell Flask where to find templates

# ========================================
# ZAP (OWASP ZAP) CONFIGURATION
# ========================================

# Configuration for ZAP API - OWASP ZAP is a web application security scanner
ZAP_API_KEY = os.environ.get('ZAP_API_KEY', 't9zmbgqgmhup8prnbg21bt')  # Your ZAP API key
ZAP_PROXY_HOST = '127.0.0.1'  # ZAP proxy host (localhost)
ZAP_PROXY_PORT = '8080'  # ZAP proxy port
ZAP_API_BASE_URL = f'http://{ZAP_PROXY_HOST}:{ZAP_PROXY_PORT}/JSON/'  # Base URL for ZAP API calls

# Initialize ZAP API client (using zapv2) - will be None if ZAP is not available
try:
    # Connect directly to ZAP API - simple initialization
    zap = ZAPv2(apikey=ZAP_API_KEY)
    # Test the connection by getting the version (it's a property, not a method)
    version = zap.core.version
    print(f"ZAP connection successful - Version: {version}")
except Exception as e:
    print(f"Warning: ZAP not available at {ZAP_PROXY_HOST}:{ZAP_PROXY_PORT}. Web scanning features will be disabled. Error: {e}")
    zap = None

# ========================================
# GEMINI AI API CONFIGURATION
# ========================================

# Gemini API Configuration - SECURE (API keys stored in environment variables)
GEMINI_API_KEYS = [
    os.environ.get('GEMINI_API_KEY_1', 'AIzaSyCoMLa_u8vwimOnUQXRpK0Y7sIcZyw86Ys'),  # Primary key
    os.environ.get('GEMINI_API_KEY_2', 'AIzaSyCCjynIUn0M-diwZa6gsHL7uPW1i6cBaSc')   # Backup key
]
current_gemini_key_index = 0  # Track which API key is currently being used

# ========================================
# RATE LIMITING CONFIGURATION
# ========================================

# Rate limiting for chat requests to prevent abuse and quota exhaustion
from collections import defaultdict
import threading

# Store rate limit data per client IP
chat_rate_limits = defaultdict(list)
rate_limit_lock = threading.Lock()  # Thread-safe access to rate limit data

def is_rate_limited(client_ip, max_requests=10, window_seconds=60):
    """
    Simple rate limiting for chat requests
    
    Args:
        client_ip (str): IP address of the client
        max_requests (int): Maximum requests allowed in the time window
        window_seconds (int): Time window in seconds
    
    Returns:
        bool: True if client is rate limited, False otherwise
    """
    current_time = time.time()
    with rate_limit_lock:
        # Clean old requests outside the time window
        chat_rate_limits[client_ip] = [req_time for req_time in chat_rate_limits[client_ip] 
                                      if current_time - req_time < window_seconds]
        
        # Check if limit exceeded
        if len(chat_rate_limits[client_ip]) >= max_requests:
            return True
        
        # Add current request timestamp
        chat_rate_limits[client_ip].append(current_time)
        return False

def switch_gemini_api_key():
    """
    Switch to next available Gemini API key when rate limited
    
    Returns:
        str: The new API key to use
    """
    global current_gemini_key_index
    current_gemini_key_index = (current_gemini_key_index + 1) % len(GEMINI_API_KEYS)
    app.logger.info(f"Switched to Gemini API key {current_gemini_key_index + 1}")
    return GEMINI_API_KEYS[current_gemini_key_index]

# ========================================
# TEST ENDPOINT
# ========================================

@app.route('/api/test', methods=['GET'])
def test_endpoint():
    """
    Simple test endpoint to verify the backend is running
    """
    return jsonify({
        "status": "success",
        "message": "Backend is running!",
        "timestamp": datetime.now().isoformat()
    }), 200

# ========================================
# CHAT ENDPOINT - AI-POWERED ASSISTANT
# ========================================

@app.route('/api/chat', methods=['POST'])
def chat_endpoint():
    """
    Secure chat endpoint that proxies requests to Gemini API with key switching
    
    This endpoint:
    - Validates user input
    - Applies rate limiting
    - Handles API key switching on rate limits
    - Returns AI responses to the frontend
    
    Expected JSON payload:
    {
        "message": "user message",
        "chat_history": [...],
        "page_context": "system instructions"
    }
    
    Returns:
        JSON response with AI-generated text or error message
    """
    # Debug logging
    app.logger.info(f"Chat endpoint called from {request.remote_addr}")
    app.logger.info(f"Request headers: {dict(request.headers)}")
    
    # Rate limiting - prevent abuse
    client_ip = request.remote_addr
    if is_rate_limited(client_ip):
        return jsonify({
            "status": "error",
            "message": "Rate limit exceeded. Please wait a moment before sending another message."
        }), 429

    try:
        # Parse and validate request data
        data = request.get_json()
        if not data or 'message' not in data:
            return jsonify({"status": "error", "message": "Message is required"}), 400

        user_message = data['message']
        chat_history = data.get('chat_history', [])
        page_context = data.get('page_context', '')

        # Construct payload for Gemini API
        contents = []
        
        # Add system instructions if provided (context about the application)
        if page_context:
            contents.append({"role": "user", "parts": [{"text": page_context}]})
        
        # Add chat history for conversation continuity
        contents.extend(chat_history)
        
        # Add current user message
        if user_message:
            contents.append({"role": "user", "parts": [{"text": user_message}]})

        payload = {"contents": contents}

        # Try with current API key, switch if rate limited
        response = None
        last_error = None
        
        for attempt in range(len(GEMINI_API_KEYS)):
            current_key = GEMINI_API_KEYS[current_gemini_key_index]
            api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={current_key}"
            
            try:
                response = requests.post(
                    api_url,
                    headers={'Content-Type': 'application/json'},
                    json=payload,
                    timeout=30  # 30 second timeout
                )
                
                if response.status_code == 200:
                    # Success! Break out of retry loop
                    break
                elif response.status_code == 429 and attempt < len(GEMINI_API_KEYS) - 1:
                    # Rate limited, try next key
                    app.logger.warning(f"Gemini API key {current_gemini_key_index + 1} rate limited, switching...")
                    switch_gemini_api_key()
                    continue
                else:
                    # Other error
                    last_error = f"API error: {response.status_code} - {response.text}"
                    break
                    
            except requests.exceptions.RequestException as e:
                last_error = str(e)
                if "429" in str(e) and attempt < len(GEMINI_API_KEYS) - 1:
                    switch_gemini_api_key()
                    continue
                break

        if not response or response.status_code != 200:
            return jsonify({
                "status": "error",
                "message": f"Failed to get response from AI: {last_error}"
            }), 500

        # Parse response from Gemini API
        result = response.json()
        bot_response = "I'm sorry, I couldn't get a response from the AI."
        
        if (result.get('candidates') and 
            result['candidates'][0].get('content') and 
            result['candidates'][0]['content'].get('parts')):
            bot_response = result['candidates'][0]['content']['parts'][0].get('text', bot_response)

        return jsonify({
            "status": "success",
            "response": bot_response
        }), 200

    except Exception as e:
        app.logger.error(f"Error in chat endpoint: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": "Internal server error. Please try again."
        }), 500

# ========================================
# FILE SERVING ENDPOINTS
# ========================================

@app.route('/')
def home():
    """
    Serves the mainpage.html when the root URL is accessed.
    This is the main entry point for the web application.
    """
    return render_template('mainpage.html')

# --- Helper functions ---

# File handling constants
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'ppt', 'pptx'}
METADATA_PATH = os.path.join(UPLOAD_FOLDER, 'file_metadata.json')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['REPORTS_FOLDER'] = REPORTS_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def load_metadata():
    if not os.path.exists(METADATA_PATH):
        with open(METADATA_PATH, 'w') as f:
            json.dump({}, f)
    with open(METADATA_PATH, 'r') as f:
        try:
            return json.load(f)
        except Exception:
            return {}

def save_metadata(metadata):
    with open(METADATA_PATH, 'w') as f:
        json.dump(metadata, f, indent=2)

@app.route('/api/upload_gallery_file', methods=['POST'])
def upload_gallery_file():
    try:
        if 'file' not in request.files:
            return jsonify({"status": "error", "message": "No file part"}), 400
        file = request.files['file']
        title = request.form.get('title', '')
        description = request.form.get('description', '')
        if file.filename == '' or not allowed_file(file.filename):
            return jsonify({"status": "error", "message": "Invalid file type or no file selected"}), 400
        filename = secure_filename(file.filename)
        save_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(save_path)
        metadata = load_metadata()
        metadata[filename] = {"title": title, "description": description}
        save_metadata(metadata)
        return jsonify({"status": "success", "fileName": filename})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Upload failed: {str(e)}"}), 500

@app.route('/api/list_gallery_files', methods=['GET'])
def list_gallery_files():
    try:
        files = []
        # Load metadata if available
        metadata = {}
        if os.path.exists(METADATA_PATH):
            with open(METADATA_PATH, 'r') as f:
                try:
                    metadata = json.load(f)
                except Exception:
                    metadata = {}
        # List files in uploads (excluding file_metadata.json)
        if os.path.exists(UPLOAD_FOLDER):
            for fname in os.listdir(UPLOAD_FOLDER):
                if fname.startswith('.') or fname == 'file_metadata.json':
                    continue
                fpath = os.path.join(UPLOAD_FOLDER, fname)
                if not os.path.isfile(fpath):
                    continue
                stat = os.stat(fpath)
                file_info = {
                    "fileName": fname,
                    "fileUrl": f"{request.host_url.rstrip('/')}/uploads/{fname}",
                    "fileType": _guess_mime_type(fname),
                    "source": "upload",
                    "mtime": stat.st_mtime
                }
                # Add metadata if available
                if fname in metadata:
                    file_info.update(metadata[fname])
                files.append(file_info)
        # List files in reports
        if os.path.exists(REPORTS_FOLDER):
            for fname in os.listdir(REPORTS_FOLDER):
                if fname.startswith('.'):
                    continue
                fpath = os.path.join(REPORTS_FOLDER, fname)
                if not os.path.isfile(fpath):
                    continue
                stat = os.stat(fpath)
                file_info = {
                    "fileName": fname,
                    "fileUrl": f"{request.host_url.rstrip('/')}/reports/{fname}",
                    "fileType": _guess_mime_type(fname),
                    "source": "zap_report",
                    "mtime": stat.st_mtime
                }
                # Add metadata if available (including highest_risk)
                if fname in metadata:
                    file_info.update(metadata[fname])
                files.append(file_info)
        # Sort files: newest first (by mtime descending)
        files.sort(key=lambda x: x.get('mtime', 0), reverse=True)
        # Remove mtime from output (not needed by frontend)
        for f in files:
            f.pop('mtime', None)
        return jsonify({"status": "success", "files": files})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/delete_gallery_item', methods=['POST'])
def delete_gallery_item():
    data = request.get_json()
    fname = data.get('fileName')
    if not fname:
        return jsonify({"status": "error", "message": "No file name provided"}), 400
    file_path = os.path.join(UPLOAD_FOLDER, fname)
    metadata = load_metadata()
    if os.path.exists(file_path):
        os.remove(file_path)
        metadata.pop(fname, None)
        save_metadata(metadata)
        return jsonify({"status": "success"})
    # Try reports folder
    file_path = os.path.join(REPORTS_FOLDER, fname)
    if os.path.exists(file_path):
        os.remove(file_path)
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "message": "File not found"}), 404

@app.route('/uploads/<filename>')
def serve_upload(filename):
    upath = os.path.join(UPLOAD_FOLDER, filename)
    rpath = os.path.join(REPORTS_FOLDER, filename)
    if os.path.exists(upath):
        return send_from_directory(UPLOAD_FOLDER, filename)
    elif os.path.exists(rpath):
        return send_from_directory(REPORTS_FOLDER, filename)
    return "File not found", 404

@app.route('/download/<folder_type>/<filename>')
def download_file(folder_type, filename):
    if folder_type == 'uploads':
        directory = UPLOAD_FOLDER
    elif folder_type == 'reports':
        directory = REPORTS_FOLDER
    else:
        return jsonify({"status": "error", "message": "Invalid folder type."}), 400
    file_path = os.path.join(directory, filename)
    if not os.path.exists(file_path):
            return jsonify({"status": "error", "message": "File not found."}), 404
    return send_from_directory(directory, filename, as_attachment=True)

@app.route('/api/recon/osint', methods=['POST'])
def run_osint_checker():
    """
    API endpoint to run the custom OSINT checker.
    It expects a JSON payload with a 'target' key (e.g., {"target": "elonmusk"}).
    Executes osint_checker.py as a subprocess and returns its JSON output.
    """
    data = request.get_json()
    target_username = data.get('target')

    if not target_username:
        return jsonify({"error": "No target username provided"}), 400

    try:
        # Import and use the function directly
        from osint_checker import check_username
        
        # Get the existing socketio instance
        socketio = current_app.extensions['socketio']
        
        # Run the check
        results = check_username(target_username, socketio)
        
        app.logger.debug(f"\n--- Custom OSINT Checker Results for '{target_username}' ---")
        app.logger.debug(f"Results: {json.dumps(results, indent=2)}")
        app.logger.debug("---------------------------------------------------\n")

        return jsonify({"status": "success", "target": target_username, "results": results}), 200

    except requests.exceptions.Timeout:
        app.logger.error(f"OSINT search for '{target_username}' timed out.")
        return jsonify({
            "status": "error",
            "message": f"OSINT search for '{target_username}' timed out. The target might be complex or the network is slow."
        }), 504  # Gateway Timeout
    except requests.exceptions.RequestException as e:
        app.logger.error(f"\n--- OSINT Request Error for '{target_username}' ---")
        app.logger.error(f"Error: {str(e)}")
        app.logger.error("---------------------------------------------------\n")
        return jsonify({
            "status": "error",
            "message": f"Error during OSINT search: {str(e)}"
        }), 500
    except Exception as e:
        app.logger.error(f"\n--- General Backend Error for '{target_username}' ---")
        app.logger.error(f"Error: {str(e)}", exc_info=True)
        app.logger.error("---------------------------------------------------\n")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/recon/phone', methods=['POST'])
def phone_recon():
    data = request.get_json()
    phone_number = data.get('target')

    if not phone_number:
        return jsonify({"status": "error", "message": "Phone number is required."}), 400

    # Validate phone number format before passing to script
    if not phone_number.startswith('+'):
        return jsonify({
            "status": "error",
            "message": "Invalid phone number format. Must start with '+' (e.g., +1234567890).",
            "data": None
        }), 400

    # Strict E.164 and country-specific validation
    is_valid, validation_message = validate_number(phone_number, country='PK')
    if not is_valid:
        return jsonify({
            "status": "error",
            "message": validation_message,
            "data": None
        }), 400

    try:
        result = subprocess.run(
            ['python', 'phone_tracker.py', phone_number],
            capture_output=True,
            text=True,
            check=True
        )

        results_from_tracker = json.loads(result.stdout)

        # Check if number is completely unusable
        if results_from_tracker.get("is_valid") is False and results_from_tracker.get("is_possible") is False:
            return jsonify({
                "status": "error",
                "message": results_from_tracker.get("error", "Number is not valid or possible."),
                "data": results_from_tracker
            }), 400

        # Convert warning-level error to a note
        if results_from_tracker.get("error") and (results_from_tracker.get("is_valid") or results_from_tracker.get("is_possible")):
            results_from_tracker["note"] = results_from_tracker["error"]
            results_from_tracker["error"] = None

        return jsonify({
            "status": "success",
            "message": "Phone number processed successfully.",
            "data": results_from_tracker
        }), 200

    except subprocess.CalledProcessError as e:
        error_output = e.stderr or "Unknown error from phone_tracker.py"
        return jsonify({
            "status": "error",
            "message": f"Script error: {error_output}",
            "data": None
        }), 500

    except json.JSONDecodeError:
        return jsonify({
            "status": "error",
            "message": "Failed to parse JSON response from phone tracker script.",
            "data": None
        }), 500

    except FileNotFoundError:
        return jsonify({
            "status": "error",
            "message": "Phone tracker script or Python interpreter not found.",
            "data": None
        }), 500

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"An unexpected server error occurred: {str(e)}",
            "data": None
        }), 500

        
                
@app.route('/api/device/port_scan', methods=['POST'])
def device_port_scan_api():
    """
    API endpoint to run the custom device port scanner.
    It expects a JSON payload with 'target' (IP/hostname) and 'ports' (range or single).
    Executes device_scanner.py with 'port_scan' action.
    """
    data = request.get_json()
    target = data.get('target')
    ports = data.get('ports')
    overall_timeout = data.get('timeout', 180)          # Reduced to 3 minutes for user-defined ports
    individual_port_timeout = data.get('port_timeout', 1)  # Reduced to 1 second for faster scanning

    if not target or not ports:
        return jsonify({"error": "No target and ports are required for port scan."}), 400

    try:
        script_path = os.path.join(os.path.dirname(__file__), 'device_scanner.py')
        cmd = [sys.executable, script_path, 'port_scan', target, '--ports', ports, 
                         '--timeout', str(overall_timeout)]

        # Debug: Log the exact command being run
        app.logger.info(f"DEBUG: Running port scan command: {cmd}")

        process = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=overall_timeout + 10) # Added timeout

        scan_output = process.stdout

        app.logger.debug(f"\n--- Custom Device Port Scan Process Output for '{target}:{ports}' ---")
        app.logger.debug(f"STDOUT: {process.stdout.strip()}")
        app.logger.debug(f"STDERR: {process.stderr.strip()}")
        app.logger.debug("---------------------------------------------------\n")

        try:
            results = json.loads(scan_output)
        except json.JSONDecodeError:
            results = {"raw_output": scan_output, "message": "Device scanner output was not clean JSON."}
         
        if results.get("error"):
            return jsonify({"status": "error", "message": results["error"], "results": results}), 500

        return jsonify({"status": "success", "target": target, "ports": ports, "results": results}), 200

    except subprocess.CalledProcessError as e:
        app.logger.error(f"\n--- Device Port Scan CalledProcessError for '{target}:{ports}' ---")
        app.logger.error(f"Return Code: {e.returncode}")
        app.logger.error(f"STDOUT: {e.stdout.strip()}")
        app.logger.error(f"STDERR: {e.stderr.strip()}")
        app.logger.error("---------------------------------------------------\n")
        return jsonify({
            "status": "error",
            "message": f"Custom device port scan failed. Error: {e.stderr.strip()}",
            "stdout": e.stdout.strip()
        }), 500
    except subprocess.TimeoutExpired:
        app.logger.error(f"Port scan for '{target}' timed out.")
        return jsonify({
            "status": "error",
            "message": f"Port scan for '{target}' timed out after {overall_timeout} seconds. The target might be unresponsive or the scan range is too large."
        }), 504 # Gateway Timeout
    except Exception as e:
        app.logger.error(f"\n--- General Backend Error during Port Scan for '{target}:{ports}' ---")
        app.logger.error(f"Error: {str(e)}", exc_info=True)
        app.logger.error("---------------------------------------------------\n")
        return jsonify({"status": "error", "message": str(e)}), 500

import nmap
from flask import Flask, request, jsonify, current_app
from flask_cors import CORS # Make sure Flask-CORS is imported

# ... (Your existing Flask app and CORS configuration like CORS(app, resources={r"/*": {"origins": CORS_ORIGINS}}, ...) should be here) ...

@app.route('/api/device/network_discovery', methods=['POST'])
def network_discovery():
    data = request.json
    target_range = data.get('target')

    if not target_range:
        return jsonify({"status": "error", "message": "Target IP address/network prefix is required."}), 400

    # Handle both dot notation (192.168.1.) and CIDR notation (192.168.1.0/24)
    if target_range.endswith('.'):
        # Convert dot notation to CIDR for nmap
        target_range = target_range + "0/24"
    elif not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$", target_range):
        return jsonify({"status": "error", "message": "Invalid network prefix format. Expected 'X.X.X.' (e.g., 192.168.1.) or CIDR notation (e.g., 192.168.1.0/24)."}), 400

    if not NMAP_AVAILABLE:
        # Fallback to device_scanner.py for network discovery
        try:
            script_path = os.path.join(os.path.dirname(__file__), 'device_scanner.py')
            # Convert CIDR back to dot notation for device_scanner.py
            fallback_target = target_range.replace('/24', '.') if target_range.endswith('/24') else target_range
            cmd = [sys.executable, script_path, 'network_discovery', fallback_target, '--timeout', '240']
            
            app.logger.info(f"DEBUG: Running network discovery command: {cmd}")
            
            process = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=300)
            
            try:
                results = json.loads(process.stdout)
                if results.get("error"):
                    return jsonify({"status": "error", "message": results["error"]}), 500
                
                return jsonify({
                    "status": "success",
                    "message": "Network discovery completed (using fallback method).",
                    "results": {
                        "network": target_range,
                        "target_range": target_range + "1-254",
                        "hosts_discovered": len(results.get("active_hosts", [])),
                        "total_hosts_scanned": 254,
                        "scan_time": "N/A",
                        "active_hosts": results.get("active_hosts", []),
                        "active_hosts_details": []
                    }
                })
            except json.JSONDecodeError:
                return jsonify({"status": "error", "message": "Failed to parse network discovery results"}), 500
                
        except Exception as e:
            return jsonify({"status": "error", "message": f"Network discovery failed: {str(e)}"}), 500

    nm = nmap.PortScanner()
    active_hosts_details = [] # This will store detailed host info including OS and ports
    total_hosts_scanned = 0
    
    # Track scan timing
    import time
    start_time = time.time() 

    try:
        # Optimized scan parameters:
        # -sn: Ping scan - disable port scan (just find hosts)
        # -T4: Aggressive timing for faster results
        # --host-timeout: Stop scanning a host after this time
        # --max-retries: Max number of retransmissions
        # -O: OS detection (try first, fallback if fails due to permissions)
        print(f"Starting Nmap scan on {target_range}...")
        
        # Try OS detection first (requires root)
        try:
            nm.scan(hosts=target_range, arguments='-sn -O -T4 --host-timeout 10s --max-retries 1')
            print("Nmap scan with OS detection completed.")
        except Exception as os_error:
            print(f"OS detection failed (likely no root privileges): {os_error}")
            print("Falling back to basic host discovery...")
            # Fallback to basic scan without OS detection
            nm.scan(hosts=target_range, arguments='-sn -T4 --host-timeout 10s --max-retries 1')
            print("Nmap basic scan completed.")

        all_scanned_hosts = nm.all_hosts()
        total_hosts_scanned = len(all_scanned_hosts)

        for host in all_scanned_hosts:
            # Check if host is "up" before trying to get details
            if nm[host].state() == 'up':
                host_data = {
                    "ip": host,
                    "status": nm[host].state(),
                    "os_details": [],
                    "ports": []
                }

                # Extract OS details if available from OS detection
                if 'osmatch' in nm[host] and nm[host]['osmatch']:
                    for osmatch in nm[host]['osmatch']:
                        os_details = {
                            "name": osmatch['name'],
                            "accuracy": osmatch['accuracy'],
                            "os_family": [osclass['osfamily'] for osclass in osmatch['osclass']] if 'osclass' in osmatch else []
                        }
                        host_data["os_details"].append(os_details)
                else:
                    # If no OS detection available, add a placeholder
                    host_data["os_details"].append({
                        "name": "OS detection not available (requires root privileges)",
                        "accuracy": "0",
                        "os_family": ["Unknown"]
                    })

                # Extract port details if available (common for -A scan, specifically TCP)
                if 'tcp' in nm[host]:
                    for port in nm[host]['tcp']:
                        host_data['ports'].append({
                            "port": port,
                            "state": nm[host]['tcp'][port]['state'],
                            "service": nm[host]['tcp'][port]['name']
                        })

                # Geolocation lookup
                try:
                    geo_resp = requests.get(f'http://ip-api.com/json/{host}', timeout=3)
                    if geo_resp.status_code == 200:
                        geo_data = geo_resp.json()
                        if geo_data.get('status') == 'success':
                            host_data['geolocation'] = {
                                'country': geo_data.get('country'),
                                'region': geo_data.get('regionName'),
                                'city': geo_data.get('city'),
                                'isp': geo_data.get('isp'),
                                'lat': geo_data.get('lat'),
                                'lon': geo_data.get('lon'),
                                'timezone': geo_data.get('timezone'),
                                'org': geo_data.get('org'),
                                'as': geo_data.get('as')
                            }
                except Exception as geo_err:
                    host_data['geolocation'] = {'error': str(geo_err)}
                active_hosts_details.append(host_data)
            else:
                print(f"Host {host} is {nm[host].state()}, skipping detailed info.")


        # Extract just the IP addresses for the frontend
        active_hosts_ips = [host["ip"] for host in active_hosts_details]
        
        # If nmap found no hosts, try fallback method
        if len(active_hosts_ips) == 0:
            print("Nmap found no hosts, trying fallback method...")
            try:
                script_path = os.path.join(os.path.dirname(__file__), 'device_scanner.py')
                # Convert CIDR back to dot notation for device_scanner.py
                fallback_target = target_range.replace('/24', '.') if target_range.endswith('/24') else target_range
                cmd = [sys.executable, script_path, 'network_discovery', fallback_target, '--timeout', '120']
                
                process = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=150)
                fallback_results = json.loads(process.stdout)
                
                if fallback_results.get("active_hosts"):
                    print(f"Fallback method found {len(fallback_results['active_hosts'])} hosts")
                    return jsonify({
                        "status": "success",
                        "message": "Network discovery completed (using fallback method).",
                        "results": {
                            "network": target_range,
                            "target_range": target_range + "1-254",
                            "hosts_discovered": len(fallback_results["active_hosts"]),
                            "total_hosts_scanned": 254,
                            "scan_time": "N/A",
                            "active_hosts": fallback_results["active_hosts"],
                            "active_hosts_details": []
                        }
                    })
            except Exception as e:
                print(f"Fallback method also failed: {e}")

        # Calculate actual scan time
        end_time = time.time()
        scan_duration = round(end_time - start_time, 2)
        scan_time = f"{scan_duration}s"
        
        return jsonify({
            "status": "success",
            "message": f"Network discovery completed in {scan_time}.",
            "results": {
                "network": target_range,
                "target_range": target_range + "1-254",  # Add this for frontend compatibility
                "hosts_discovered": len(active_hosts_details), # Count of hosts with detailed data and 'up' status
                "total_hosts_scanned": total_hosts_scanned, # Total hosts attempted to scan
                "scan_time": scan_time, # Actual scan duration
                "active_hosts": active_hosts_ips,  # Simple array of IPs for frontend
                "active_hosts_details": active_hosts_details  # Detailed data for future use
            }
        })

    except nmap.PortScannerError as e:
        print(f"Nmap error during network discovery: {e}")
        error_msg = f"Network scanning failed: {str(e)}"
        if "permission" in str(e).lower() or "root" in str(e).lower():
            error_msg += ". OS detection requires root privileges, but basic host discovery should still work."
        return jsonify({"status": "error", "message": error_msg}), 500
    except Exception as e:
        print(f"Internal server error during network discovery: {e}")
        # Try fallback method if main scan fails
        try:
            print("Main scan failed, trying fallback method...")
            script_path = os.path.join(os.path.dirname(__file__), 'device_scanner.py')
            fallback_target = target_range.replace('/24', '.') if target_range.endswith('/24') else target_range
            cmd = [sys.executable, script_path, 'network_discovery', fallback_target, '--timeout', '120']
            
            process = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=150)
            fallback_results = json.loads(process.stdout)
            
            if fallback_results.get("active_hosts"):
                return jsonify({
                    "status": "success",
                    "message": "Network discovery completed using fallback method.",
                    "results": {
                        "network": target_range,
                        "target_range": target_range + "1-254",
                        "hosts_discovered": len(fallback_results["active_hosts"]),
                        "total_hosts_scanned": 254,
                        "scan_time": "N/A",
                        "active_hosts": fallback_results["active_hosts"],
                        "active_hosts_details": []
                    }
                })
        except Exception as fallback_error:
            print(f"Fallback method also failed: {fallback_error}")
        
        return jsonify({"status": "error", "message": f"Network discovery failed: {str(e)}. Please check your network configuration and try again."}), 500


@app.route('/api/web/reset_zap_session', methods=['POST'])
def web_reset_zap_session_api():
    """
    API endpoint to reset OWASP ZAP's session.
    This clears all scan data and alerts.
    """
    if zap is None:
        return jsonify({"status": "error", "message": "ZAP API not connected. Cannot reset ZAP session."}), 500
    try:
        app.logger.info("Attempting to reset ZAP session via direct API call...")
        # Revert to using requests.get for newSession due to zapv2 client version incompatibility
        reset_response = requests.get(
            f'{ZAP_API_BASE_URL}core/action/newSession/',
            params={'apikey': ZAP_API_KEY, 'name': 'ResetSession', 'overwrite': 'true'},
            timeout=10 # Add timeout for ZAP API call
        )
        reset_response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        app.logger.info(f"ZAP Session Reset Response: {reset_response.json()}")
        # Also clear any active scans tracked by our Flask app
        # active_scans.clear() # This variable is not defined in the provided code, so commenting out
        return jsonify({"status": "success", "message": "ZAP session reset successfully."}), 200
    except requests.exceptions.ConnectionError as e:
        app.logger.error(f"Connection Error to ZAP during reset: {e}", exc_info=True)
        return jsonify({"status": "error", "message": f"Could not connect to ZAP API during reset. Ensure ZAP is running in daemon mode. Error: {str(e)}"}), 503
    except requests.exceptions.Timeout:
        app.logger.error(f"Timeout connecting to ZAP during reset.", exc_info=True)
        return jsonify({"status": "error", "message": "Timeout connecting to ZAP API during reset. ZAP might be unresponsive."}), 504
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error communicating with ZAP API during reset: {e}", exc_info=True)
        return jsonify({"status": "error", "message": f"Error communicating with ZAP API: {str(e)}. Ensure ZAP is running."}), 500
    except Exception as e:
        app.logger.error(f"General error resetting ZAP session: {e}", exc_info=True)
        return jsonify({"status": "error", "message": f"Failed to reset ZAP session: {str(e)}"}), 500

@app.route('/api/web/access_zap_url', methods=['POST'])
def access_zap_url_api():
    """
    Helper API endpoint to ensure ZAP has accessed a URL.
    This is crucial for ZAP to build its sites tree before scanning or reporting.
    """
    if zap is None:
        return jsonify({"status": "error", "message": "ZAP API not connected. Cannot access URL via ZAP."}), 500
    data = request.get_json()
    target_url = data.get('target_url')

    if not target_url:
        return jsonify({"status": "error", "message": "Target URL is required."}), 400

    try:
        app.logger.debug(f"Attempting to access URL in ZAP: {target_url}")
        # Use zapv2 client directly
        zap.urlopen(target_url)
        app.logger.debug(f"Successfully accessed {target_url} via ZAP.")
        return jsonify({"status": "success", "message": "URL accessed in ZAP."}), 200
    except Exception as e:
        app.logger.error(f"Error accessing URL via ZAP: {e}", exc_info=True)
        return jsonify({"status": "error", "message": f"Failed to access URL via ZAP: {str(e)}"}), 500

@app.route('/api/web/spider_status', methods=['GET'])
def get_spider_status():
    if zap is None:
        return jsonify({"status": "error", "message": "ZAP API not connected"}), 500
    
    # Get the latest scan_id from app config
    scan_ids = [k.replace('spider_scan_', '') for k in app.config.keys() if k.startswith('spider_scan_')]
    if not scan_ids:
        return jsonify({"status": "error", "message": "No spider scan in progress"}), 404
    
    scan_id = scan_ids[-1]  # Get most recent scan
    scan_info = app.config[f'spider_scan_{scan_id}']
    
    try:
        progress = int(zap.spider.status(scan_id))
        urls = []
        urls_found = 0
        
        if progress >= 100:
            # Scan complete, get results
            urls = zap.spider.results(scan_id)
            urls_found = len(urls)
            # Clean up stored scan info
            del app.config[f'spider_scan_{scan_id}']
            state = "completed"
        else:
            state = "in_progress"
        
        return jsonify({
            "status": "success",
            "state": state,
            "progress": progress,
            "urls_found": urls_found,
            "discovered_urls": urls if progress >= 100 else []
        })
        
    except Exception as e:
        app.logger.error(f"Error checking spider status: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/web/spider_scan', methods=['POST'])
def spider_scan():
    if zap is None:
        return jsonify({"status": "error", "message": "ZAP API not connected. Cannot perform spider scan."}), 500
    data = request.json
    target_url = data.get('target_url')

    if not target_url:
        return jsonify({"status": "error", "message": "Target URL is required."}), 400

    try:
        app.logger.info(f"Starting spider scan on {target_url}")
        scan_id = zap.spider.scan(url=target_url)
        
        # Store scan ID and target URL for status checks
        app.config[f'spider_scan_{scan_id}'] = {
            'target_url': target_url,
            'start_time': time.time()
        }
        
        return jsonify({
            "status": "success",
            "message": "Spider scan started",
            "scan_id": scan_id
        })

        # Get discovered URLs
        urls = zap.core.urls()
        # Filter for URLs belonging to the target domain, as ZAP might list others
        parsed_target = urlparse(target_url)
        base_domain = parsed_target.netloc
        discovered_urls = [url for url in urls if base_domain in url]
        
        return jsonify({
            "status": "success",
            "message": "Spider scan completed.",
            "discovered_urls_count": len(discovered_urls),
            "discovered_urls": discovered_urls
        })
    except Exception as e:
        app.logger.error(f"Error during spider scan: {e}", exc_info=True)
        return jsonify({"status": "error", "message": f"Failed to perform spider scan: {str(e)}"}), 500

# At the top of your app.py
active_scans = {}

@app.route('/api/web/active_scan', methods=['POST'])
def active_scan():
    if zap is None:
        return jsonify({"status": "error", "message": "ZAP API not connected. Cannot perform active scan."}), 500

    data = request.json
    target_url = data.get('target_url')
    if not target_url:
        return jsonify({"status": "error", "message": "Target URL is required."}), 400

    try:
        scan_id = zap.ascan.scan(url=target_url)
        app.logger.info(f"ZAP active scan initiated. Scan ID: {scan_id} for URL: {target_url}")
        # Optionally, store scan_id -> target_url mapping if you want to use it in status
        active_scans[str(scan_id)] = target_url
        return jsonify({
            "status": "success",
            "message": "Active scan initiated.",
            "scan_id": scan_id
        }), 202
    except Exception as e:
        app.logger.error(f"Error during active scan: {e}", exc_info=True)
        return jsonify({"status": "error", "message": f"Failed to perform active scan: {str(e)}"}), 500

# 2. Ensure /api/web/scan_status/<scan_id> returns a 'progress' field (0-100)
@app.route('/api/web/scan_status/<scan_id>', methods=['GET'])
def scan_status(scan_id):
    try:
        zap = get_zap_instance()
        status = int(zap.ascan.status(scan_id))
        alerts = zap.core.alerts()
        if status < 100:
            return jsonify({
                "status": "running",
                "progress": status,
                "detailed_alerts": alerts
            }), 200
        else:
            return jsonify({
                "status": "completed",
                "progress": 100,
                "detailed_alerts": alerts
            }), 200
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to get scan status: {str(e)}"
        }), 500

# Helper: get ZAP instance

def get_zap_instance():
    try:
        ZAP_API_KEY = os.environ.get('ZAP_API_KEY', 't9zmbgqgmhup8prnbg21bt')
        ZAP_ADDRESS = os.environ.get('ZAP_ADDRESS', '127.0.0.1')
        ZAP_PORT = os.environ.get('ZAP_PORT', '8080')
        
        # Connect directly to ZAP API - simple initialization
        zap_instance = ZAPv2(apikey=ZAP_API_KEY)
        # Test the connection by getting the version (it's a property, not a method)
        version = zap_instance.core.version
        return zap_instance
    except Exception as e:
        print(f"Error connecting to ZAP: {e}")
        return None

# Helper: risk level to color tag
RISK_COLOR = {
    'Informational': '#3498db',  # blue
    'Low': '#27ae60',            # green
    'Medium': '#f1c40f',         # yellow
    'High': '#e67e22',           # orange
    'Critical': '#e74c3c',       # red
    'No risk': '#3498db',        # blue
}
def risk_tag(risk):
    color = RISK_COLOR.get(risk, '#7f8c8d')
    return f'<span style="background-color:{color};color:#fff;padding:2px 8px;border-radius:8px;font-size:0.9em;">{risk}</span>'

# Helper for risk color and label
RISK_MAP = {
    '0': ('#2196f3', 'Informational'),  # Blue
    '1': ('#4caf50', 'Low'),            # Green
    '2': ('#ffeb3b', 'Medium'),         # Yellow
    '3': ('#ff9800', 'High'),           # Orange
    '4': ('#f44336', 'Critical'),       # Red
}

def get_risk_tag(riskcode):
    color, label = RISK_MAP.get(str(riskcode), ('#757575', 'Unknown'))
    return f'<span style="background-color:{color};color:#fff;padding:2px 8px;border-radius:8px;font-size:0.9em;margin-right:6px;">{label}</span>'

@app.route('/api/web/generate_native_report', methods=['POST'])
def generate_native_report():
    try:
        data = request.get_json()
        target_url = data.get('target_url')
        if not target_url:
            return jsonify({'status': 'error', 'message': 'Missing target_url'}), 400
        zap = get_zap_instance()
        if zap is None:
            return jsonify({'status': 'error', 'message': 'ZAP is not available. Please start OWASP ZAP and ensure it is accessible at 127.0.0.1:8080'}), 500
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_filename = f"zap_native_report_{timestamp}.html"
        report_path = os.path.join(REPORTS_FOLDER, report_filename)
        try:
            html_report = zap.core.htmlreport()
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(html_report)
        except Exception as e:
            return jsonify({'status': 'error', 'message': f'Failed to generate native report: {str(e)}'}), 500
        report_url = f"http://127.0.0.1:5000/reports/{report_filename}"
        return jsonify({'status': 'success', 'report_url': report_url}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/web/generate_custom_report', methods=['POST'])
def generate_custom_report():
    try:
        data = request.get_json()
        target_url = data.get('target_url')
        report_name = data.get('report_name', 'Dark_Custom_Report')
        if not target_url:
            return jsonify({'status': 'error', 'message': 'Missing target_url'}), 400
        zap = get_zap_instance()
        if zap is None:
            return jsonify({'status': 'error', 'message': 'ZAP is not available. Please start OWASP ZAP and ensure it is accessible at 127.0.0.1:8080'}), 500
        
        alerts_raw = zap.core.alerts(baseurl=target_url, start=0, count=9999)
        if isinstance(alerts_raw, dict) and 'alerts' in alerts_raw:
            alerts = alerts_raw['alerts']
        elif isinstance(alerts_raw, list):
            alerts = alerts_raw
        else:
            alerts = []
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        file_name = f"{report_name}_dark_custom.html"
        report_path = os.path.join(REPORTS_FOLDER, file_name)
        # Calculate highest risk for gallery
        risk_order = ['critical', 'high', 'medium', 'low', 'informational', 'none']
        found_risks = set(a.get('risk', 'none').lower() for a in alerts)
        highest_risk = 'none'
        for r in risk_order:
            if r in found_risks:
                highest_risk = r
                break
        # Purplish theme CSS
        html_content = f"""
        <!DOCTYPE html>
        <html lang='en'>
        <head>
            <meta charset='UTF-8'>
            <meta name='viewport' content='width=device-width, initial-scale=1.0'>
            <title>{report_name} - Dark Custom Security Report</title>
            <style>
                body {{ background: #231942; color: #f3e8ff; font-family: 'Inter', sans-serif; }}
                .container {{ max-width: 900px; margin: 40px auto; padding: 30px; background: #32235a; border-radius: 18px; box-shadow: 0 0 24px #0003; }}
                h1, h2, h3 {{ color: #a259ec; text-align: center; margin-bottom: 0.5em; }}
                h1 {{ font-size: 2.2em; }}
                h2 {{ font-size: 1.5em; margin-top: 2em; }}
                h3 {{ font-size: 1.2em; margin-top: 1.5em; }}
                .summary {{ background: #2d1950; border-radius: 12px; padding: 1.5em; margin-bottom: 2em; }}
                .summary-item {{ display: flex; justify-content: space-between; padding: 0.5em 0; border-bottom: 1px solid #3d2c5a; }}
                .summary-item:last-child {{ border-bottom: none; }}
                .risk-critical {{ color: #a259ec; }}
                .risk-high {{ color: #e94560; }}
                .risk-medium {{ color: #f7b731; }}
                .risk-low {{ color: #4dd599; }}
                .risk-informational {{ color: #5b8dee; }}
                .risk-none {{ color: #6c47a3; }}
                .alert-card {{ background: #2d1950; border-radius: 10px; margin-bottom: 1.5em; padding: 1.2em; box-shadow: 0 2px 8px #0002; }}
                .risk-tag {{ display: inline-block; padding: 2px 12px; border-radius: 6px; color: #fff; font-size: 0.95em; margin-bottom: 0.5em; font-weight: bold; }}
                .footer {{ text-align: center; margin-top: 40px; font-size: 0.9em; color: #b39ddb; }}
                a {{ color: #5b8dee; }}
                pre {{ background: #231942; color: #f3e8ff; border-radius: 6px; padding: 0.7em; overflow-x: auto; }}
            </style>
        </head>
        <body>
            <div class='container'>
                <h1>{report_name} - Dark Custom Security Report</h1>
                <p style='text-align:center;color:#e94560;'><strong>Generated On:</strong> {timestamp}</p>
                <p style='text-align:center;'>This report provides a summary and detailed listing of vulnerabilities identified during the web application scan using OWASP ZAP.</p>
                <h2>Summary of Vulnerabilities</h2>
                <div class='summary'>
                    <div class='summary-item'><span>Critical:</span> <span class='risk-critical'>{sum(1 for a in alerts if a.get('risk', '').lower() == 'critical')}</span></div>
                    <div class='summary-item'><span>High:</span> <span class='risk-high'>{sum(1 for a in alerts if a.get('risk', '').lower() == 'high')}</span></div>
                    <div class='summary-item'><span>Medium:</span> <span class='risk-medium'>{sum(1 for a in alerts if a.get('risk', '').lower() == 'medium')}</span></div>
                    <div class='summary-item'><span>Low:</span> <span class='risk-low'>{sum(1 for a in alerts if a.get('risk', '').lower() == 'low')}</span></div>
                    <div class='summary-item'><span>Informational:</span> <span class='risk-informational'>{sum(1 for a in alerts if a.get('risk', '').lower() == 'informational')}</span></div>
                    <div class='summary-item'><span>No Risk:</span> <span class='risk-none'>{sum(1 for a in alerts if a.get('risk', '').lower() == 'none')}</span></div>
                </div>
                <h2>Detailed Alerts</h2>
        """
        if alerts:
            for alert in alerts:
                risk = alert.get('risk', 'none').lower()
                color = {
                    'critical': '#a259ec',
                    'high': '#e94560',
                    'medium': '#f7b731',
                    'low': '#4dd599',
                    'informational': '#5b8dee',
                    'none': '#6c47a3',
                }.get(risk, '#6c47a3')
                html_content += f"<div class='alert-card'><span class='risk-tag' style='background:{color}'>{risk.capitalize()}</span> <b>{alert.get('alert','No title')}</b><br><b>URL:</b> <a href='{alert.get('url','N/A')}' target='_blank'>{alert.get('url','N/A')}</a><br><b>Confidence:</b> {alert.get('confidence','N/A')}<br><b>Description:</b><pre>{alert.get('description','')}</pre><b>Solution:</b><pre>{alert.get('solution','N/A')}</pre></div>"
        else:
            html_content += "<div style='margin:2em;'>No vulnerabilities found.</div>"
        html_content += """
                <div class='footer'>
                    <p>&copy; {year} Haroon Allahdad - CyberGuard FYP. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """.replace('{year}', time.strftime('%Y'))
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        # Save highest_risk to metadata
        metadata = load_metadata()
        metadata[file_name] = {
            "title": f"ZAP Native Report: {target_url}",
            "description": f"ZAP Native Report for {target_url}. Highest detected risk: {highest_risk.capitalize()}.",
            "fileName": file_name,
            "fileType": "text/html",
            "fileUrl": f"http://127.0.0.1:5000/reports/{file_name}",
            "source": "zap_report",
            "highest_risk": highest_risk,
            "timestamp": time.time()
        }
        save_metadata(metadata)
        report_url = f"http://127.0.0.1:5000/reports/{file_name}"
        return jsonify({
            'status': 'success',
            'message': 'Dark Custom report generated successfully.',
            'file_name': file_name,
            'report_url': report_url
        }), 200
    except Exception as e:
        app.logger.error(f"Error in generate_custom_report: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': f'Failed to generate custom report: {str(e)}'}), 500

# Serve reports statically
@app.route('/reports/<path:filename>')
def serve_report(filename):
    return send_from_directory(REPORTS_FOLDER, filename)

@app.route('/api/web/generate_classic_custom_report', methods=['POST'])
def generate_classic_custom_report():
    try:
        data = request.get_json()
        target_url = data.get('target_url')
        if not target_url:
            return jsonify({'status': 'error', 'message': 'Missing target_url'}), 400
        zap = get_zap_instance()
        alerts = zap.core.alerts(baseurl=target_url, start=0, count=9999)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_filename = f"classic_zap_custom_report_{timestamp}.html"
        report_path = os.path.join(REPORTS_FOLDER, report_filename)
        html = f"""
        <html><head><meta charset='utf-8'><title>Classic ZAP Custom Report</title>
        <style>body{{background:#f4f4f4;color:#333;font-family:sans-serif;}}.alert{{background:#fff;border-left:6px solid #2196f3;padding:15px;margin-bottom:15px;border-radius:5px;}}.risk-Critical{{border-color:#f44336;}}.risk-High{{border-color:#ff9800;}}.risk-Medium{{border-color:#ffc107;}}.risk-Low{{border-color:#4caf50;}}.risk-Informational{{border-color:#2196f3;}}</style></head><body>
        <h1>Classic ZAP Custom Report</h1>
        <h2>Target: {target_url}</h2>
        <h3>Generated: {timestamp}</h3>
        """
        if alerts.get('alerts'):
            for alert in alerts['alerts']:
                risk = alert.get('risk', 'Informational')
                html += f"<div class='alert risk-{risk}'><b>{alert.get('alert','No title')}</b><br><span>{alert.get('description','')}</span><br><b>URL:</b> {alert.get('url','N/A')}<br><b>Solution:</b> {alert.get('solution','N/A')}</div>"
        else:
            html += "<div style='margin:2em;'>No vulnerabilities found.</div>"
        html += "<div style='text-align:center;margin-top:40px;font-size:0.9em;color:#666;'><p>&copy; " + time.strftime('%Y') + " Haroon Allahdad - CyberGuard FYP. All rights reserved.</p></div></body></html>"
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html)
        report_url = f"http://127.0.0.1:5000/reports/{report_filename}"
        return jsonify({'status': 'success', 'report_url': report_url}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/web/generate_6risk_report', methods=['POST'])
def generate_6risk_report():
    try:
        data = request.get_json()
        target_url = data.get('target_url')
        report_name = data.get('report_name', 'Light_Custom_Report')
        if not target_url:
            return jsonify({'status': 'error', 'message': 'Missing target_url'}), 400
        zap = get_zap_instance()
        alerts_raw = zap.core.alerts(baseurl=target_url, start=0, count=9999)
        if isinstance(alerts_raw, dict) and 'alerts' in alerts_raw:
            alerts = alerts_raw['alerts']
        elif isinstance(alerts_raw, list):
            alerts = alerts_raw
        else:
            alerts = []
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        file_name = f"Light_Custom_Report_{re.sub(r'[^a-zA-Z0-9]', '_', target_url)}_{int(time.time())}.html"
        report_path = os.path.join(REPORTS_FOLDER, file_name)
        # Calculate highest risk for gallery
        risk_order = ['critical', 'high', 'medium', 'low', 'informational', 'none']
        found_risks = set(a.get('risk', 'none').lower() for a in alerts)
        highest_risk = 'none'
        for r in risk_order:
            if r in found_risks:
                highest_risk = r
                break
        # White/Blue theme CSS for 6-risk
        html_content = f"""
        <!DOCTYPE html>
        <html lang='en'>
        <head>
            <meta charset='UTF-8'>
            <meta name='viewport' content='width=device-width, initial-scale=1.0'>
            <title>{report_name} - CyberGuard Risk Matrix Report</title>
            <link href='https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap' rel='stylesheet'>
            <style>
                body {{ background: #f0f2f5; color: #333; font-family: 'Inter', sans-serif; }}
                .container {{ max-width: 960px; margin: 2rem auto; padding: 2rem; background: #fff; border-radius: 0.75rem; box-shadow: 0 4px 10px rgba(0,0,0,0.1); }}
                h1, h2, h3 {{ color: #1a202c; margin-bottom: 1rem; }}
                h1 {{ font-size: 2.5rem; text-align: center; color: #4f46e5; }}
                h2 {{ font-size: 1.8rem; border-bottom: 2px solid #e2e8f0; padding-bottom: 0.5rem; margin-top: 2rem; }}
                h3 {{ font-size: 1.4rem; color: #4f46e5; }}
                .summary {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 0.5rem; padding: 1.5rem; margin-bottom: 1.5rem; }}
                .summary-item {{ display: flex; justify-content: space-between; padding: 0.5rem 0; border-bottom: 1px dashed #e2e8f0; }}
                .summary-item:last-child {{ border-bottom: none; }}
                .risk-critical {{ color: #dc2626; font-weight: 600; }}
                .risk-high {{ color: #ef4444; font-weight: 600; }}
                .risk-medium {{ color: #f97316; font-weight: 600; }}
                .risk-low {{ color: #facc15; font-weight: 600; }}
                .risk-informational {{ color: #3b82f6; font-weight: 600; }}
                .risk-none {{ color: #22c55e; font-weight: 600; }}
                .alert-card {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 0.5rem; padding: 1.5rem; margin-bottom: 1.5rem; }}
                .risk-tag {{ display: inline-block; padding: 2px 12px; border-radius: 6px; color: #fff; font-size: 0.95em; margin-bottom: 0.5em; font-weight: bold; }}
                .tag-critical {{ background: #dc2626; }}
                .tag-high {{ background: #ef4444; }}
                .tag-medium {{ background: #f97316; }}
                .tag-low {{ background: #facc15; color: #333; }}
                .tag-informational {{ background: #3b82f6; }}
                .tag-none {{ background: #22c55e; }}
                .footer {{ text-align: center; margin-top: 40px; font-size: 0.9em; color: #64748b; }}
                a {{ color: #4f46e5; }}
                pre {{ background: #e2e8f0; padding: 1rem; border-radius: 0.5rem; overflow-x: auto; font-size: 0.875rem; }}
            </style>
        </head>
        <body>
            <div class='container'>
                <h1>Light Custom Security Report</h1>
                <p style='text-align:center;color:#2563eb;'><strong>Generated On:</strong> {timestamp}</p>
                <p style='text-align:center;'>This report provides a summary and detailed listing of vulnerabilities identified during the web application scan using OWASP ZAP, categorized by the CyberGuard 6-Risk Matrix.</p>
                <h2>CVSS 6-Risk Legend</h2>
                <div style='display:flex;justify-content:center;gap:10px;flex-wrap:wrap;margin-bottom:1.5em;'>
                    <span class='risk-tag tag-critical'>Critical</span>
                    <span class='risk-tag tag-high'>High</span>
                    <span class='risk-tag tag-medium'>Medium</span>
                    <span class='risk-tag tag-low'>Low</span>
                    <span class='risk-tag tag-informational'>Informational</span>
                    <span class='risk-tag tag-none'>None</span>
                </div>
                <h2>Summary of Vulnerabilities</h2>
                <div class='summary'>
                    <div class='summary-item'><span>Critical:</span> <span class='risk-critical'>{sum(1 for a in alerts if a.get('risk', '').lower() == 'critical')}</span></div>
                    <div class='summary-item'><span>High:</span> <span class='risk-high'>{sum(1 for a in alerts if a.get('risk', '').lower() == 'high')}</span></div>
                    <div class='summary-item'><span>Medium:</span> <span class='risk-medium'>{sum(1 for a in alerts if a.get('risk', '').lower() == 'medium')}</span></div>
                    <div class='summary-item'><span>Low:</span> <span class='risk-low'>{sum(1 for a in alerts if a.get('risk', '').lower() == 'low')}</span></div>
                    <div class='summary-item'><span>Informational:</span> <span class='risk-informational'>{sum(1 for a in alerts if a.get('risk', '').lower() == 'informational')}</span></div>
                    <div class='summary-item'><span>No Risk:</span> <span class='risk-none'>{sum(1 for a in alerts if a.get('risk', '').lower() == 'none')}</span></div>
                </div>
                <h2>Detailed Alerts</h2>
        """
        if alerts:
            for alert in alerts:
                risk = alert.get('risk', 'none').lower()
                tag_class = {
                    'critical': 'tag-critical',
                    'high': 'tag-high',
                    'medium': 'tag-medium',
                    'low': 'tag-low',
                    'informational': 'tag-informational',
                    'none': 'tag-none',
                }.get(risk, 'tag-none')
                html_content += f"<div class='alert-card'><span class='risk-tag {tag_class}'>{risk.capitalize()}</span> <b>{alert.get('alert','No title')}</b><br><b>URL:</b> <a href='{alert.get('url','N/A')}' target='_blank'>{alert.get('url','N/A')}</a><br><b>Confidence:</b> {alert.get('confidence','N/A')}<br><b>Description:</b><pre>{alert.get('description','')}</pre><b>Solution:</b><pre>{alert.get('solution','N/A')}</pre></div>"
        else:
            html_content += "<div style='margin:2em;'>No vulnerabilities found.</div>"
        html_content += """
                <div class='footer'>
                    <p>&copy; {year} Haroon Allahdad - CyberGuard FYP. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """.replace('{year}', time.strftime('%Y'))
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        # Save highest_risk to metadata
        metadata = load_metadata()
        metadata[file_name] = {
            "title": f"Light Custom Security Report: {target_url}",
            "description": f"Light Custom Security Report for {target_url}. Highest detected risk: {highest_risk.capitalize()}.",
            "fileName": file_name,
            "fileType": "text/html",
            "fileUrl": f"http://127.0.0.1:5000/reports/{file_name}",
            "source": "zap_report",
            "highest_risk": highest_risk,
            "timestamp": time.time()
        }
        save_metadata(metadata)
        report_url = f"http://127.0.0.1:5000/reports/{file_name}"
        return jsonify({
            'status': 'success',
            'message': 'Light Custom report generated successfully.',
            'file_name': file_name,
            'report_url': report_url
        }), 200
    except Exception as e:
        app.logger.error(f"Error in generate_6risk_report: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': f'Failed to generate 6-risk report: {str(e)}'}), 500

def _guess_mime_type(filename):
    import mimetypes
    mime, _ = mimetypes.guess_type(filename)
    return mime or 'application/octet-stream'

if __name__ == '__main__':
    # Make sure your app runs with socketio.run
    # allow_unsafe_werkzeug=True is for development only
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True) 
