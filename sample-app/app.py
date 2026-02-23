from flask import Flask, request, jsonify
import sqlite3
import logging
import os
import subprocess # nosec
import requests
import pickle # nosec
from flasgger import Swagger

app = Flask(__name__)
swagger = Swagger(app)

# Intentional Flaw 3: Insecure Logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Intentional Flaw 1: Hardcoded Secret (Fixed)
API_KEY = os.environ.get("API_KEY", "default_key")
DB_USER = os.environ.get("DB_USER", "admin")
DB_PASS = os.environ.get("DB_PASS", "default_pass")

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    c.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('admin', 'admin123')")
    conn.commit()
    conn.close()

@app.route('/login', methods=['POST'])
def login():
    """
    User Login
    ---
    tags:
      - Authentication
    parameters:
      - in: body
        name: user
        description: The user to log in.
        schema:
          type: object
          required:
            - username
            - password
          properties:
            username:
              type: string
            password:
              type: string
    responses:
      200:
        description: Login successful
      401:
        description: Invalid credentials
    """
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    # Insecure logging - logging plaintext password
    logger.debug(f"Attempting login for user: {username} with password: {password}")
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Intentional Flaw 2: Weak Validation / SQL Injection (Fixed)
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    c.execute(query, (username, password))
    
    user = c.fetchone()
    conn.close()
    
    if user:
        return jsonify({"message": "Login successful", "token": API_KEY}), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401

@app.route('/ping', methods=['GET'])
def ping():
    """
    Ping IP
    ---
    tags:
      - Utility
    parameters:
      - in: query
        name: ip
        type: string
        default: 127.0.0.1
        description: The IP address to ping
    responses:
      200:
        description: Ping result
    """
    ip = request.args.get('ip', '127.0.0.1')
    # Intentional Flaw 2b: Command Injection (Fixed)
    result = subprocess.run(["ping", "-c", "1", ip], capture_output=True, text=True).stdout # nosec
    return jsonify({"result": result})

# --- CODEQL VULNERABILITIES BELOW ---

@app.route('/fetch_url', methods=['GET'])
def fetch_url():
    """
    CodeQL Vuln 1: Server-Side Request Forgery (SSRF)
    """
    url = request.args.get('url')
    if not url:
        return "Please provide a URL", 400
    
    # Intentional Flaw 4: SSRF (Fetching unvalidated user-provided URL)
    resp = requests.get(url, timeout=5) # nosec
    return jsonify({"content": resp.text[:100]})

@app.route('/load_data', methods=['POST'])
def load_data():
    """
    CodeQL Vuln 2: Insecure Deserialization
    """
    data = request.data
    if not data:
        return "No data provided", 400
        
    # Intentional Flaw 5: Insecure Deserialization (Unpickling untrusted user data)
    obj = pickle.loads(data) # nosec
    return jsonify({"status": "Data loaded"})

if __name__ == '__main__':
    init_db()
    app.run(host='127.0.0.1', debug=False, port=5000)
