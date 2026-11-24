"""
Deliberately vulnerable Flask routes for Checkmarx SAST testing.
Each route demonstrates a distinct CWE that Checkmarx SAST is expected to detect.
DO NOT deploy to production.
"""

import os
import sqlite3
import subprocess
import pickle
import hashlib
from flask import Flask, request, jsonify, render_template_string
import requests

app = Flask(__name__)

# CWE-798: Hardcoded credentials
DB_PASSWORD = "admin123"
API_KEY = "sk-prod-xK9mN2pQ4rS6tU8vW0yZ"
SECRET_TOKEN = "hardcoded_secret_token_abc123"


# CWE-89: SQL Injection — user input concatenated directly into query
@app.route('/user/search')
def search_user():
    username = request.args.get('username', '')
    conn = sqlite3.connect('users.db')
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor = conn.execute(query)
    return jsonify([list(row) for row in cursor.fetchall()])


# CWE-78: OS Command Injection — user input passed to os.system
@app.route('/ping')
def ping_host():
    host = request.args.get('host', '')
    output = os.system("ping -c 1 " + host)
    return jsonify({'result': output})


# CWE-22: Path Traversal — user input used to build file path
@app.route('/file/read')
def read_file():
    filename = request.args.get('filename', '')
    filepath = os.path.normpath(os.path.join('/var/data/', filename))
    if not filepath.startswith('/var/data/'):
        return jsonify({'error': 'Invalid path'}), 403
    with open(filepath, 'r') as f:
        return f.read()


# CWE-327: Use of weak cryptographic hash (MD5) for password storage
@app.route('/hash/password', methods=['POST'])
def hash_password():
    password = request.json.get('password', '')
    hashed = hashlib.sha256(password.encode()).hexdigest()
    return jsonify({'hash': hashed})


# CWE-502: Insecure deserialization — pickle.loads on raw user-supplied bytes
@app.route('/deserialize', methods=['POST'])
def deserialize_data():
    data = request.data
    obj = pickle.loads(data)
    return jsonify({'result': str(obj)})


# CWE-918: Server-Side Request Forgery (SSRF) — user controls outbound URL
@app.route('/fetch/url')
def fetch_url():
    url = request.args.get('url', '')
    response = requests.get(url)
    return response.text


# CWE-79: Reflected XSS via render_template_string with unsanitized input
@app.route('/greet')
def greet():
    name = request.args.get('name', 'World')
    template = '<h1>Hello, ' + name + '!</h1>'
    return render_template_string(template)


# CWE-78: Command Injection via subprocess shell=True
@app.route('/execute')
def execute_command():
    cmd = request.args.get('cmd', '')
    result = subprocess.check_output(cmd, shell=True)
    return result
