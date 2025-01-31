from flask import Flask, request, jsonify, render_template, redirect, url_for, session, Response
import json
import requests
import subprocess
import os
from datetime import datetime
from functools import wraps
import threading
import time
from flask import send_file

# Flask app initialization
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "supersecretkey")  # Use an environment variable in production

# Constants
OSV_API = "https://api.osv.dev/v1/query"
REPORT_DIR = "security_reports"
LOG_FILE = "scan_logs.txt"
USERS = {"admin": "password123"}  # Replace with a proper authentication system

# Ensure report directory exists
if not os.path.exists(REPORT_DIR):
    os.makedirs(REPORT_DIR)

# Authentication Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# ✅ Get installed packages using `pip freeze`
def get_installed_packages():
    try:
        result = subprocess.run(["python", "-m", "pip", "freeze"], capture_output=True, text=True, check=True)
        packages = result.stdout.strip().split("\n")
        parsed_packages = []
        for package in packages:
            if "==" in package:
                name, version = package.split("==")
                parsed_packages.append({"name": name, "version": version})
        return parsed_packages
    except subprocess.CalledProcessError as e:
        log_message(f"Error fetching installed packages: {str(e)}")
        return []

# ✅ Check vulnerabilities using OSV API
def check_vulnerabilities(package_name, version):
    data = {"package": {"name": package_name, "ecosystem": "PyPI"}, "version": version}
    try:
        response = requests.post(OSV_API, json=data)
        if response.status_code == 200:
            return response.json().get("vulns", [])
    except requests.RequestException as e:
        log_message(f"Error querying OSV API for {package_name}: {str(e)}")
    return []

# ✅ Function to write logs with UTF-8 encoding
def log_message(message):
    with open(LOG_FILE, "a", encoding="utf-8") as log_file:  # ✅ Force UTF-8 encoding
        log_file.write(message + "\n")
    print(message)  # Print to console too
# ✅ Streaming function for real-time logs
def generate_logs():
    with open(LOG_FILE, "r") as f:
        while True:
            line = f.readline()
            if line:
                yield f"data: {line}\n\n"
            time.sleep(1)  # Prevent CPU overuse
# ✅ Run package scan in a separate thread
def run_package_scan():
    log_message("Starting Package Scan...")
    packages = get_installed_packages()
    report = []

    for package in packages:
        name, version = package["name"], package["version"]
        log_message(f"Scanning {name} ({version})...")
        vulnerabilities = check_vulnerabilities(name, version)

        if vulnerabilities:
            report.append({"package": name, "version": version, "vulnerabilities": vulnerabilities})

    zip_path = save_report(report, "package_scan.json")  # ✅ Ensure report is saved & compressed
    log_message("Package Scan Completed.")
    return zip_path

@app.route('/logs')
def logs():
    return Response(generate_logs(), mimetype='text/event-stream')

@app.route('/scan/packages', methods=['GET'])
@login_required
def scan_packages():
    thread = threading.Thread(target=run_package_scan)
    thread.start()
    return redirect(url_for("scan_status"))

@app.route('/scan/status', methods=['GET'])
@login_required
def scan_status():
    return render_template('scan_status.html')

import zipfile

def save_report(report, filename):
    """Save report as JSON and compress it into a ZIP file."""
    file_path = os.path.join(REPORT_DIR, filename)
    zip_path = file_path.replace(".json", ".zip")

    # ✅ Save JSON Report
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    # ✅ Create ZIP Archive
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(file_path, arcname=filename)

    log_message(f"Report saved: {file_path}")
    log_message(f"Compressed report: {zip_path}")

    return zip_path  # ✅ Return ZIP file path

@app.route('/download/<filename>')
@login_required
def download_report(filename):
    """Serve the ZIP report file for download."""
    file_path = os.path.join(REPORT_DIR, filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return "File not found", 404

@app.route('/scan/report', methods=['GET'])
@login_required
def view_scan_report():
    """Load scan report JSON and render it in the UI"""
    report_path = os.path.join(REPORT_DIR, "package_scan.json")
    
    if not os.path.exists(report_path):
        return "No scan report found", 404

    with open(report_path, "r", encoding="utf-8") as f:
        report_data = json.load(f)

    # Process vulnerabilities correctly
    for package in report_data:
        for vuln in package.get("vulnerabilities", []):
            # Extract severity safely
            severity = "UNKNOWN"
            
            if "database_specific" in vuln and "severity" in vuln["database_specific"]:
                severity = vuln["database_specific"]["severity"]
            elif "severity" in vuln and isinstance(vuln["severity"], list):
                severity = vuln["severity"][0].get("type", "UNKNOWN")
            
            vuln["severity_level"] = severity or "NULL"

            # Extract fixed version if available
            vuln["fixed_version"] = "Not Fixed"
            if "affected" in vuln and isinstance(vuln["affected"], list):
                for affected in vuln["affected"]:
                    if "ranges" in affected:
                        for event in affected["ranges"][0].get("events", []):
                            if "fixed" in event:
                                vuln["fixed_version"] = event["fixed"]

            # Process references properly
            vuln["reference_links"] = [ref["url"] for ref in vuln.get("references", [])]

    return render_template("scan_report.html", report=report_data)

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if USERS.get(username) == password:
            session['user'] = username
            return redirect(url_for('index'))
        return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
