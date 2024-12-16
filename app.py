from flask import Flask, render_template, request
import random
import string
import socket
import requests
import re

app = Flask(__name__)

def scan_ports(target_ip, ports):
    open_ports = []
    services = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex((target_ip, port)) == 0:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "Unknown Service"
                open_ports.append(port)
                services.append(service)
            sock.close()
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
    return open_ports, services

def generate_password(length):
    if length < 6:
        return "Password too short! Must be at least 6 characters."
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

def scan_vulnerabilities(url):
    vulnerability_patterns = {
        "Outdated Software": r"Apache/2\.2\.|PHP/5\.",
        "Exposed Version": r"X-Powered-By: (.+)",
        "SQL Error": r"SQL syntax.*MySQL|Warning.*mysql_.*|MySQL Query fail",
        "PHP Error": r"Fatal error.*|Parse error.*",
    }
    findings = []
    try:
        response = requests.get(url, timeout=5)
        for vuln, pattern in vulnerability_patterns.items():
            if re.search(pattern, response.text, re.IGNORECASE):
                findings.append(f"Potential {vuln} in content")
            for header, value in response.headers.items():
                if re.search(pattern, value, re.IGNORECASE):
                    findings.append(f"Potential {vuln} in header '{header}'")
    except requests.RequestException as e:
        findings.append(f"Error: {e}")
    return findings

def brute_force_directories(url, directories):
    accessible_dirs = []
    for directory in directories:
        full_url = f"{url.rstrip('/')}/{directory}"
        try:
            response = requests.get(full_url, timeout=5)
            if response.status_code == 200:
                accessible_dirs.append(full_url)
        except requests.RequestException:
            pass
    return accessible_dirs

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/tools')
def tools():
    return render_template('tools.html')

@app.route('/portscanner', methods=['GET', 'POST'])
def portscanner():
    open_ports = []
    services = []
    error = None
    target = ""

    if request.method == 'POST':
        target = request.form.get('ip', '').strip()
        ports_input = request.form.get('ports', '80,443,22,53')

        if not target:
            error = "Please provide a valid domain or IP address."
        else:
            try:
                target_ip = socket.gethostbyname(target)
                try:
                    ports = [int(p) for p in ports_input.split(',')]
                except ValueError:
                    error = "Ports must be a comma-separated list of numbers."
                if not error:
                    open_ports, services = scan_ports(target_ip, ports)
            except socket.gaierror:
                error = "Invalid domain or IP address."

    return render_template('portscanner.html', open_ports=open_ports, services=services, target=target, error=error)

@app.route('/password_gen', methods=['GET', 'POST'])
def password_gen():
    password = None
    if request.method == 'POST':
        try:
            length = int(request.form['length'])
            password = generate_password(length)
        except ValueError:
            password = "Invalid input! Length must be a number."
    return render_template('password_gen.html', password=password)

@app.route('/vulnscanner', methods=['GET', 'POST'])
def vulnscanner():
    findings = None
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if url:
            findings = scan_vulnerabilities(url)
        else:
            findings = ["Please enter a valid URL."]
    return render_template('vulnscanner.html', findings=findings)

@app.route('/brute_forcer', methods=['GET', 'POST'])
def brute_forcer():
    accessible_dirs = None
    if request.method == 'POST':
        url = request.form.get('brute_url', '').strip()
        directories = request.form.get('directories', 'admin,login,dashboard,test').split(',')
        if url:
            accessible_dirs = brute_force_directories(url, directories)
    return render_template('brute_forcer.html', accessible_dirs=accessible_dirs)

if __name__ == '__main__':
    app.run(debug=True)
