import requests
import socket
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from datetime import datetime
import dns.resolver
import json
from rich.console import Console
from rich.progress import track

console = Console()

# Utility Functions
def log_info(message):
    console.print(f"[cyan][INFO] {message}[/cyan]")

def log_success(message):
    console.print(f"[green][SUCCESS] {message}[/green]")

def log_warning(message):
    console.print(f"[yellow][WARNING] {message}[/yellow]")

def log_error(message):
    console.print(f"[red][ERROR] {message}[/red]")

# Automated Wordlist Generator
def generate_wordlist(target):
    log_info("Generating dynamic wordlist...")
    wordlist = ["admin", "login", "test", "backup", "config"]
    domain_parts = urlparse(target).netloc.split(".")
    for part in domain_parts:
        if part not in wordlist:
            wordlist.append(part)
    return wordlist

# Hidden Content Discovery
def discover_hidden_content(target):
    log_info("Discovering hidden content...")
    discovered = []
    for path in ["/robots.txt", "/sitemap.xml"]:
        url = f"{target}{path}"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                log_success(f"Hidden content found: {url}")
                discovered.append({"path": path, "status_code": response.status_code, "content": response.text[:200]})
        except requests.RequestException:
            pass
    return discovered

# Subdomain Discovery
def discover_subdomains(target):
    log_info("Discovering subdomains...")
    subdomains = ["www", "api", "test", "dev", "staging"]
    discovered = []

    for sub in progress_bar(subdomains, "Scanning subdomains..."):
        subdomain = f"{sub}.{urlparse(target).netloc}"
        try:
            socket.gethostbyname(subdomain)
            log_success(f"Subdomain found: {subdomain}")
            discovered.append(subdomain)
        except socket.gaierror:
            pass
    return discovered

# Directory Scanning
def scan_directories(target, wordlist):
    log_info("Scanning directories...")
    discovered = []
    for word in progress_bar(wordlist, "Scanning paths..."):
        url = f"{target}/{word}"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                log_success(f"Directory found: {url}")
                discovered.append({"path": word, "status_code": response.status_code})
        except requests.RequestException:
            pass
    return discovered

# Automated Header Analysis
def analyze_headers(target):
    log_info("Analyzing headers...")
    recommendations = []
    headers_info = {}
    try:
        response = requests.head(target, timeout=5)
        headers = response.headers
        headers_info = dict(headers)

        # Check security headers
        if "Strict-Transport-Security" not in headers:
            recommendations.append("Enable HSTS to enforce HTTPS.")
        if "Content-Security-Policy" not in headers:
            recommendations.append("Add a Content Security Policy to prevent XSS attacks.")
        if "X-Frame-Options" not in headers:
            recommendations.append("Set X-Frame-Options to SAMEORIGIN to prevent clickjacking.")

        if not recommendations:
            log_success("All essential security headers are in place!")
    except requests.RequestException:
        log_error("Failed to analyze headers.")

    return {"headers": headers_info, "recommendations": recommendations}

# Automated SQL Injection Detection
def detect_sqli(target):
    log_info("Detecting SQL Injection vulnerabilities...")
    vulnerabilities = []
    payloads = ["' OR 1=1--", "' AND 'a'='a", "' UNION SELECT NULL--"]

    for payload in progress_bar(payloads, "Testing SQL payloads..."):
        try:
            url = f"{target}?id={payload}"
            response = requests.get(url, timeout=5)
            if "SQL syntax" in response.text or "database" in response.text.lower():
                log_warning(f"Possible SQL Injection detected: {url}")
                vulnerabilities.append({"url": url, "payload": payload})
        except requests.RequestException:
            pass
    return vulnerabilities

# Automated XSS Detection
def detect_xss(target):
    log_info("Detecting XSS vulnerabilities...")
    vulnerabilities = []
    payloads = ["<script>alert(1)</script>", "'><img src=x onerror=alert(1)>"]

    for payload in progress_bar(payloads, "Testing XSS payloads..."):
        try:
            response = requests.get(f"{target}?q={payload}", timeout=5)
            if payload in response.text:
                log_warning(f"Possible XSS vulnerability detected: {target}?q={payload}")
                vulnerabilities.append({"url": f"{target}?q={payload}", "payload": payload})
        except requests.RequestException:
            pass
    return vulnerabilities

# Host Header Fuzzing
def test_host_header(target):
    log_info("Testing Host header vulnerabilities...")
    vulnerabilities = []
    payloads = ["evil.com", "malicious.com"]

    for payload in payloads:
        try:
            response = requests.get(target, headers={"Host": payload}, timeout=5)
            if "404" not in response.text and response.status_code != 400:
                log_warning(f"Potential Host header vulnerability: {payload}")
                vulnerabilities.append({"host_header": payload, "response_code": response.status_code})
        except requests.RequestException:
            pass
    return vulnerabilities

# DNS Enumeration
def enumerate_dns(target):
    log_info("Enumerating DNS records...")
    subdomains = []
    try:
        domain = urlparse(target).netloc
        resolver = dns.resolver.Resolver()
        records = resolver.query(domain, "A")
        for record in records:
            subdomains.append(record.to_text())
            log_success(f"DNS Record found: {record.to_text()}")
    except Exception as e:
        log_error(f"DNS enumeration failed: {e}")
    return subdomains

# Automated API Endpoint Detection
def discover_api_endpoints(target):
    log_info("Discovering API endpoints...")
    endpoints = []
    try:
        response = requests.get(target, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        links = [link.get("href") for link in soup.find_all("a", href=True)]
        endpoints = [link for link in links if "/api/" in link]
        for endpoint in endpoints:
            log_success(f"API Endpoint found: {endpoint}")
    except requests.RequestException:
        log_error("Failed to discover API endpoints.")
    return endpoints

# Progress Bar Helper
def progress_bar(tasks, description="Processing..."):
    return track(tasks, description=description)

# Generate Suggestions for Developers
def generate_suggestions(results):
    suggestions = [
        "Add Strict-Transport-Security (HSTS) to enforce HTTPS connections.",
        "Implement Content Security Policy (CSP) to mitigate XSS attacks.",
        "Configure X-Frame-Options to prevent clickjacking attacks.",
        "Validate and sanitize all user inputs to prevent SQL Injection.",
        "Escape output to mitigate XSS vulnerabilities.",
        "Use DNSSEC to secure DNS records.",
        "Restrict access to sensitive API endpoints with authentication.",
        "Avoid exposing hidden files like robots.txt with sensitive paths.",
        "Log and monitor server responses for anomaly detection.",
        "Use rate limiting and CAPTCHA to prevent brute-force attacks."
    ]
    return suggestions

# Report Generation
def generate_report(results, target):
    log_info("Generating detailed report...")
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_name = f"scan_report_{timestamp}.json"
    suggestions = generate_suggestions(results)
    results["Suggestions"] = suggestions

    with open(report_name, "w") as file:
        json.dump(results, file, indent=4)
    log_success(f"Detailed report saved as {report_name}")
    return report_name

# Main Function
def main():
    console.clear()
    log_info("Starting advanced security scan...")
    target = input("Enter the target URL (e.g., https://example.com): ").strip()
    if not target.startswith("http"):
        target = "http://" + target

    wordlist = generate_wordlist(target)
    subdomains = discover_subdomains(target)
    hidden_content = discover_hidden_content(target)
    directories = scan_directories(target, wordlist)
    headers_analysis = analyze_headers(target)
    sqli_vulnerabilities = detect_sqli(target)
    xss_vulnerabilities = detect_xss(target)
    api_endpoints = discover_api_endpoints(target)
    host_header_vulnerabilities = test_host_header(target)
    dns_records = enumerate_dns(target)

    results = {
        "Target": target,
        "Subdomains Found": subdomains,
        "Hidden Content": hidden_content,
        "Directories Found": directories,
        "Headers Analysis": headers_analysis,
        "SQL Injection Vulnerabilities": sqli_vulnerabilities,
        "XSS Vulnerabilities": xss_vulnerabilities,
        "API Endpoints Found": api_endpoints,
        "Host Header Vulnerabilities": host_header_vulnerabilities,
        "DNS Records": dns_records,
    }

    report_file = generate_report(results, target)
    console.print(f"\n[bold green]Scan Completed! Report saved as: {report_file}[/bold green]")

if __name__ == "__main__":
    main()
