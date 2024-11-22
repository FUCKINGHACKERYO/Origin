import os
import json
import requests
import dns.resolver
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from prettytable import PrettyTable
from scapy.all import *
import whois
import shodan
from tqdm import tqdm
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# API Keys (Set your keys)
SHODAN_API_KEY = "aa6ZZ2ugynaDZHKgvEJLk22TgKeiKiNQ"
VIRUSTOTAL_API_KEY = "77b1d607ff702f271cd96f4d2e7c8f93aa865830d74652f40927f08630cf590b"
SECURITYTRAILS_API_KEY = ""

# Colors for CLI
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# 1. Advanced DNS Enumeration
def enumerate_dns(domain):
    record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'CNAME']
    results = {}
    print(f"{Colors.OKCYAN}Enumerating DNS records for {domain}{Colors.ENDC}")
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            results[record_type] = [str(rdata) for rdata in answers]
        except:
            results[record_type] = "No records found"
    return results

def zone_transfer(domain):
    print(f"{Colors.OKCYAN}Attempting Zone Transfer for {domain}{Colors.ENDC}")
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        for ns in ns_records:
            ns_ip = socket.gethostbyname(str(ns.target))
            query = dns.query.xfr(ns_ip, domain)
            for message in query:
                print(message.to_text())
    except Exception as e:
        print(f"{Colors.WARNING}Zone Transfer Failed: {str(e)}{Colors.ENDC}")

def dnssec_check(domain):
    print(f"{Colors.OKCYAN}Checking DNSSEC for {domain}{Colors.ENDC}")
    try:
        answers = dns.resolver.resolve(domain, 'DNSKEY')
        return [key.to_text() for key in answers]
    except:
        return "DNSSEC not implemented."

# 2. Certificate Transparency Logs
def fetch_from_cert_logs(domain):
    print(f"{Colors.OKCYAN}Fetching subdomains from Certificate Transparency Logs for {domain}{Colors.ENDC}")
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            subdomains = {entry['name_value'] for entry in data}
            return list(subdomains)
    except Exception as e:
        print(f"{Colors.WARNING}Error fetching from Certificate Logs: {str(e)}{Colors.ENDC}")
    return []

# 3. VirusTotal Subdomain Discovery
def fetch_from_virustotal(domain):
    print(f"{Colors.OKCYAN}Fetching subdomains from VirusTotal API for {domain}{Colors.ENDC}")
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return [item['id'] for item in data['data']]
    except Exception as e:
        print(f"{Colors.WARNING}Error fetching from VirusTotal: {str(e)}{Colors.ENDC}")
    return []

# 4. SecurityTrails Subdomain Discovery
def fetch_from_securitytrails(domain):
    print(f"{Colors.OKCYAN}Fetching subdomains from SecurityTrails API for {domain}{Colors.ENDC}")
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"apikey": SECURITYTRAILS_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return data.get('subdomains', [])
    except Exception as e:
        print(f"{Colors.WARNING}Error fetching from SecurityTrails: {str(e)}{Colors.ENDC}")
    return []

# 5. Authentication Scanner
def authentication_scanner(domain):
    print(f"{Colors.OKCYAN}Scanning {domain} for authentication misconfigurations{Colors.ENDC}")
    auth_issues = []
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        if "admin" in response.text.lower() or "login" in response.text.lower():
            auth_issues.append("Login page found on HTTP")
    except:
        pass

    try:
        response = requests.get(f"https://{domain}", timeout=5)
        if "admin" in response.text.lower() or "login" in response.text.lower():
            auth_issues.append("Login page found on HTTPS")
    except:
        pass

    return auth_issues

# 6. Parallelized Subdomain Resolution
def parallel_resolve_subdomains(subdomains):
    print(f"{Colors.OKCYAN}Resolving subdomains in parallel{Colors.ENDC}")
    resolved = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(resolve_subdomain, subdomain) for subdomain in subdomains]
        for future in as_completed(futures):
            result = future.result()
            if result:
                resolved.append(result)
    return resolved

def resolve_subdomain(subdomain):
    try:
        socket.gethostbyname(subdomain)
        return subdomain
    except:
        return None

# 7. AI/ML-based Subdomain Prediction
def train_and_predict_subdomains(domain, wordlist):
    print(f"{Colors.OKCYAN}Training AI/ML model for subdomain prediction{Colors.ENDC}")
    # Real-world training data
    dataset = [
        ("www", 1), ("mail", 1), ("ftp", 1), ("dev", 1), ("staging", 1), 
        ("random", 0), ("notreal", 0), ("xyz", 0), ("abc", 0), ("dummy", 0)
    ]
    words, labels = zip(*dataset)
    vectorizer = CountVectorizer()
    X = vectorizer.fit_transform(words)
    y = labels

    # Train model
    clf = RandomForestClassifier()
    clf.fit(X, y)

    # Test with the provided wordlist
    with open(wordlist, 'r') as file:
        test_words = [line.strip() for line in file]
    test_X = vectorizer.transform(test_words)
    predictions = clf.predict(test_X)
    predicted_subdomains = [f"{word}.{domain}" for word, label in zip(test_words, predictions) if label == 1]
    return predicted_subdomains

# Main Function
def main():
    print(f"{Colors.HEADER}Welcome to the Ultimate Subdomain Recon Tool!{Colors.ENDC}")
    domain = input("Enter the target domain: ")
    wordlist = input("Enter the path to the wordlist: ")

    print(f"{Colors.BOLD}Starting advanced reconnaissance...{Colors.ENDC}")

    # DNS Enumeration
    dns_records = enumerate_dns(domain)
    print(f"\n{Colors.OKGREEN}DNS Records:{Colors.ENDC}")
    print(json.dumps(dns_records, indent=2))

    # Zone Transfer
    zone_transfer(domain)

    # DNSSEC Check
    dnssec_keys = dnssec_check(domain)
    print(f"\n{Colors.OKGREEN}DNSSEC Keys:{Colors.ENDC}")
    print(json.dumps(dnssec_keys, indent=2))

    # Subdomain Discovery
    subdomains = []
    subdomains += fetch_from_cert_logs(domain)
    subdomains += fetch_from_virustotal(domain)
    subdomains += fetch_from_securitytrails(domain)

    # Resolve Subdomains in Parallel
    subdomains = parallel_resolve_subdomains(list(set(subdomains)))
    print(f"\n{Colors.OKGREEN}Resolved Subdomains:{Colors.ENDC}")
    for subdomain in subdomains:
        print(subdomain)

    # Authentication Scanner
    auth_issues = authentication_scanner(domain)
    print(f"\n{Colors.WARNING}Authentication Issues:{Colors.ENDC}")
    for issue in auth_issues:
        print(issue)

    # AI/ML-based Prediction
    predicted_subdomains = train_and_predict_subdomains(domain, wordlist)
    print(f"\n{Colors.OKGREEN}AI/ML Predicted Subdomains:{Colors.ENDC}")
    for subdomain in predicted_subdomains:
        print(subdomain)

    print(f"\n{Colors.OKGREEN}Advanced Reconnaissance Complete!{Colors.ENDC}")

if __name__ == "__main__":
    main()
