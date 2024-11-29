import requests
from bs4 import BeautifulSoup
import whois
import matplotlib.pyplot as plt
import ssl
import socket

def scan_url(url):
    result = {"url": url, "safe": True, "issues": []}

    # 1. SSL Certificate Check
    try:
        hostname = url.split("//")[-1].split("/")[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        result["ssl"] = True
    except:
        result["ssl"] = False
        result["safe"] = False
        result["issues"].append("No SSL certificate found.")

    # 2. Domain Age Check
    try:
        domain_info = whois.whois(hostname)
        result["domain"] = {"creation_date": domain_info.creation_date, "expiration_date": domain_info.expiration_date}
    except:
        result["domain"] = None
        result["issues"].append("Domain WHOIS information not available.")

    # 3. HTML Content Check
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        if soup.find("input", {"type": "password"}):
            result["issues"].append("Website asks for sensitive information.")
            result["safe"] = False
    except:
        result["issues"].append("Could not fetch website content.")

    return result

def visualize_results(results):
    labels = ['Safe', 'Issues Found']
    values = [1 if results["safe"] else 0, len(results["issues"])]
    colors = ['green', 'red']

    plt.pie(values, labels=labels, colors=colors, autopct='%1.1f%%')
    plt.title(f"Website Safety Analysis for {results['url']}")
    plt.show()

if _name_ == "_main_":
    url = input("Enter the URL to scan: ")
    results = scan_url(url)
    print("Analysis Report:")
    print(results)
    visualize_results(results)
