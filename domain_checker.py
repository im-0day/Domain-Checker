import requests
import whois
import ssl
import socket
import logging
import os
import ctypes
from OpenSSL import crypto
from bs4 import BeautifulSoup

def clear_console():
    if os.name == 'nt':
        os.system('cls')
        ctypes.windll.kernel32.SetConsoleTitleW("Domain Checker - Coded by Artin")
    else:
        os.system('clear')

clear_console()

logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)

def get_all_tlds():
    response = requests.get("https://data.iana.org/TLD/tlds-alpha-by-domain.txt")
    tlds = response.text.splitlines()[1:]
    return tlds

def log_with_frame(message, level="INFO"):
    frame_length = len(message) + 4
    frame = "+" + "-" * frame_length + "+"
    
    if level == "INFO":
        logging.info(f"{frame}\n|  {message}  |\n{frame}")
    elif level == "ERROR":
        logging.error(f"{frame}\n|  {message}  |\n{frame}")
    elif level == "WARNING":
        logging.warning(f"{frame}\n|  {message}  |\n{frame}")

def log_related_domain(message):
    frame = "*" * 50
    logging.info(f"{frame}\n*  Related Domain: {message}  *\n{frame}")

def get_ssl_certificate(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.connect((domain, 443))
            cert = s.getpeercert(binary_form=True)
            x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
            return x509
    except Exception as e:
        log_with_frame(f"Error fetching SSL certificate for {domain}: {e}", "ERROR")
        return None

def check_ssl_match(main_cert, target_domain):
    target_cert = get_ssl_certificate(target_domain)
    if target_cert is None:
        return False
    return main_cert.digest('sha1') == target_cert.digest('sha1')

def check_domain_in_content(main_domain, target_domain):
    try:
        response = requests.get(f"http://{target_domain}", timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            return main_domain in soup.text
    except Exception as e:
        log_with_frame(f"Error fetching content from {target_domain}: {e}", "ERROR")
        return False
    return False

def check_dns_match(main_domain, target_domain):
    try:
        main_ip = socket.gethostbyname(main_domain)
        target_ip = socket.gethostbyname(target_domain)
        return main_ip == target_ip
    except Exception as e:
        log_with_frame(f"Error fetching DNS records for {target_domain}: {e}", "ERROR")
        return False

def find_related_domains(main_domain):
    extracted_domain = main_domain.split('.')[0]
    tlds = get_all_tlds()  
    related_domains = []

    main_cert = get_ssl_certificate(main_domain)

    try:
        main_whois = whois.whois(main_domain)
    except Exception as e:
        log_with_frame(f"WHOIS lookup failed for {main_domain}: {e}", "ERROR")
        main_whois = None

    for tld in tlds:
        possible_domain = f"{extracted_domain}.{tld.lower()}"
        log_with_frame(f"Checking domain: {possible_domain}", "INFO")
        try:
            w = whois.whois(possible_domain)
            if w.domain_name:
                if main_whois and (w.registrant_name == main_whois.registrant_name or
                                   w.registrant_organization == main_whois.registrant_organization or
                                   w.emails == main_whois.emails):
                    related_domains.append(possible_domain)
                    continue

                if main_cert and check_ssl_match(main_cert, possible_domain):
                    related_domains.append(possible_domain)
                    continue

                if check_dns_match(main_domain, possible_domain):
                    related_domains.append(possible_domain)
                    continue

                if check_domain_in_content(main_domain, possible_domain):
                    related_domains.append(possible_domain)
                    continue

                log_with_frame(f"No match found for {possible_domain}", "WARNING")
        except Exception as e:
            log_with_frame(f"WHOIS lookup failed for {possible_domain}: {e}", "ERROR")
            continue

    return related_domains

banner = """
+-----------------------------+
|    Coded By Artin           |
+-----------------------------+
"""
log_with_frame(banner, "INFO")

main_domain = "example.com"
domains = find_related_domains(main_domain)

log_with_frame("Related domains found:", "INFO")
for domain in domains:
    log_related_domain(domain)

log_with_frame("This script may have some inaccuracies.", "ERROR")
