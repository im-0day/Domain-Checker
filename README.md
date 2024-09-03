# Domain Checker Tool

## Overview

This tool helps in finding related domains for a given domain by checking WHOIS information, SSL certificates, DNS records, and website content. It is a powerful tool to identify domains that may belong to the same organization or individual.

### Key Features:

- **WHOIS Information Matching**: Checks if WHOIS information like `registrant_name`, `registrant_organization`, and `emails` match with the main domain.
- **SSL Certificate Matching**: Compares SSL certificates to identify related domains.
- **DNS Record Matching**: Compares DNS records (like IP addresses) to find domains that point to the same server.
- **Website Content Matching**: Checks if the main domain's name appears in the website content of potential related domains.
- **Clear and Organized Logging**: Outputs results in a clear and organized manner, with distinct formats for domain checking and related domains.

## Installation

### Prerequisites

Make sure you have Python 3.x installed on your machine. You will also need to install the required Python packages.

### Installation Steps

1. **Clone the repository**:
  
  ```bash
  git clone https://github.com/YourUsername/Domain-checker.git
  cd domain-checker
  ```
  
2. **Install the required packages**:
   You can install the required Python packages using `pip`:
  
  ```bash
  pip install -r requirements.txt
  ```
  

## Usage

1. **Run the script**:
  
  You can run the script using Python:
  
  ```bash
  python3 domain_checker.py
  ```
  
  By default, the script will check a predefined list of TLDs for related domains to the main domain (`example.com` in this example).
  
2. **Customize the main domain**:
   You can modify the `main_domain` variable in the script to check related domains for a different main domain:
  
  ```python
  main_domain = "yourdomain.com"
  ```
  

## Output

The script will clear the console at the start and display a banner. It will then log the process of checking each domain and will display related domains with a distinct format.

### Example Output

```
+-----------------------------+
|    Coded By Artin           |
+-----------------------------+

+-------------------------------+
|  Checking domain: example.com  |
+-------------------------------+

*  Related Domain: example.org  *
**************************************************

*  Related Domain: example.net  *
**************************************************

+--------------------------------------------------+
|  This script may have some inaccuracies.         |
+--------------------------------------------------+
```

## Disclaimer

**Warning**: This script may have some inaccuracies due to the limitations of WHOIS data, SSL certificate differences, and DNS configurations. It is recommended to manually verify the results.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
