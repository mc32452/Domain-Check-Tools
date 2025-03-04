# Domain Checker

**Domain Checker** is a comprehensive, web-based domain analysis tool built with Python and Streamlit. It provides a suite of checks—from HTTP status verification and DNS record lookups to WHOIS data retrieval (with RDAP fallback), TLS/SSL certificate validation, subdomain discovery via crt.sh, and an advanced all-in-one analysis. The tool’s asynchronous design ensures fast and concurrent processing, while its intuitive interface makes it ideal for both developers and casual users.

---

## Table of Contents

- [Features](#features)
- [Usage](#usage)
  - [HTTP Check](#http-check)
  - [DNS Lookup](#dns-lookup)
  - [WHOIS Lookup](#whois-lookup)
  - [TLS/SSL Certificate Check](#tlsssl-certificate-check)
  - [Subdomain Finder](#subdomain-finder)
  - [Advanced Check](#advanced-check)
- [Visualizations](#visualizations)
- [Technical Details](#technical-details)
- [Known Issues and Limitations](#known-issues-and-limitations)
- [Requirements](#requirements)

---

## Features

- **HTTP Check**: Quickly assess website availability by retrieving HTTP status codes, response times, content snippets, and redirection details.
- **DNS Lookup**: Perform DNS record lookups for multiple types (A, AAAA, CNAME, MX, NS, SOA, TXT) with an option for recursive resolution.
- **WHOIS Lookup**: Retrieve detailed domain registration data using RDAP—with a fallback to traditional WHOIS if needed.
- **TLS/SSL Certificate Check**: Validate TLS/SSL certificates, checking expiry dates and calculating days until expiration.
- **Subdomain Finder**: Discover subdomains through crt.sh and evaluate their online status via HTTP checks.
- **Advanced Check**: Combine HTTP, DNS, WHOIS, TLS/SSL, wildcard DNS, and IP geolocation checks into a single, comprehensive report.
- **Interactive Visualizations**: Utilize Plotly to display subdomain status distributions and response time metrics.
- **Asynchronous Processing**: Leverages asyncio and aiohttp to run concurrent network checks for enhanced performance.
- **User-Friendly Interface**: Built with Streamlit for an intuitive multi-tabbed experience.

---

## Usage

The Domain Checker application is divided into several tabs, each designed for a specific type of domain analysis.

### HTTP Check

- **Purpose**: Assess website availability and performance.
- **Input**:
  - One or more domain names (each on a new line).
  - Configurable timeout, concurrency, and retry parameters.
- **Output**:
  - A table listing each domain’s HTTP status, response snippet, response time, number of attempts, and redirection history.
  - Option to download results as a CSV file.

### DNS Lookup

- **Purpose**: Retrieve DNS records for specified domains.
- **Input**:
  - One or more domain names.
  - Selection of record types (A, AAAA, CNAME, MX, NS, SOA, TXT).
  - Optional recursive DNS resolution.
- **Output**:
  - A table displaying DNS records for each domain.
  - If enabled, a recursive DNS resolution chain is provided.
  - CSV download option.

### WHOIS Lookup

- **Purpose**: Fetch domain registration and ownership details.
- **Input**:
  - One or more domain names.
- **Output**:
  - A table with registrant details, registrar information, creation/expiration dates, and name server data.
  - Downloadable CSV report.

### TLS/SSL Certificate Check

- **Purpose**: Verify TLS/SSL certificate validity.
- **Input**:
  - One or more domain names.
- **Output**:
  - Certificate expiry dates, days until expiration, and any error messages encountered.
  - Option to export the results as CSV.

### Subdomain Finder

- **Purpose**: Discover subdomains using crt.sh and perform HTTP checks on them.
- **Input**:
  - A naked domain (without “www” or any pre-existing subdomain).
- **Output**:
  - Lists of unique subdomains categorized as online, flagged/unreachable, and offline.
  - Interactive graphs (pie chart for subdomain status and bar chart for response times).
  - CSV download options for each subdomain category.

### Advanced Check

- **Purpose**: Perform a multi-faceted analysis combining HTTP, DNS, WHOIS, TLS/SSL, wildcard DNS, and IP geolocation checks.
- **Input**:
  - One or more domain names.
  - Optional selection to enable WHOIS, TLS/SSL, wildcard DNS, and IP geolocation.
  - DNS record type selection.
- **Output**:
  - A comprehensive table combining all selected checks.
  - Downloadable CSV report.
  - If IP geolocation is enabled, a map visualization is also provided.

---

## Visualizations

- **Pie Chart**: Displays the distribution of subdomains by status (Online, Flagged/Unreachable, Offline).
- **Bar Chart**: Shows response times for online subdomains, highlighting performance differences.

These visualizations help users quickly assess the health and performance of the domain’s subdomains.

---

## Technical Details

- **Asynchronous Design**: Uses Python’s asyncio and aiohttp libraries to perform non-blocking, concurrent HTTP and DNS operations.
- **DNS Resolution**: Utilizes `dns.asyncresolver` with custom nameservers (e.g., Google’s 8.8.8.8 and Cloudflare’s 1.1.1.1) to ensure robust lookups.
- **WHOIS and RDAP Integration**: Attempts RDAP queries first and falls back to traditional WHOIS methods if necessary.
- **TLS/SSL Validation**: Implements certificate checks using the ssl and socket modules.
- **Subdomain Discovery**: Integrates with crt.sh to extract subdomains and further evaluates them via HTTP checks.
- **Streamlit Interface**: Employs a multi-tab layout with interactive forms, progress bars, and download buttons to enhance user experience.
- **Error Handling & Retry Logic**: Robust exception management and retry mechanisms are built-in for improved reliability.

---

## Known Issues and Limitations

- **Third-Party Service Dependency**: Reliance on external services (crt.sh, RDAP/WHOIS, free IP geolocation API) may result in rate limiting or temporary unavailability.
- **DNS Caching**: DNS lookup results might be affected by caching; clearing the cache may be necessary for up-to-date results.
- **Certificate Verification**: Domains without proper HTTPS support or with misconfigured certificates might not return valid certificate information.
- **Performance Variability**: Network-intensive operations can lead to variable response times depending on the domain load and external service performance.

---

## Requirements

- **Python 3.8+**
- **Streamlit**
- **aiohttp**
- **dnspython** (for `dns.asyncresolver`)
- **pandas**
- **plotly**
- **whois**
- **crtsh**
- Additional dependencies as imported in the source code

---
