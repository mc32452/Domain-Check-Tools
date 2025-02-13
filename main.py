import io
import time
import random
import socket
import ssl
import whois
import dns.resolver
import pandas as pd
import requests
import streamlit as st

# ---------------------------
# Helper Functions for WHOIS & DNS
# ---------------------------
def get_whois_info(domain):
    """Fetch WHOIS information for a domain."""
    try:
        return whois.whois(domain)
    except Exception as e:
        return {"error": str(e)}

def get_dns_info(domain, record_types):
    """Fetch selected DNS records for a domain."""
    dns_data = {}
    for record in record_types:
        try:
            answers = dns.resolver.resolve(domain, record, lifetime=5)
            dns_data[record] = [r.to_text() for r in answers]
        except Exception as e:
            dns_data[record] = [f"Error: {e}"]
    return dns_data

def process_whois_dns(domain, record_types):
    """Process a single domain for WHOIS and DNS data."""
    whois_data = get_whois_info(domain)
    dns_data = get_dns_info(domain, record_types)
    return {"domain": domain, "whois": whois_data, "dns": dns_data}

def generate_csv(results, tool="whois_dns"):
    """Flatten results and generate CSV content for downloadable data."""
    rows = []
    if tool == "whois_dns":
        for res in results:
            domain = res["domain"]
            whois_info = res["whois"]
            dns_info = res["dns"]
            # Extract some common WHOIS fields.
            creation_date = whois_info.get("creation_date", "N/A")
            expiration_date = whois_info.get("expiration_date", "N/A")
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            dns_str = {key: "; ".join(value) for key, value in dns_info.items()}
            row = {
                "domain": domain,
                "creation_date": creation_date,
                "expiration_date": expiration_date,
            }
            for key in dns_str:
                row[f"{key}_records"] = dns_str.get(key, "")
            rows.append(row)
    else:
        # For other tools, assume each result is a flat dict.
        for res in results:
            rows.append(res)
    df = pd.DataFrame(rows)
    csv_buffer = io.StringIO()
    df.to_csv(csv_buffer, index=False)
    return csv_buffer.getvalue()

# ---------------------------
# Terminal-Style Command Animation
# ---------------------------
def matrix_loading_message(domain, tool):
    """Return a terminal-style command flash for cool loading effects."""
    commands = {
        "whois_dns": [
            f"whois {domain}",
            f"dig {domain} ANY",
            f"nslookup {domain}",
            f"fetch --whois {domain}",
            f"resolvconf {domain}"
        ],
        "http_status": [
            f"curl -I http://{domain}",
            f"wget --spider http://{domain}",
            f"ping {domain}",
            f"curl -L https://{domain}"
        ],
        "ssl_cert": [
            f"openssl s_client -connect {domain}:443",
            f"sslscan {domain}",
            f"certinfo {domain}",
            f"openssl x509 -in <cert> -noout -dates"
        ],
        "traceroute": [
            f"traceroute {domain}",
            f"mtr {domain}",
            f"tracepath {domain}",
            f"ping -R {domain}"
        ],
        "reverse_ip": [
            f"host {domain}",
            f"dig -x {domain}",
            f"nslookup {domain}",
            f"reverse-dns {domain}"
        ],
        "port_scan": [
            f"nmap -p 21,22,25,53,80,110,443 {domain}",
            f"masscan {domain} -p21,22,25,53,80,110,443",
            f"scan {domain} for common ports"
        ],
        "ip_geolocation": [
            f"geoiplookup {domain}",
            f"ipinfo {domain}",
            f"curl ipinfo.io/{domain}"
        ]
    }
    cmd = random.choice(commands.get(tool, [f"Processing {domain}"]))
    return f"<div style='font-family: monospace; background-color: #000; color: #0F0; padding: 5px; border-radius: 5px;'>{cmd}</div>"

# ---------------------------
# Existing Domain Tools
# ---------------------------
def process_http_status(domain):
    """Check HTTP status for a domain."""
    url = f"http://{domain}"
    try:
        start = time.time()
        response = requests.get(url, timeout=5)
        elapsed = time.time() - start
        return {"domain": domain, "url": url, "status_code": response.status_code, "response_time_sec": round(elapsed, 2)}
    except Exception:
        url = f"https://{domain}"
        try:
            start = time.time()
            response = requests.get(url, timeout=5)
            elapsed = time.time() - start
            return {"domain": domain, "url": url, "status_code": response.status_code, "response_time_sec": round(elapsed, 2)}
        except Exception as e:
            return {"domain": domain, "url": url, "error": str(e)}

def process_ssl_cert(domain):
    """Retrieve SSL certificate details for a domain."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert.get('subject', ()))
                issuer = dict(x[0] for x in cert.get('issuer', ()))
                valid_from = cert.get('notBefore', 'N/A')
                valid_to = cert.get('notAfter', 'N/A')
                return {"domain": domain, "subject": subject, "issuer": issuer, "valid_from": valid_from, "valid_to": valid_to}
    except Exception as e:
        return {"domain": domain, "error": str(e)}

def process_traceroute(domain):
    """Simulate a traceroute by generating random hops."""
    hops = []
    num_hops = random.randint(4, 8)
    for i in range(1, num_hops + 1):
        fake_ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
        delay = round(random.uniform(10, 100) / 1000, 3)  # in seconds
        hops.append(f"Hop {i}: {fake_ip}  {delay*1000} ms")
    return {"domain": domain, "traceroute": hops}

def process_reverse_ip(domain):
    """Perform a reverse IP lookup."""
    try:
        ip = socket.gethostbyname(domain)
        rev = socket.gethostbyaddr(ip)
        return {"domain": domain, "ip": ip, "reverse_dns": rev[0], "aliases": rev[1]}
    except Exception as e:
        return {"domain": domain, "error": str(e)}

# ---------------------------
# New Tools
# ---------------------------
def process_port_scan(domain, ports):
    """Scan a list of common ports for a domain."""
    results = {}
    try:
        ip = socket.gethostbyname(domain)
    except Exception as e:
        return {"domain": domain, "error": f"DNS resolution failed: {e}"}
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            s.connect((ip, port))
            results[port] = "open"
        except Exception:
            results[port] = "closed"
        finally:
            s.close()
    return {"domain": domain, "ip": ip, "ports": results}

def process_ip_geolocation(domain):
    """Retrieve geolocation data for a domain's IP using ipinfo.io."""
    try:
        ip = socket.gethostbyname(domain)
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        data = response.json()
        data["domain"] = domain
        data["ip"] = ip
        return data
    except Exception as e:
        return {"domain": domain, "error": str(e)}

# ---------------------------
# Run Tool Functions (with Terminal View and CSV download)
# ---------------------------
SIMULATED_DELAY = 0.5
DEFAULT_RECORDS = ["A", "MX", "NS", "TXT"]

def run_whois_dns_tool(domains, selected_records, simulated_delay):
    results = []
    progress_bar = st.progress(0)
    log_area = st.empty()
    for i, domain in enumerate(domains):
        log_area.markdown(matrix_loading_message(domain, "whois_dns"), unsafe_allow_html=True)
        with st.spinner(f"Processing WHOIS & DNS for {domain}..."):
            res = process_whois_dns(domain, selected_records)
            results.append(res)
            time.sleep(simulated_delay)
        progress_bar.progress((i+1)/len(domains))
    st.success("WHOIS & DNS processing complete!")
    csv_data = generate_csv(results, tool="whois_dns")
    st.download_button("Download CSV", data=csv_data, file_name="whois_dns_records.csv", mime="text/csv")
    st.dataframe(pd.read_csv(io.StringIO(csv_data)))
    return results

def run_http_status_tool(domains, simulated_delay):
    results = []
    progress_bar = st.progress(0)
    log_area = st.empty()
    for i, domain in enumerate(domains):
        log_area.markdown(matrix_loading_message(domain, "http_status"), unsafe_allow_html=True)
        with st.spinner(f"Checking HTTP status for {domain}..."):
            res = process_http_status(domain)
            results.append(res)
            time.sleep(simulated_delay)
        progress_bar.progress((i+1)/len(domains))
    st.success("HTTP status check complete!")
    csv_data = generate_csv(results, tool="http_status")
    st.download_button("Download CSV", data=csv_data, file_name="http_status.csv", mime="text/csv")
    st.dataframe(pd.read_csv(io.StringIO(csv_data)))
    return results

def run_ssl_cert_tool(domains, simulated_delay):
    results = []
    progress_bar = st.progress(0)
    log_area = st.empty()
    for i, domain in enumerate(domains):
        log_area.markdown(matrix_loading_message(domain, "ssl_cert"), unsafe_allow_html=True)
        with st.spinner(f"Fetching SSL certificate for {domain}..."):
            res = process_ssl_cert(domain)
            results.append(res)
            time.sleep(simulated_delay)
        progress_bar.progress((i+1)/len(domains))
    st.success("SSL Certificate check complete!")
    csv_data = generate_csv(results, tool="ssl_cert")
    st.download_button("Download CSV", data=csv_data, file_name="ssl_cert.csv", mime="text/csv")
    st.dataframe(pd.read_csv(io.StringIO(csv_data)))
    return results

def run_traceroute_tool(domains, simulated_delay):
    results = []
    progress_bar = st.progress(0)
    log_area = st.empty()
    for i, domain in enumerate(domains):
        log_area.markdown(matrix_loading_message(domain, "traceroute"), unsafe_allow_html=True)
        with st.spinner(f"Running traceroute for {domain}..."):
            res = process_traceroute(domain)
            results.append(res)
            time.sleep(simulated_delay)
        progress_bar.progress((i+1)/len(domains))
    st.success("Traceroute simulation complete!")
    for res in results:
        st.markdown(f"### {res['domain']}")
        for hop in res['traceroute']:
            st.text(hop)
    return results

def run_reverse_ip_tool(domains, simulated_delay):
    results = []
    progress_bar = st.progress(0)
    log_area = st.empty()
    for i, domain in enumerate(domains):
        log_area.markdown(matrix_loading_message(domain, "reverse_ip"), unsafe_allow_html=True)
        with st.spinner(f"Performing reverse IP lookup for {domain}..."):
            res = process_reverse_ip(domain)
            results.append(res)
            time.sleep(simulated_delay)
        progress_bar.progress((i+1)/len(domains))
    st.success("Reverse IP lookup complete!")
    csv_data = generate_csv(results, tool="reverse_ip")
    st.download_button("Download CSV", data=csv_data, file_name="reverse_ip.csv", mime="text/csv")
    st.dataframe(pd.read_csv(io.StringIO(csv_data)))
    return results

def run_port_scan_tool(domains, simulated_delay):
    results = []
    progress_bar = st.progress(0)
    common_ports = [21, 22, 25, 53, 80, 110, 443, 3306, 8080]
    log_area = st.empty()
    for i, domain in enumerate(domains):
        log_area.markdown(matrix_loading_message(domain, "port_scan"), unsafe_allow_html=True)
        with st.spinner(f"Scanning ports for {domain}..."):
            res = process_port_scan(domain, common_ports)
            results.append(res)
            time.sleep(simulated_delay)
        progress_bar.progress((i+1)/len(domains))
    st.success("Port scanning complete!")
    csv_data = generate_csv(results, tool="port_scan")
    st.download_button("Download CSV", data=csv_data, file_name="port_scan.csv", mime="text/csv")
    st.dataframe(pd.read_csv(io.StringIO(csv_data)))
    return results

def run_ip_geolocation_tool(domains, simulated_delay):
    results = []
    progress_bar = st.progress(0)
    log_area = st.empty()
    for i, domain in enumerate(domains):
        log_area.markdown(matrix_loading_message(domain, "ip_geolocation"), unsafe_allow_html=True)
        with st.spinner(f"Fetching IP geolocation for {domain}..."):
            res = process_ip_geolocation(domain)
            results.append(res)
            time.sleep(simulated_delay)
        progress_bar.progress((i+1)/len(domains))
    st.success("IP Geolocation complete!")
    csv_data = generate_csv(results, tool="ip_geolocation")
    st.download_button("Download CSV", data=csv_data, file_name="ip_geolocation.csv", mime="text/csv")
    st.dataframe(pd.read_csv(io.StringIO(csv_data)))
    return results

# ---------------------------
# Main App with Tabs (Without Sidebar or Subdomain Finder)
# ---------------------------
def main():
    st.set_page_config(page_title="Ultimate Domain Toolkit", layout="wide")

    tabs = st.tabs([
        "WHOIS & DNS Checker", 
        "HTTP Status Checker", 
        "SSL Certificate Checker", 
        "Traceroute Simulator", 
        "Reverse IP Lookup", 
        "Port Scanner", 
        "IP Geolocation"
    ])

    # WHOIS & DNS Checker
    with tabs[0]:
        st.header("WHOIS & DNS Checker")
        domain_input = st.text_input("Enter domains (comma separated):", "example.com, google.com")
        domains = [d.strip() for d in domain_input.split(",") if d.strip()]
        if st.button("Run WHOIS & DNS Checker", key="run_whois_dns"):
            if not domains:
                st.error("Please enter at least one domain.")
            else:
                run_whois_dns_tool(domains, DEFAULT_RECORDS, SIMULATED_DELAY)

    # HTTP Status Checker
    with tabs[1]:
        st.header("HTTP Status Checker")
        domain_input = st.text_input("Enter domains (comma separated):", "example.com, google.com", key="http_status_input")
        domains = [d.strip() for d in domain_input.split(",") if d.strip()]
        if st.button("Run HTTP Status Checker", key="run_http_status"):
            if not domains:
                st.error("Please enter at least one domain.")
            else:
                run_http_status_tool(domains, SIMULATED_DELAY)

    # SSL Certificate Checker
    with tabs[2]:
        st.header("SSL Certificate Checker")
        domain_input = st.text_input("Enter domains (comma separated):", "example.com, google.com", key="ssl_cert_input")
        domains = [d.strip() for d in domain_input.split(",") if d.strip()]
        if st.button("Run SSL Certificate Checker", key="run_ssl_cert"):
            if not domains:
                st.error("Please enter at least one domain.")
            else:
                run_ssl_cert_tool(domains, SIMULATED_DELAY)

    # Traceroute Simulator
    with tabs[3]:
        st.header("Traceroute Simulator")
        domain_input = st.text_input("Enter domains (comma separated):", "example.com, google.com", key="traceroute_input")
        domains = [d.strip() for d in domain_input.split(",") if d.strip()]
        if st.button("Run Traceroute Simulator", key="run_traceroute"):
            if not domains:
                st.error("Please enter at least one domain.")
            else:
                run_traceroute_tool(domains, SIMULATED_DELAY)

    # Reverse IP Lookup
    with tabs[4]:
        st.header("Reverse IP Lookup")
        domain_input = st.text_input("Enter domains (comma separated):", "example.com, google.com", key="reverse_ip_input")
        domains = [d.strip() for d in domain_input.split(",") if d.strip()]
        if st.button("Run Reverse IP Lookup", key="run_reverse_ip"):
            if not domains:
                st.error("Please enter at least one domain.")
            else:
                run_reverse_ip_tool(domains, SIMULATED_DELAY)

    # Port Scanner
    with tabs[5]:
        st.header("Port Scanner")
        domain_input = st.text_input("Enter domains (comma separated):", "example.com, google.com", key="port_scan_input")
        domains = [d.strip() for d in domain_input.split(",") if d.strip()]
        if st.button("Run Port Scanner", key="run_port_scan"):
            if not domains:
                st.error("Please enter at least one domain.")
            else:
                run_port_scan_tool(domains, SIMULATED_DELAY)

    # IP Geolocation
    with tabs[6]:
        st.header("IP Geolocation")
        domain_input = st.text_input("Enter domains (comma separated):", "example.com, google.com", key="ip_geo_input")
        domains = [d.strip() for d in domain_input.split(",") if d.strip()]
        if st.button("Run IP Geolocation", key="run_ip_geo"):
            if not domains:
                st.error("Please enter at least one domain.")
            else:
                run_ip_geolocation_tool(domains, SIMULATED_DELAY)

    # Footer
    st.markdown(
        """
        <style>
        .footer {
            text-align: center;
            font-family: 'Courier New', monospace;
            margin-top: 50px;
            opacity: 0.7;
        }
        </style>
        <div class="footer">
            Made by Misha Castle
        </div>
        """, unsafe_allow_html=True
    )

if __name__ == "__main__":
    main()
