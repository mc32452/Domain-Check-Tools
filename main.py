import asyncio
import aiohttp
import dns.asyncresolver
import csv
import io
import time
import streamlit as st
import pandas as pd
import whois
from urllib.parse import urlparse
import ssl
import socket
import datetime

http_headers = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/90.0.4430.93 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5"
}

WHOIS_CACHE = {}

def get_whois_info(domain):
    global WHOIS_CACHE
    if domain in WHOIS_CACHE:
        return WHOIS_CACHE[domain]
    time.sleep(0.2)
    max_attempts = 3
    backoff_factor = 0.5
    for attempt in range(max_attempts):
        try:
            if attempt > 0:
                delay = backoff_factor * (2 ** (attempt - 1))
                time.sleep(delay)
            w = whois.whois(domain)
            registrar = w.registrar if hasattr(w, 'registrar') else ""
            creation_date = w.creation_date
            expiration_date = w.expiration_date
            name_servers = w.name_servers if hasattr(w, 'name_servers') else ""
            if isinstance(name_servers, list):
                name_servers = ", ".join(name_servers)
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            result = {
                "registrar": registrar,
                "creation_date": creation_date,
                "expiration_date": expiration_date,
                "name_servers": name_servers,
                "error": ""
            }
            WHOIS_CACHE[domain] = result
            return result
        except Exception as e:
            error_str = str(e)
            if "reset" in error_str.lower():
                error_str = "Connection reset error. Please try again later."
            if attempt == max_attempts - 1:
                result = {
                    "registrar": "",
                    "creation_date": "",
                    "expiration_date": "",
                    "name_servers": "",
                    "error": error_str
                }
                WHOIS_CACHE[domain] = result
                return result

async def process_whois_domain(domain):
    info = await asyncio.to_thread(get_whois_info, domain)
    return (
        domain,
        info.get("registrar", ""),
        info.get("creation_date", ""),
        info.get("expiration_date", ""),
        info.get("name_servers", ""),
        info.get("error", "")
    )

async def run_whois_checks(domains):
    tasks = [process_whois_domain(domain) for domain in domains]
    results = []
    total = len(tasks)
    progress_bar = st.progress(0)
    for i, coro in enumerate(asyncio.as_completed(tasks), start=1):
        result = await coro
        results.append(result)
        progress_bar.progress(int((i / total) * 100))
    return results

async def check_http_domain(domain, timeout, retries, session, headers, semaphore):
    url = "http://" + domain if not domain.startswith(("http://", "https://")) else domain
    attempt = 0
    error_message = ""
    response_time = None
    redirect_info = ""
    redirected = "No"
    start_time = time.perf_counter()
    def normalize_url(url):
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]
        path = parsed.path.rstrip("/")
        if not path:
            path = "/"
        return netloc, path, parsed.query
    while attempt < retries:
        attempt += 1
        try:
            async with semaphore:
                async with session.get(url, headers=headers, timeout=timeout) as response:
                    response_time = time.perf_counter() - start_time
                    status = response.status
                    text = await response.text()
                    snippet = text[:200]
                    if response.history:
                        redirects = [str(resp.url) for resp in response.history]
                        redirects.append(str(response.url))
                        redirect_info = " -> ".join(redirects)
                    else:
                        redirect_info = "No redirect"
                    original_norm = normalize_url(url)
                    final_norm = normalize_url(str(response.url))
                    if original_norm == final_norm:
                        redirected = "No"
                    else:
                        redirected = "Yes"
                    return (
                        domain, status, snippet, response_time, 
                        attempt, "Yes", redirect_info, redirected
                    )
        except Exception as e:
            error_message = str(e)
            await asyncio.sleep(0.5)
    response_time = time.perf_counter() - start_time
    snippet = f"Error occurred: {error_message}"
    return (domain, None, snippet, response_time, attempt, "No", "No redirect", "No")

async def run_http_checks(domains, timeout, concurrency, retries):
    results = []
    semaphore = asyncio.Semaphore(concurrency)
    async with aiohttp.ClientSession() as session:
        tasks = [check_http_domain(domain, timeout, retries, session, http_headers, semaphore) for domain in domains]
        progress_bar = st.progress(0)
        total = len(tasks)
        completed = 0
        for future in asyncio.as_completed(tasks):
            result = await future
            results.append(result)
            completed += 1
            progress_bar.progress(int((completed / total) * 100))
    return results

async def get_dns_record_for_domain(domain, record_types):
    if not domain or '.' not in domain:
        return domain, {rtype: "Invalid domain format" for rtype in record_types}
    records = {}
    for rtype in record_types:
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            resolver.nameservers = ['8.8.8.8', '1.1.1.1']
            answers = await resolver.resolve(domain, rtype)
            if rtype == "MX":
                record_list = [f"Priority {rdata.preference}: {rdata.exchange}" for rdata in answers]
            else:
                record_list = [rdata.to_text() for rdata in answers]
            records[rtype] = record_list if record_list else "No records found"
        except dns.resolver.NoAnswer:
            records[rtype] = "No records found"
        except dns.resolver.NXDOMAIN:
            records[rtype] = "Domain does not exist"
        except dns.resolver.Timeout:
            records[rtype] = "Lookup timed out"
        except Exception as e:
            records[rtype] = f"Error: {str(e)}"
    return domain, records

async def run_dns_checks(domains, record_types, progress_callback=None):
    results = {}
    tasks = [get_dns_record_for_domain(domain, record_types) for domain in domains]
    total = len(tasks)
    completed = 0
    for task in asyncio.as_completed(tasks):
        domain, result = await task
        results[domain] = result
        completed += 1
        if progress_callback:
            progress_callback(completed, total)
    return results

def get_certificate_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry_date_str = cert.get('notAfter')
                if not expiry_date_str:
                    return None, None, "Certificate does not have an expiration date"
                expiry_date = datetime.datetime.strptime(expiry_date_str, "%b %d %H:%M:%S %Y %Z")
                now = datetime.datetime.utcnow()
                days_until_expiry = (expiry_date - now).days
                return expiry_date_str, days_until_expiry, ""
    except Exception as e:
        return None, None, str(e)

async def process_certificate_check(domain):
    return await asyncio.to_thread(get_certificate_info, domain)

async def process_cert_domain(domain):
    cert_expiry_date, days_until_expiry, cert_error = await process_certificate_check(domain)
    return (domain, cert_expiry_date if cert_expiry_date else "", 
            days_until_expiry if days_until_expiry is not None else "", cert_error)

async def run_certificate_checks(domains):
    tasks = [process_cert_domain(domain) for domain in domains]
    results = []
    total = len(tasks)
    progress_bar = st.progress(0)
    for i, task in enumerate(asyncio.as_completed(tasks), start=1):
        result = await task
        results.append(result)
        progress_bar.progress(int((i / total) * 100))
    return results

async def process_all_in_one(domain, timeout, retries, dns_record_types, whois_enabled, cert_enabled, session, semaphore):
    result = {"Domain": domain}
    if whois_enabled:
        whois_info = await asyncio.to_thread(get_whois_info, domain)
        result["Registrar"] = whois_info.get("registrar", "")
        result["WHOIS Creation Date"] = whois_info.get("creation_date", "")
        result["WHOIS Expiration Date"] = whois_info.get("expiration_date", "")
        result["Name Servers"] = whois_info.get("name_servers", "")
        result["WHOIS Error"] = whois_info.get("error", "")
    http_result = await check_http_domain(domain, timeout, retries, session, http_headers, semaphore)
    (_, http_status, http_snippet, http_response_time, http_attempts,
     http_response_received, http_redirect_history, http_redirected) = http_result
    result["HTTP Status"] = http_status
    result["HTTP Snippet"] = http_snippet
    result["HTTP Response Time (s)"] = http_response_time
    result["HTTP Attempts"] = http_attempts
    result["Response Received"] = http_response_received
    result["Redirect History"] = http_redirect_history
    result["Redirected"] = http_redirected
    if dns_record_types:
        dns_result = await get_dns_record_for_domain(domain, dns_record_types)
        dns_records = dns_result[1]
        dns_summary = ", ".join(
            [f"{rtype}: {', '.join(val) if isinstance(val, list) else val}" for rtype, val in dns_records.items()]
        )
        result["DNS Records"] = dns_summary
    if cert_enabled:
        cert_expiry_date, days_until_expiry, cert_error = await process_certificate_check(domain)
        result["Certificate Expiry Date"] = cert_expiry_date if cert_expiry_date else ""
        result["Days Until Expiry"] = days_until_expiry if days_until_expiry is not None else ""
        result["Certificate Error"] = cert_error
    return result

async def run_all_in_one_checks(domains, timeout, concurrency, retries, dns_record_types, whois_enabled, cert_enabled):
    results = []
    semaphore = asyncio.Semaphore(concurrency)
    async with aiohttp.ClientSession() as session:
        tasks = [
            process_all_in_one(domain, timeout, retries, dns_record_types, whois_enabled, cert_enabled, session, semaphore)
            for domain in domains
        ]
        progress_bar = st.progress(0)
        total = len(tasks)
        completed = 0
        for future in asyncio.as_completed(tasks):
            result = await future
            results.append(result)
            completed += 1
            progress_bar.progress(int((completed / total) * 100))
    return results

st.set_page_config(page_title="🔍Domain Checker", layout="wide")
st.title("Domain Checker")

tabs = st.tabs(["HTTP Check", "DNS Lookup", "WHOIS Check", "TLS/SSL Certificate Check", "Advanced Check"])

# --------------------- HTTP Check Tab --------------------- #
with tabs[0]:
    st.header("HTTP Check")
    st.markdown("Retrieve the HTTP status code, a snippet of the response, response time, and redirection details. Use this to verify website availability and performance.")
    with st.form("http_form"):
        domains_input_http = st.text_area("Enter one or more domains (one per line):", height=200)
        timeout = st.number_input("Timeout (seconds)", min_value=1, value=10, step=1)
        concurrency = st.number_input("Concurrency", min_value=1, value=20, step=1)
        retries = st.number_input("Retries", min_value=1, value=3, step=1)
        submit_http = st.form_submit_button("Run HTTP Check")
    if submit_http:
        if not domains_input_http.strip():
            st.error("Please enter at least one domain.")
        else:
            domains_http = [line.strip() for line in domains_input_http.splitlines() if line.strip()]
            st.info("Starting HTTP checks...")
            http_results = asyncio.run(run_http_checks(domains_http, timeout, concurrency, retries))
            df_http = pd.DataFrame(
                http_results,
                columns=["Domain", "Status Code", "Response Snippet", "Response Time (s)",
                         "Attempts", "Response Received", "Redirect History", "Redirected"]
            )
            st.write("### HTTP Check Results", df_http)
            st.session_state["http_df"] = df_http
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            st.download_button("Download Table as CSV", df_http.to_csv(index=False),
                               file_name=f"HTTP_Check_Results_{timestamp}.csv", mime="text/csv")
    elif "http_df" in st.session_state:
        st.write("### HTTP Check Results", st.session_state["http_df"])

# --------------------- DNS Lookup Tab --------------------- #
with tabs[1]:
    st.header("DNS Lookup")
    st.markdown("Performs DNS record lookups for the specified domains. Select one or more DNS record types (e.g., A, AAAA, MX) to retrieve detailed DNS information for each domain.")
    with st.form("dns_form"):
        domains_input_dns = st.text_area("Enter one or more domains (one per line):", height=150, help="Example: example.com")
        st.markdown("### Select DNS Record Types")
        record_options = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]
        selected_record_types = []
        cols = st.columns(4)
        for i, rtype in enumerate(record_options):
            col = cols[i % 4]
            if col.checkbox(rtype, value=True, key=f"checkbox_{rtype}"):
                selected_record_types.append(rtype)
        submit_dns = st.form_submit_button("Lookup DNS Records")
    if submit_dns:
        if not domains_input_dns.strip():
            st.error("Please enter at least one domain.")
        elif not selected_record_types:
            st.error("Please select at least one DNS record type.")
        else:
            domains_dns = [line.strip() for line in domains_input_dns.splitlines() if line.strip()]
            total_domains = len(domains_dns)
            st.write(f"Processing **{total_domains}** domain(s)...")
            progress_bar = st.progress(0)
            def progress_callback(completed, total):
                progress_bar.progress(int((completed / total) * 100))
            start_time = time.time()
            dns_results = asyncio.run(run_dns_checks(domains_dns, selected_record_types, progress_callback))
            end_time = time.time()
            elapsed_time = end_time - start_time
            domains_per_second = total_domains / elapsed_time if elapsed_time > 0 else 0
            csv_output = io.StringIO()
            csv_writer = csv.writer(csv_output)
            header = ["Domain"] + selected_record_types
            csv_writer.writerow(header)
            data_rows = []
            for domain, recs in dns_results.items():
                row = [domain]
                for rtype in selected_record_types:
                    val = recs.get(rtype, "")
                    if isinstance(val, list):
                        val = "; ".join(val)
                    row.append(val)
                data_rows.append(row)
                csv_writer.writerow(row)
            csv_data = csv_output.getvalue()
            st.subheader("Statistics")
            st.write(f"**Time Taken:** {elapsed_time:.2f} seconds")
            st.write(f"**Processing Speed:** {domains_per_second:.2f} domains/second")
            st.download_button("Download Table as CSV", data=csv_data,
                               file_name=f"DNS_Lookup_Results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", mime="text/csv")
            st.subheader("DNS Results")
            df_dns = pd.DataFrame(data_rows, columns=header)
            st.write(df_dns)
            st.session_state["dns_df"] = df_dns
    elif "dns_df" in st.session_state:
        st.write("DNS Results", st.session_state["dns_df"])

# --------------------- WHOIS Check Tab --------------------- #
with tabs[2]:
    st.header("WHOIS Check")
    st.markdown("Retrieves domain registration details: Registrar, creation date, expiration date, and name servers.")
    with st.form("whois_form"):
        domains_input = st.text_area("Enter one or more domains (one per line):", height=200)
        submit_whois = st.form_submit_button("Run WHOIS Check")
    if submit_whois:
        if not domains_input.strip():
            st.error("Please enter at least one domain.")
        else:
            domains = [line.strip() for line in domains_input.splitlines() if line.strip()]
            st.info("Starting WHOIS lookups...")
            whois_results = asyncio.run(run_whois_checks(domains))
            df_whois = pd.DataFrame(
                whois_results,
                columns=["Domain", "Registrar", "WHOIS Creation Date", "WHOIS Expiration Date", "Name Servers", "WHOIS Error"]
            )
            if "WHOIS Error" in df_whois.columns and df_whois["WHOIS Error"].astype(str).str.strip().eq("").all():
                df_whois.drop(columns=["WHOIS Error"], inplace=True)
            st.write("### WHOIS Results", df_whois)
            st.session_state["whois_df"] = df_whois
            st.download_button("Download Table as CSV", df_whois.to_csv(index=False),
                               file_name=f"WHOIS_Results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", mime="text/csv")
    elif "whois_df" in st.session_state:
        st.write("### WHOIS Results", st.session_state["whois_df"])

# --------------------- TLS/SSL Certificate Check Tab --------------------- #
with tabs[3]:
    st.header("TLS/SSL Certificate Check")
    st.markdown("Performs a TLS/SSL certificate check for each domain. This check returns the certificate expiry date, calculates the number of days until expiry, and reports any errors encountered.")
    with st.form("cert_form"):
        domains_input_cert = st.text_area("Enter one or more domains (one per line):", height=200)
        submit_cert = st.form_submit_button("Run TLS/SSL Certificate Check")
    if submit_cert:
        if not domains_input_cert.strip():
            st.error("Please enter at least one domain.")
        else:
            domains_cert = [line.strip() for line in domains_input_cert.splitlines() if line.strip()]
            st.info("Starting TLS/SSL Certificate Check...")
            cert_results = asyncio.run(run_certificate_checks(domains_cert))
            df_cert = pd.DataFrame(
                cert_results,
                columns=["Domain", "Certificate Expiry Date", "Days Until Expiry", "Certificate Error"]
            )
            if "Certificate Error" in df_cert.columns and df_cert["Certificate Error"].astype(str).str.strip().eq("").all():
                df_cert.drop(columns=["Certificate Error"], inplace=True)
            st.write("### TLS/SSL Certificate Check Results", df_cert)
            st.session_state["cert_df"] = df_cert
            st.download_button("Download Table as CSV", df_cert.to_csv(index=False),
                               file_name=f"TLS_SSL_Certificate_Results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", mime="text/csv")
    elif "cert_df" in st.session_state:
        st.write("### TLS/SSL Certificate Check Results", st.session_state["cert_df"])

# --------------------- Advanced Check Tab --------------------- #
with tabs[4]:
    st.header("Advanced Check")
    st.markdown("Combines WHOIS, HTTP, and DNS lookups into one comprehensive report. Provides a full picture of each domain’s registration, server response, and DNS configuration.")
    with st.form("all_form"):
        domains_input_all = st.text_area("Enter one or more domains (one per line):", height=200)
        whois_enabled = st.checkbox("Enable WHOIS Lookup *(Slows Down Large Batches)*", value=False, key="all_whois_enabled")
        cert_enabled = st.checkbox("Enable TLS/SSL Certificate Check", value=False, key="all_cert_enabled")
        st.markdown("### Select DNS Record Types")
        record_options_all = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]
        selected_dns_all = []
        cols = st.columns(4)
        for i, rtype in enumerate(record_options_all):
            col = cols[i % 4]
            if col.checkbox(rtype, value=True, key=f"all_checkbox_{rtype}"):
                selected_dns_all.append(rtype)
        timeout_all = st.number_input("HTTP Timeout (seconds)", min_value=1, value=10, step=1)
        concurrency_all = st.number_input("HTTP Concurrency", min_value=1, value=20, step=1)
        retries_all = st.number_input("HTTP Retries", min_value=1, value=3, step=1)
        submit_all = st.form_submit_button("Run Advanced Check")
    if submit_all:
        if not domains_input_all.strip():
            st.error("Please enter at least one domain.")
        else:
            domains_all = [line.strip() for line in domains_input_all.splitlines() if line.strip()]
            enabled_checks = "HTTP"
            if whois_enabled:
                enabled_checks += ", WHOIS"
            if selected_dns_all:
                enabled_checks += ", DNS"
            if cert_enabled:
                enabled_checks += ", TLS/SSL Certificate Check"
            st.info(f"Starting All In One checks ({enabled_checks})...")

            start_time_all = time.time()
            all_results = asyncio.run(
                run_all_in_one_checks(domains_all, timeout_all, concurrency_all, retries_all, selected_dns_all, whois_enabled, cert_enabled)
            )
            end_time_all = time.time()
            elapsed_all = end_time_all - start_time_all
            st.write(f"**Total Time Taken:** {elapsed_all:.2f} seconds")

            columns = ["Domain", "HTTP Status"]
            if cert_enabled:
                columns.extend(["Certificate Expiry Date", "Days Until Expiry"])
            if selected_dns_all:
                columns.append("DNS Records")
            if whois_enabled:
                columns.extend(["Registrar", "WHOIS Creation Date", "WHOIS Expiration Date", "Name Servers"])
            columns.extend(["HTTP Response Time (s)", "HTTP Attempts", "Response Received", "Redirected", "Redirect History", "HTTP Snippet"])
            if whois_enabled:
                columns.append("WHOIS Error")
            if cert_enabled:
                columns.append("Certificate Error")
            df_all = pd.DataFrame(all_results)
            df_all = df_all[[col for col in columns if col in df_all.columns]]
            if "WHOIS Error" in df_all.columns and df_all["WHOIS Error"].astype(str).str.strip().eq("").all():
                df_all.drop(columns=["WHOIS Error"], inplace=True)
            if "Certificate Error" in df_all.columns and df_all["Certificate Error"].astype(str).str.strip().eq("").all():
                df_all.drop(columns=["Certificate Error"], inplace=True)
            st.write("### Advanced Check Results", df_all)
            st.session_state["adv_df"] = df_all
            st.download_button("Download Table as CSV", df_all.to_csv(index=False),
                               file_name=f"Advanced_Check_Results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", mime="text/csv")

            st.session_state["all_results"] = all_results

    if "all_results" in st.session_state:
        with st.expander("View Statistics"):
            all_results = st.session_state["all_results"]
            http_times = [res.get("HTTP Response Time (s)") for res in all_results if res.get("HTTP Response Time (s)") is not None]
            if http_times:
                avg_time = sum(http_times) / len(http_times)
                max_time = max(http_times)
                min_time = min(http_times)
                slowest_domains = [res["Domain"] for res in all_results if res.get("HTTP Response Time (s)") == max_time]
                fastest_domains = [res["Domain"] for res in all_results if res.get("HTTP Response Time (s)") == min_time]
                speed = len(http_times) / sum(http_times) if sum(http_times) > 0 else 0
                st.write(f"**Total Domains Processed:** {len(http_times)}")
                st.write(f"**Average HTTP Response Time:** {avg_time:.2f} seconds")
                if fastest_domains:
                    st.write(f"The fastest response was from {fastest_domains[0]} taking {min_time:.2f} seconds.")
                if slowest_domains:
                    st.write(f"The slowest response was from {slowest_domains[0]} taking {max_time:.2f} seconds.")
                st.write(f"**Speed per Domain:** {speed:.2f} domains per second")
            else:
                st.write("No HTTP response times available for advanced statistics.")
