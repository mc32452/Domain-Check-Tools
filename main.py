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

# Global HTTP headers (used for HTTP check and All In One)
http_headers = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/90.0.4430.93 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5"
}

# Global cache for WHOIS lookups
WHOIS_CACHE = {}

# ============================
# WHOIS CHECK FUNCTIONS
# ============================

def get_whois_info(domain):
    """
    Synchronously retrieves WHOIS information for the given domain.
    Uses a retry loop with exponential backoff and caches responses.
    Returns a dictionary with registrar, creation_date, expiration_date,
    name_servers, and any error encountered.
    """
    global WHOIS_CACHE

    # Return cached result if available
    if domain in WHOIS_CACHE:
        return WHOIS_CACHE[domain]

    # Introduce a small delay before making the request to help throttle lookups.
    time.sleep(0.2)

    max_attempts = 3
    backoff_factor = 0.5  # initial backoff in seconds

    for attempt in range(max_attempts):
        try:
            # On retry attempts, wait exponentially longer.
            if attempt > 0:
                delay = backoff_factor * (2 ** (attempt - 1))
                time.sleep(delay)

            w = whois.whois(domain)
            registrar = w.registrar if hasattr(w, 'registrar') else ""
            creation_date = w.creation_date
            expiration_date = w.expiration_date
            name_servers = w.name_servers if hasattr(w, 'name_servers') else ""

            # If name_servers is a list, join into a comma-separated string
            if isinstance(name_servers, list):
                name_servers = ", ".join(name_servers)

            # In case creation_date or expiration_date is a list, use the first element.
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
            # Cache the successful result
            WHOIS_CACHE[domain] = result
            return result

        except Exception as e:
            error_str = str(e)
            # Custom error handling for connection reset errors.
            if "reset" in error_str.lower():
                error_str = "Connection reset error. Please try again later."
            # If this is the last attempt, return the error.
            if attempt == max_attempts - 1:
                result = {
                    "registrar": "",
                    "creation_date": "",
                    "expiration_date": "",
                    "name_servers": "",
                    "error": error_str
                }
                # Cache the error result so that subsequent lookups don't re-trigger the failure.
                WHOIS_CACHE[domain] = result
                return result
            # Otherwise, continue to the next retry attempt.

async def process_whois_domain(domain):
    """
    Runs the WHOIS lookup for a domain asynchronously.
    """
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
    """
    Processes a list of domains concurrently for WHOIS lookups.
    """
    tasks = [process_whois_domain(domain) for domain in domains]
    results = []
    total = len(tasks)
    progress_bar = st.progress(0)
    for i, coro in enumerate(asyncio.as_completed(tasks), start=1):
        result = await coro
        results.append(result)
        progress_bar.progress(int((i / total) * 100))
    return results

# ============================
# HTTP CHECK FUNCTIONS
# ============================

async def check_http_domain(domain, timeout, retries, session, headers, semaphore):
    """
    Performs an HTTP GET request for the domain and logs:
      - HTTP status
      - A snippet of the response
      - Response time and number of attempts
      - Redirection chain and a simple Yes/No flag if a redirect occurred.

    Only "significant" redirects are flagged. Changes solely in scheme (http vs https),
    the presence or absence of a "www." prefix, or trailing slashes are ignored.
    """
    url = "http://" + domain if not domain.startswith(("http://", "https://")) else domain
    attempt = 0
    error_message = ""
    response_time = None
    redirect_info = ""
    redirected = "No"
    start_time = time.perf_counter()

    # Function to normalize a URL (ignoring scheme, www, and trailing slash)
    def normalize_url(url):
        parsed = urlparse(url)
        # Lowercase the hostname and strip "www."
        netloc = parsed.netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]
        # Remove trailing slash from the path
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

                    # Build the redirect chain if present.
                    if response.history:
                        redirects = [str(resp.url) for resp in response.history]
                        redirects.append(str(response.url))
                        redirect_info = " -> ".join(redirects)
                    else:
                        redirect_info = "No redirect"

                    # Normalize the original and final URLs.
                    original_norm = normalize_url(url)
                    final_norm = normalize_url(str(response.url))

                    # Only mark as a redirect if the normalized values differ.
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
    """
    Processes a list of domains concurrently for HTTP checks.
    """
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

# ============================
# DNS LOOKUP FUNCTIONS
# ============================

async def get_dns_record_for_domain(domain, record_types):
    """
    Asynchronously fetch DNS records for a given domain and record types.
    """
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
    """
    Processes a list of domains concurrently for DNS lookups.
    """
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

# ============================
# ALL IN ONE CHECK FUNCTIONS
# ============================

async def process_all_in_one(domain, timeout, retries, dns_record_types, whois_enabled, session, semaphore):
    """
    Runs the selected checks (WHOIS, HTTP, DNS) for the given domain concurrently.
    Returns a dictionary with the results, including only the enabled checks.
    """
    result = {"Domain": domain}

    # WHOIS lookup if enabled
    if whois_enabled:
        whois_info = await asyncio.to_thread(get_whois_info, domain)
        result["Registrar"] = whois_info.get("registrar", "")
        result["Creation Date"] = whois_info.get("creation_date", "")
        result["Expiration Date"] = whois_info.get("expiration_date", "")
        result["Name Servers"] = whois_info.get("name_servers", "")
        result["WHOIS Error"] = whois_info.get("error", "")

    # HTTP lookup (always enabled)
    http_result = await check_http_domain(domain, timeout, retries, session, http_headers, semaphore)
    # Unpack HTTP result (skip domain, then rest of the fields)
    (_, http_status, http_snippet, http_response_time, http_attempts,
     http_response_received, http_redirect_history, http_redirected) = http_result

    result["HTTP Status"] = http_status
    result["HTTP Snippet"] = http_snippet
    result["HTTP Response Time (s)"] = http_response_time
    result["HTTP Attempts"] = http_attempts
    result["Response Received"] = http_response_received
    result["Redirect History"] = http_redirect_history
    result["Redirected"] = http_redirected

    # DNS lookup if any record types are selected
    if dns_record_types:
        dns_result = await get_dns_record_for_domain(domain, dns_record_types)
        dns_records = dns_result[1]  # dictionary of DNS records
        dns_summary = ", ".join(
            [f"{rtype}: {', '.join(val) if isinstance(val, list) else val}" for rtype, val in dns_records.items()]
        )
        result["DNS Records"] = dns_summary

    return result

async def run_all_in_one_checks(domains, timeout, concurrency, retries, dns_record_types, whois_enabled):
    results = []
    semaphore = asyncio.Semaphore(concurrency)
    async with aiohttp.ClientSession() as session:
        tasks = [
            process_all_in_one(domain, timeout, retries, dns_record_types, whois_enabled, session, semaphore)
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

# ============================
# STREAMLIT USER INTERFACE
# ============================

st.set_page_config(page_title="Domain Checker", layout="wide")
st.title("Domain Checker")

# Create four tabs: WHOIS, HTTP, DNS, and All In One.
tabs = st.tabs(["WHOIS Check", "HTTP Check", "DNS Lookup", "All In One"])

# ----- WHOIS Check Tab -----
with tabs[0]:
    st.header("WHOIS Check")
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
                columns=[
                    "Domain", "Registrar", "Creation Date",
                    "Expiration Date", "Name Servers", "WHOIS Error"
                ]
            )
            st.write("### WHOIS Results", df_whois)

            csv_buffer = io.StringIO()
            df_whois.to_csv(csv_buffer, index=False)
            st.download_button("Download WHOIS CSV", csv_buffer.getvalue(),
                               file_name="whois_results.csv", mime="text/csv")

# ----- HTTP Check Tab -----
with tabs[1]:
    st.header("HTTP Check")
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
                columns=[
                    "Domain", "Status Code", "Response Snippet", "Response Time (s)",
                    "Attempts", "Response Received", "Redirect History", "Redirected"
                ]
            )
            st.write("### HTTP Check Results", df_http)

            csv_buffer = io.StringIO()
            df_http.to_csv(csv_buffer, index=False)
            st.download_button("Download HTTP CSV", csv_buffer.getvalue(),
                               file_name="http_results.csv", mime="text/csv")

# ----- DNS Lookup Tab -----
with tabs[2]:
    st.header("DNS Lookup")
    with st.form("dns_form"):
        domains_input_dns = st.text_area("Enter one or more domains (one per line):", height=150,
                                         help="Example: example.com")
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

            # Build CSV output
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
            st.download_button("Download DNS CSV", data=csv_data, file_name="dns_lookup_results.csv", mime="text/csv")
            st.subheader("DNS Results")
            df_dns = pd.DataFrame(data_rows, columns=header)
            st.dataframe(df_dns, use_container_width=True)

# ----- All In One Tab -----
with tabs[3]:
    st.header("All In One Check")
    with st.form("all_form"):
        domains_input_all = st.text_area("Enter one or more domains (one per line):", height=200)
        # Toggle for WHOIS lookup
        whois_enabled = st.checkbox("Enable WHOIS Lookup", value=True, key="all_whois_enabled")
        # DNS selection in an expandable section (optional)
        with st.expander("Selected DNS Record Types", expanded=False):
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
        submit_all = st.form_submit_button("Run All Checks")

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
            st.info(f"Starting All In One checks ({enabled_checks})...")
            all_results = asyncio.run(
                run_all_in_one_checks(domains_all, timeout_all, concurrency_all, retries_all, selected_dns_all, whois_enabled)
            )
            # Build DataFrame columns based on enabled checks
            columns = ["Domain"]
            if whois_enabled:
                columns.extend(["Registrar", "Creation Date", "Expiration Date", "Name Servers", "WHOIS Error"])
            columns.extend(["HTTP Status", "HTTP Snippet", "HTTP Response Time (s)", "HTTP Attempts", "Response Received", "Redirect History", "Redirected"])
            if selected_dns_all:
                columns.append("DNS Records")
            df_all = pd.DataFrame(all_results)
            # Reorder columns if they exist in the DataFrame
            df_all = df_all[[col for col in columns if col in df_all.columns]]
            st.write("### All In One Results", df_all)

            csv_buffer = io.StringIO()
            df_all.to_csv(csv_buffer, index=False)
            st.download_button("Download All-In-One CSV", csv_buffer.getvalue(),
                               file_name="all_in_one_results.csv", mime="text/csv")
