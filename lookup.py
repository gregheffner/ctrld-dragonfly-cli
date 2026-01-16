API_URL = "https://api.sentinel.controld.com/api/v1/domains/{}"
# The Authorization token below is a sample from your browser session. For production, you may need to refresh it or use your own.
AUTHORIZATION = ""


import sys
import time

import pandas as pd
import requests
from tabulate import tabulate
from termcolor import colored


def print_section(title, color):
    print(colored(f"\n{title}", color, attrs=["bold"]))


def lookup_domain(domain, retries=3, delay=2):
    url = API_URL.format(domain)
    headers = {
        "Accept": "*/*",
        "Authorization": AUTHORIZATION,
        "Content-Type": "application/json",
        "Origin": "https://controld.com",
        "Referer": "https://controld.com/",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 Safari/605.1.15",
    }
    for attempt in range(1, retries + 1):
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print(colored(f"Error: {response.status_code}", "red"))
            print(response.text)
            return
        data = response.json()
        parse_errors = []
        # Try all sections, collect parse errors
        # Domain Categories
        try:
            categories = data["body"]["features"]["classification"]["categories"]
            df = pd.DataFrame(categories)
            df = df[["name", "confidence", "confidenceLabel", "reasoning"]]
            print_section("Domain Categories:", "cyan")
            print(
                tabulate(
                    df,
                    headers="keys",
                    tablefmt="fancy_grid",
                    showindex=False,
                    stralign="left",
                )
            )
        except Exception as e:
            parse_errors.append("categories")
            print(colored(f"Could not parse categories: {e}", "red"))
        # DNS Records
        try:
            dns = data["body"]["features"]["dns"]["records"]
            dns_rows = []
            for record_type, records in dns.items():
                if isinstance(records, list):
                    for rec in records:
                        if isinstance(rec, dict):
                            address = rec.get("value", "")
                            ttl = rec.get("ttl", "")
                        else:
                            address = rec
                            ttl = ""
                        dns_rows.append(
                            {"Type": record_type, "Address": address, "TTL": ttl}
                        )
                elif isinstance(records, dict):
                    address = records.get("value", "")
                    ttl = records.get("ttl", "")
                    dns_rows.append(
                        {"Type": record_type, "Address": address, "TTL": ttl}
                    )
            if dns_rows:
                dns_df = pd.DataFrame(dns_rows)
                print_section("DNS Records:", "green")
                print(
                    tabulate(
                        dns_df,
                        headers="keys",
                        tablefmt="fancy_grid",
                        showindex=False,
                        stralign="left",
                    )
                )
            else:
                print(colored("No DNS records found.", "yellow"))
        except Exception as e:
            parse_errors.append("dns")
            print(colored(f"Could not parse DNS records: {e}", "red"))
        # GeoIP Snapshot
        try:
            geoip = data["body"]["features"].get("geoip", {}).get("ipLocations", {})
            geoip_rows = []
            for ip, info in geoip.items():
                geoip_rows.append(
                    {
                        "IP": ip,
                        "ASN": info.get("asn", ""),
                        "ISP": info.get("organization", ""),
                        "Location": info.get("location", ""),
                    }
                )
            if geoip_rows:
                geoip_df = pd.DataFrame(geoip_rows)
                print_section("GeoIP Snapshot:", "magenta")
                print(
                    tabulate(
                        geoip_df,
                        headers="keys",
                        tablefmt="fancy_grid",
                        showindex=False,
                        stralign="left",
                    )
                )
            else:
                print(colored("No GeoIP data found.", "yellow"))
        except Exception as e:
            parse_errors.append("geoip")
            print(colored(f"Could not parse GeoIP data: {e}", "red"))
        # TLS Results
        try:
            tls = data["body"]["features"].get("tls", {})
            tls_rows = [
                {
                    "Version": tls.get("supportedProtocols", ""),
                    "Issuer": tls.get("issuer", ""),
                    "Valid From": tls.get("validFrom", ""),
                    "Valid Until": tls.get("validUntil", ""),
                }
            ]
            tls_df = pd.DataFrame(tls_rows)
            print_section("TLS Results:", "yellow")
            print(
                tabulate(
                    tls_df,
                    headers="keys",
                    tablefmt="fancy_grid",
                    showindex=False,
                    stralign="left",
                )
            )
        except Exception as e:
            parse_errors.append("tls")
            print(colored(f"Could not parse TLS data: {e}", "red"))
        # WHOIS Data
        try:
            whois = data["body"]["features"].get("whois", {}).get("parsed", {})
            whois_rows = [
                {
                    "Registrar": whois.get("registrar", ""),
                    "Expires": whois.get("expirationDate", ""),
                    "Registered": whois.get("creationDate", ""),
                    "Updated": whois.get("lastUpdated", ""),
                }
            ]
            whois_df = pd.DataFrame(whois_rows)
            print_section("WHOIS Data:", "blue")
            print(
                tabulate(
                    whois_df,
                    headers="keys",
                    tablefmt="fancy_grid",
                    showindex=False,
                    stralign="left",
                )
            )
        except Exception as e:
            parse_errors.append("whois")
            print(colored(f"Could not parse WHOIS data: {e}", "red"))
        # If no parse errors, break
        if not parse_errors:
            break
        elif attempt < retries:
            print(
                colored(
                    f"\nSome info not available yet, retrying in {delay}s... (Attempt {attempt+1}/{retries})",
                    "yellow",
                )
            )
            time.sleep(delay)
        else:
            print(colored("\nSome info could not be loaded after retries.", "red"))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python lookup_domain.py <domain>")
        sys.exit(1)
    lookup_domain(sys.argv[1])
