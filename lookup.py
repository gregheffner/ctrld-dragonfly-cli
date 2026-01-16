import argparse
import json
import sys

from termcolor import colored


def print_section(title, color):
    print(colored(f"\n{title}", color, attrs=["bold"]))


import pandas as pd
import requests
from tabulate import tabulate


def lookup_domain(
    domain,
    output_json=False,
    show_categories=True,
    show_dns=True,
    show_geoip=True,
    show_tls=True,
    show_whois=True,
):
    url = API_URL.format(domain)
    response = requests.get(url)
    if response.status_code != 200:
        print(f"Error: {response.status_code}")
        print(response.text)
        return
    data = response.json()
    if output_json:
        print(json.dumps(data, indent=2))
        return
    # Section outputs
    if show_categories:
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
            print(colored(f"Could not parse categories: {e}", "red"))
    if show_dns:
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
            print(colored(f"Could not parse DNS records: {e}", "red"))
    if show_geoip:
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
            print(colored(f"Could not parse GeoIP data: {e}", "red"))
    if show_tls:
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
            print(colored(f"Could not parse TLS data: {e}", "red"))
    if show_whois:
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
            print(colored(f"Could not parse WHOIS data: {e}", "red"))


API_URL = "https://api.sentinel.controld.com/api/v1/domains/{}"


def main():
    parser = argparse.ArgumentParser(
        description="""
controld-lookup: Query domain intelligence from ControlD Sentinel API.

Usage:
  python lookup_domain.py <domain> [options]

Options:
  --json           Output full JSON response only (no formatting)
  --categories     Show only domain categories
  --dns            Show only DNS records
  --geoip          Show only GeoIP snapshot
  --tls            Show only TLS results
  --whois          Show only WHOIS data

If no section flags are provided, all sections are shown (except --json, which overrides all).
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("domain", help="Domain to look up")
    parser.add_argument("--json", action="store_true", help="Output raw JSON only")
    parser.add_argument(
        "--categories", action="store_true", help="Show only domain categories"
    )
    parser.add_argument("--dns", action="store_true", help="Show only DNS records")
    parser.add_argument("--geoip", action="store_true", help="Show only GeoIP snapshot")
    parser.add_argument("--tls", action="store_true", help="Show only TLS results")
    parser.add_argument("--whois", action="store_true", help="Show only WHOIS data")
    args = parser.parse_args()

    # Section flags: if any are set, only show those
    section_flags = [args.categories, args.dns, args.geoip, args.tls, args.whois]
    if any(section_flags):
        show_categories = args.categories
        show_dns = args.dns
        show_geoip = args.geoip
        show_tls = args.tls
        show_whois = args.whois
    else:
        show_categories = show_dns = show_geoip = show_tls = show_whois = True

    lookup_domain(
        args.domain,
        output_json=args.json,
        show_categories=show_categories,
        show_dns=show_dns,
        show_geoip=show_geoip,
        show_tls=show_tls,
        show_whois=show_whois,
    )


if __name__ == "__main__":
    main()
