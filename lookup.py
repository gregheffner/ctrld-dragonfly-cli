API_URL = "https://api.sentinel.controld.com/api/v1/domains/{}"
# The Authorization token below is a sample from your browser session. For production, you may need to refresh it or use your own.
AUTHORIZATION = ""


import sys
import pandas as pd
import requests


def lookup_domain(domain):

    API_URL = "https://api.sentinel.controld.com/api/v1/domains/{}"


def lookup_domain(domain):
    url = API_URL.format(domain)
    headers = {
        "Accept": "*/*",
        "Authorization": AUTHORIZATION,
        "Content-Type": "application/json",
        "Origin": "https://controld.com",
        "Referer": "https://controld.com/",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 Safari/605.1.15",
    }
    response = requests.get(url, headers=headers)
    print(f"Status: {response.status_code}")
    if response.status_code != 200:
        print(response.text)
        return
    data = response.json()
    # Extract categories
    try:
        categories = data["body"]["features"]["classification"]["categories"]
        df = pd.DataFrame(categories)
        df = df[["name", "confidence", "confidenceLabel", "reasoning"]]
        print("\nDomain Categories:")
        print(df.to_markdown(index=False))
    except Exception as e:
        print("Could not parse categories:", e)
    # Optionally, print DNS records
    try:
        dns = data["body"]["features"]["dns"]["records"]
        dns_rows = []
        for record_type, records in dns.items():
            if isinstance(records, list):
                for rec in records:
                    # Some records may be dicts with 'value' and 'ttl', others just strings
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
                dns_rows.append({"Type": record_type, "Address": address, "TTL": ttl})
        if dns_rows:
            dns_df = pd.DataFrame(dns_rows)
            print("\nDNS Records:")
            print(dns_df.to_markdown(index=False))
        else:
            print("No DNS records found.")
    except Exception as e:
        print("Could not parse DNS records:", e)
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
                    # Location is not always available, so leave blank if missing
                    "Location": info.get("location", ""),
                }
            )
        if geoip_rows:
            geoip_df = pd.DataFrame(geoip_rows)
            print("\nGeoIP Snapshot:")
            print(geoip_df.to_markdown(index=False))
        else:
            print("No GeoIP data found.")
    except Exception as e:
        print("Could not parse GeoIP data:", e)

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
        print("\nTLS Results:")
        print(tls_df.to_markdown(index=False))
    except Exception as e:
        print("Could not parse TLS data:", e)

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
        print("\nWHOIS Data:")
        print(whois_df.to_markdown(index=False))
    except Exception as e:
        print("Could not parse WHOIS data:", e)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python lookup_domain.py <domain>")
        sys.exit(1)
    lookup_domain(sys.argv[1])
