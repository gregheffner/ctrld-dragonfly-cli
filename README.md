# ControlD Dragonfly Domain Lookup CLI

This is a simple Python CLI tool to query the [ControlD Dragonfly URL Filtering](https://controld.com/tools/dragonfly-url-filtering) API and display domain information in a readable table format.

## Features
- Lookup domain categories, DNS records, GeoIP, TLS, and WHOIS data
- Output is formatted as tables using pandas
- Uses the same public API as the ControlD Dragonfly web tool

## Usage
1. **Clone this repository and enter the directory:**
   ```sh
   git clone <your-repo-url>
   cd controld-lookup
   ```
2. **Create a virtual environment and install dependencies:**
   ```sh
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
   Or install manually:
   ```sh
   pip install requests pandas tabulate
   ```
3. **Get your ControlD API Authorization token:**
   - Go to [https://controld.com/tools/dragonfly-url-filtering](https://controld.com/tools/dragonfly-url-filtering)
   - Open your browser's Developer Tools (Network tab)
   - Perform a lookup and copy the `Authorization` header value from the API request
   - Paste your token into the script where indicated (do NOT share your token publicly)

4. **Run the script:**
   ```sh
   python lookup_domain.py <domain>
   ```

## Notes
- This tool is for personal and educational use.
- Do not publish your personal Authorization token.
- For more information about ControlD and their services, visit [https://controld.com](https://controld.com)

## Disclaimer
This project is not affiliated with or endorsed by ControlD. Use of the API is subject to ControlD's terms of service.
