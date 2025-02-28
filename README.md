# SubCracker

Advanced Subdomain Discovery Tool for Bug Hunters and Security Researchers

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.5-blue.svg" alt="Version 2.5">
  <img src="https://img.shields.io/badge/Python-3.7+-green.svg" alt="Python 3.7+">
  <img src="https://img.shields.io/badge/License-MIT-red.svg" alt="License">
</p>

## Overview

SubCracker is a powerful subdomain discovery tool designed for bug hunters and security researchers. It combines comprehensive discovery techniques with advanced analysis capabilities to identify and evaluate subdomains for security vulnerabilities.

## Features

- **Multi-Threaded Subdomain Discovery**: Scan with up to 200 concurrent threads for faster results
- **Website Crawling Engine**: Extract potential subdomains from target website content
- **Custom Wordlist Generation**: Create target-specific subdomain lists
- **Subdomain Takeover Detection**: Identify vulnerable subdomains susceptible to takeover
- **Advanced DNS Analysis**: Comprehensive DNS record inspection
- **Port Scanning**: Discover open ports on identified subdomains
- **Interactive HTML Reports**: Generate visual reports with charts and statistics
- **Multiple Output Formats**: Export results in TXT, JSON, and CSV formats
- **Robust Error Handling**: Gracefully handle timeouts and connection issues

## Requirements

- Python 3.7+
- Required packages (see requirements.txt)

## Installation

```bash
# Clone the repository
git clone https://github.com/0xsh4n/subcracker.git
cd subcracker

chmod +x install.sh
./install.sh

# Install required dependencies
pip install -r requirements.txt

# Make the script executable
chmod +x subcracker.py
```

## Quick Start

```bash
# Basic usage
./subcracker.py -u example.com -w wordlists/subdomains.txt

# Advanced usage with multiple features
./subcracker.py -u example.com -w wordlists/subdomains.txt -t 100 --check-takeover --crawl --report
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `-u, --url` | Target URL or domain to scan for subdomains (Required) |
| `-w, --wordlist` | One or more wordlist files containing subdomains to check |
| `-t, --threads` | Number of concurrent threads for scanning (Default: 50, Range: 1-200) |
| `-o, --output-dir` | Directory to save output files (Default: "output") |
| `--timeout` | Timeout in seconds for HTTP/DNS requests (Default: 3.0) |
| `--dns-servers` | Custom DNS servers to use for resolution (e.g., 8.8.8.8 1.1.1.1) |
| `--user-agent` | Custom User-Agent string for HTTP requests |
| `--ignore-ssl-errors` | Ignore SSL certificate errors |
| `--report` | Generate an HTML report with visualizations |
| `--ports` | Comma-separated list of ports to scan (Default: 80,443,8080,8443) |
| `--check-takeover` | Check for potential subdomain takeover vulnerabilities |
| `--crawl` | Crawl the website to discover potential subdomains in content |
| `--crawl-depth` | Maximum depth to crawl from the starting page (Default: 2, Range: 1-5) |
| `--crawl-timeout` | Timeout in seconds for crawling requests (Default: 5.0) |
| `--max-crawl-urls` | Maximum number of URLs to crawl (Default: 500, Range: 10-2000) |
| `-v, --verbose` | Increase verbosity level (use -v for verbose, -vv for very verbose) |
| `--version` | Show program version and exit |

## Website Crawling Feature

The website crawling engine intelligently extracts potential subdomain names from the target website's content. This feature works similarly to tools like CeWL but is specifically focused on finding subdomains.

```bash
# Basic crawling
./subcracker.py -u example.com --crawl

# Deeper crawl with more URLs
./subcracker.py -u example.com --crawl --crawl-depth 4 --max-crawl-urls 1000
```

The crawler will:
1. Visit the target domain and extract potential subdomain names
2. Follow links to discover more content (up to the specified depth)
3. Generate a custom wordlist file named `subdomain_<domain>.txt`
4. Automatically use these potential subdomains in the current scan

## Output Files

SubCracker generates several output files in the specified output directory:

- `<domain>_<timestamp>_subdomains.txt`: Simple list of discovered subdomains
- `<domain>_<timestamp>_detailed.json`: Detailed JSON output with all information
- `<domain>_<timestamp>_results.csv`: CSV format results for spreadsheet analysis
- `<domain>_<timestamp>_report.html`: Interactive HTML report with visualizations (when `--report` is used)
- `subdomain_<domain>.txt`: Custom wordlist generated from website crawling (when `--crawl` is used)
- `subcracker.log`: Log file containing detailed information about any errors

## Viewing HTML Reports

The HTML report provides a visual representation of your subdomain scan results, including interactive charts and tables. To view the report:

### Method 1: Direct browser opening
1. After running SubCracker with the `--report` flag, it will generate an HTML file in the output directory.
2. The path to this file will be displayed in the console output.
3. Open this HTML file in any web browser:
   ```bash
   firefox output/example.com_20250228_123456_report.html
   ```

### Method 2: Using Python's HTTP server
If you want to serve the reports through a web server:

1. Navigate to your output directory:
   ```bash
   cd output
   ```

2. Start a simple HTTP server:
   ```bash
   python3 -m http.server 8080
   ```

3. Open a browser and go to:
   ```
   http://localhost:8080
   ```

4. Browse to the HTML report file from there.

## Example Scenarios

### Bug Bounty Reconnaissance

```bash
./subcracker.py -u target-company.com --crawl --check-takeover -t 100 --report --ignore-ssl-errors
```

This command will crawl the website, check for subdomain takeover vulnerabilities, use 100 concurrent threads, ignore SSL errors, and generate a comprehensive HTML report.

### Creating a Custom Wordlist from Target

```bash
./subcracker.py -u target-company.com --crawl --crawl-depth 4 --max-crawl-urls 2000 -o custom_wordlists
```

This focuses on thorough website crawling to generate a comprehensive custom wordlist without performing a full scan.

### Comprehensive Scan with Multiple Wordlists

```bash
./subcracker.py -u target-company.com -w common_subdomains.txt technology_subdomains.txt --crawl --check-takeover --ports 80,443,8080,8443,3000,3001,5000,8000,8888 --report
```

This combines multiple wordlists with website crawling, takeover checks, and extended port scanning for a thorough assessment.

## Troubleshooting

If you encounter issues:

1. Check the `subcracker.log` file for detailed error information
2. Ensure you have the latest version of all dependencies
3. Try increasing timeouts with `--timeout` and `--crawl-timeout` for slow networks
4. Use `-v` or `-vv` to get more detailed output during execution

## Contributing

Contributions to SubCracker are welcome! If you'd like to contribute:

1. Fork the repository
2. Create a new branch (`git checkout -b feature-branch`)
3. Make your changes
4. Test thoroughly
5. Commit your changes (`git commit -am 'Add new feature'`)
6. Push to the branch (`git push origin feature-branch`)
7. Create a new Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is intended for security research with proper authorization. Always ensure you have permission to scan the target domain. Unauthorized scanning may violate laws and regulations.
