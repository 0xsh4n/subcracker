# SubCracker

Advanced Subdomain Reconnaissance Tool for Bug Hunters and Security Researchers

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.5-blue.svg" alt="Version 2.5">
  <img src="https://img.shields.io/badge/Python-3.7+-green.svg" alt="Python 3.7+">
  <img src="https://img.shields.io/badge/License-MIT-red.svg" alt="License">
</p>

## Overview

SubCracker is a powerful subdomain reconnaissance tool designed for bug hunters and security researchers. It combines comprehensive discovery techniques with advanced analysis capabilities to identify and evaluate subdomains for security vulnerabilities.

## Features

- **Multi-Threaded Subdomain Discovery**: Rapidly scan for subdomains using customizable concurrency
- **Website Crawling Engine**: Intelligently extract potential subdomains from website content
- **Custom Wordlist Generation**: Create target-specific subdomain lists for more effective enumeration
- **Subdomain Takeover Detection**: Identify vulnerable subdomains susceptible to takeover attacks
- **Advanced DNS Analysis**: Comprehensive DNS record inspection and validation
- **Port Scanning Integration**: Discover open ports on identified subdomains
- **Multiple Output Formats**: Export results in JSON, CSV, and plaintext for further analysis
- **HTML Reports**: Generate visual reports with charts and statistics
- **Comprehensive Subdomain Analysis**: Get detailed information on each discovered subdomain

## Requirements

- Python 3.7+
- Required packages:
  - requests
  - dnspython
  - beautifulsoup4
  - rich
  - python-whois
  - tldextract

## Installation

```bash
# Clone the repository
git clone https://github.com/0xsh4n/subcracker.git
cd subcracker

chmod +x setup.sh
./setup.sh

# Install required dependencies
pip install -r requirements.txt
```

## Quick Start

```bash
# Basic usage
python3 subcracker.py -u example.com -w subdomains.txt

# Advanced usage with multiple features
python3 subcracker.py -u example.com -w subdomains.txt -t 100 --check-takeover --crawl --report
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `-u, --url` | Target URL or domain to scan for subdomains (Required) |
| `-w, --wordlist` | One or more wordlist files containing subdomains to check |
| `-t, --threads` | Number of concurrent threads for scanning (Default: 50) |
| `-o, --output-dir` | Directory to save output files (Default: "output") |
| `--timeout` | Timeout in seconds for HTTP/DNS requests (Default: 3.0) |
| `--dns-servers` | Custom DNS servers to use for resolution |
| `--user-agent` | Custom User-Agent string for HTTP requests |
| `--ignore-ssl-errors` | Ignore SSL certificate errors |
| `--report` | Generate an HTML report with visualizations |
| `--ports` | Comma-separated list of ports to scan (Default: 80,443,8080,8443) |
| `--check-takeover` | Check for potential subdomain takeover vulnerabilities |
| `--crawl` | Crawl the website to discover potential subdomains in content |
| `--crawl-depth` | Maximum depth to crawl from the starting page (Default: 2) |
| `--crawl-timeout` | Timeout in seconds for crawling requests (Default: 5.0) |
| `--max-crawl-urls` | Maximum number of URLs to crawl (Default: 500) |
| `-v, --verbose` | Increase verbosity level (use -v for verbose, -vv for very verbose) |

## Website Crawling Feature

The website crawling engine intelligently extracts potential subdomain names from the target website's content, similar to how CeWL generates password lists. This feature:

1. Crawls the target website to the specified depth
2. Analyzes HTML, JavaScript, and text content
3. Extracts strings that match potential subdomain patterns
4. Filters out false positives and common terms
5. Generates a custom wordlist (`subdomain_<domain>.txt`) for scanning

To use this feature:

```bash
python3 subcracker.py -u example.com --crawl --crawl-depth 3
```

The generated wordlist is automatically used in the current scan and saved for future use.

## Output Files

SubCracker generates several output files in the specified output directory:

- `<domain>_<timestamp>_subdomains.txt`: Simple list of discovered subdomains
- `<domain>_<timestamp>_detailed.json`: Detailed JSON output with all subdomain information
- `<domain>_<timestamp>_results.csv`: CSV format results for spreadsheet analysis
- `<domain>_<timestamp>_report.html`: HTML report with visualizations (when `--report` is used)
- `subdomain_<domain>.txt`: Custom wordlist generated from website crawling (when `--crawl` is used)

## Example Scenarios

### Bug Bounty Reconnaissance

```bash
python3 subcracker.py -u target-company.com --crawl --check-takeover -t 100 --report
```

This command will crawl the website, check for subdomain takeover vulnerabilities, use 100 concurrent threads, and generate a comprehensive HTML report.

### Creating a Custom Wordlist from Target

```bash
python3 subcracker.py -u target-company.com --crawl --crawl-depth 4 --max-crawl-urls 2000 -o custom_wordlists
```

This focuses on thorough website crawling to generate a comprehensive custom wordlist without performing a full scan.

### Comprehensive Scan with Multiple Wordlists

```bash
python3 subcracker.py -u target-company.com -w common_subdomains.txt technology_subdomains.txt --crawl --check-takeover --ports 80,443,8080,8443,3000,3001,5000,8000,8888 --report
```

This combines multiple wordlists with website crawling, takeover checks, and extended port scanning for a thorough assessment.

## Contributing

Contributions to SubCracker are welcome! If you'd like to contribute:

1. Fork the repository
2. Create a new branch (`git checkout -b feature-branch`)
3. Make your changes
4. Test thoroughly
5. Commit your changes (`git commit -am 'Add new feature'`)
6. Push to the branch (`git push origin feature-branch`)
7. Create a new Pull Request

Please follow the existing code style and include appropriate documentation and tests for new features.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is intended for security research with proper authorization. Always ensure you have permission to scan the target domain. Unauthorized scanning may violate laws and regulations.
