#!/usr/bin/env python3

############################################################################
#          Copyright (c) 2025 Sub Cracker. All rights reserved.        #
#                Subdomain reconnaissance and discovery tool           #
#            For licensing inquiries, contact: mr-sh4n@tuta.io         #
############################################################################

import requests
import sys
import os
import time
import json
import argparse
import threading
import concurrent.futures
import socket
import dns.resolver
import whois
import urllib3
import csv
import socket
import ipaddress
import re
import tldextract
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urljoin
from rich.console import Console
from rich.progress import Progress, TextColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint
from bs4 import BeautifulSoup

# Disable SSL warnings for testing purposes
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize rich console for attractive output
console = Console()

# Define color scheme for consistent branding
COLORS = {
    "primary": "blue",
    "secondary": "cyan",
    "success": "green",
    "warning": "yellow",
    "error": "red",
    "info": "white"
}

class SubDomainHunter:
    def __init__(self, args):
        """Initialize the SubCracker with command line arguments."""
        self.args = args
        self.target_url = args.url
        self.output_dir = args.output_dir
        self.threads = args.threads
        self.timeout = args.timeout
        self.wordlist_files = self._prepare_wordlists(args.wordlist)
        self.discovered_subdomains = set()
        self.valid_subdomains = []
        self.scan_start_time = None
        self.scan_end_time = None
        self.dns_servers = args.dns_servers or ["8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9"]
        self.user_agent = args.user_agent or "SubCracker v2.5 - Subdomain Enumeration Tool"
        self.verify_ssl = not args.ignore_ssl_errors
        self.generate_report = args.report
        self.scan_ports = args.ports
        self.takeover_check = args.check_takeover
        self.status_codes = set()
        self.crawl_depth = args.crawl_depth
        self.crawl_timeout = args.crawl_timeout
        self.max_crawl_urls = args.max_crawl_urls
        self.crawled_urls = set()
        self.crawl_patterns = [
            r'((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})',  # Domain pattern
            r'([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)',      # Subdomain pattern
        ]
        self.potential_subdomains = set()

        # Set up DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = self.dns_servers
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout

        # Ensure output directory exists
        if self.output_dir:
            os.makedirs(self.output_dir, exist_ok=True)

    def _prepare_wordlists(self, wordlist_args):
        """Prepare wordlists from user arguments."""
        wordlists = []
        
        # Default wordlist if none provided
        if not wordlist_args:
            default_path = Path("subdomains.txt")
            if default_path.exists():
                wordlists.append(default_path)
            else:
                console.print("[bold red]Error:[/bold red] Default wordlist 'subdomains.txt' not found.")
                console.print("Please provide a wordlist with --wordlist or create 'subdomains.txt'")
                sys.exit(1)
        else:
            for wordlist in wordlist_args:
                path = Path(wordlist)
                if path.exists():
                    wordlists.append(path)
                else:
                    console.print(f"[bold yellow]Warning:[/bold yellow] Wordlist {wordlist} not found, skipping.")
        
        return wordlists

    def print_banner(self):
        """Display the Tool banner."""
        banner = """
 ███████╗██╗   ██╗██████╗  ██████╗██████╗  █████╗  ██████╗██╗  ██╗███████╗ ██████╗ 
 ██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝ ██╔══██╗
 ███████╗██║   ██║██████╔╝██║     ██████╔╝███████║██║     █████╔╝ █████╗   ██████╔╝
 ╚════██║██║   ██║██╔══██╗██║     ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝   ██╔══██╗
 ███████║╚██████╔╝██████╔╝╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗███████╗ ██║  ██║
 ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═╝  ╚═╝
        """
        
        panel = Panel(
            f"[bold {COLORS['primary']}]{banner}[/bold {COLORS['primary']}]", 
            subtitle="[bold {COLORS['secondary']}]Subdomain Reconnaissance Tool v2.5[/bold {COLORS['secondary']}]"
        )
        console.print(panel)
        console.print(f"[bold {COLORS['info']}]Subdomain discovery and analysis for security researchers[/bold {COLORS['info']}]")
        console.print(f"[{COLORS['secondary']}]© 2025 SubCracker - All rights reserved[/{COLORS['secondary']}]")
        console.print()

    def parse_url(self, url):
        """Parse and normalize the target URL."""
        if not (url.startswith('http://') or url.startswith('https://')):
            url = 'https://' + url
        
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        
        # Remove www. if present
        if domain.startswith('www.'):
            domain = domain[4:]
            
        return domain

    def validate_domain(self, domain):
        """Validate that the domain exists and is reachable."""
        try:
            socket.gethostbyname(domain)
            return True
        except socket.gaierror:
            return False

    def load_subdomains(self):
        """Load subdomain wordlists and add any from crawling if enabled."""
        subdomains = set()
        
        # First check if we need to crawl the site
        if self.args.crawl:
            self.crawl_website()
            
            # Save the crawled subdomains to a wordlist if any were found
            if self.potential_subdomains:
                domain = self.parse_url(self.target_url)
                crawl_wordlist = os.path.join(self.output_dir, f"subdomain_{domain}.txt")
                try:
                    with open(crawl_wordlist, 'w') as f:
                        for subdomain in sorted(self.potential_subdomains):
                            f.write(f"{subdomain}\n")
                    console.print(f"[bold {COLORS['success']}]Saved {len(self.potential_subdomains)} crawled potential subdomains to {crawl_wordlist}[/bold {COLORS['success']}]")
                    
                    # Add to wordlist files
                    self.wordlist_files.append(Path(crawl_wordlist))
                except Exception as e:
                    console.print(f"[bold {COLORS['error']}]Error saving crawled subdomains: {str(e)}[/bold {COLORS['error']}]")
        
        # Now load all wordlists
        total_files = len(self.wordlist_files)
        
        with Progress(
            TextColumn("[bold blue]{task.description}[/bold blue]"),
            BarColumn(),
            TextColumn("[bold green]{task.completed}/{task.total}[/bold green]"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[bold blue]Loading wordlists...", total=total_files)
            
            for wordlist_file in self.wordlist_files:
                try:
                    with open(wordlist_file, 'r') as f:
                        file_subdomains = set(line.strip().lower() for line in f if line.strip())
                        subdomains.update(file_subdomains)
                    progress.update(task, advance=1)
                except Exception as e:
                    console.print(f"[bold {COLORS['error']}]Error loading wordlist {wordlist_file}: {str(e)}[/bold {COLORS['error']}]")
        
        console.print(f"[bold {COLORS['success']}]Loaded {len(subdomains)} unique subdomains from {total_files} wordlist(s)[/bold {COLORS['success']}]")
        return list(subdomains)
        
    def crawl_website(self):
        """Crawl the website to discover potential subdomains in content."""
        console.print(f"[bold {COLORS['info']}]Starting website crawl to discover potential subdomains (depth {self.crawl_depth})...[/bold {COLORS['info']}]")
        
        base_domain = self.parse_url(self.target_url)
        ext = tldextract.extract(base_domain)
        root_domain = f"{ext.domain}.{ext.suffix}"
        
        # Ensure the URL has a scheme
        if not (self.target_url.startswith('http://') or self.target_url.startswith('https://')):
            start_url = 'https://' + self.target_url
        else:
            start_url = self.target_url
            
        queue = [(start_url, 0)]  # (url, depth)
        self.crawled_urls = set()
        self.potential_subdomains = set()
        
        with Progress(
            TextColumn("[bold blue]{task.description}[/bold blue]"),
            BarColumn(),
            TextColumn("[bold green]{task.completed}[/bold green]"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            crawl_task = progress.add_task("[bold blue]Crawling website...", total=None)
            extracted_task = progress.add_task("[bold blue]Extracted subdomains", total=None)
            
            while queue and len(self.crawled_urls) < self.max_crawl_urls:
                url, depth = queue.pop(0)
                
                if url in self.crawled_urls or depth > self.crawl_depth:
                    continue
                    
                self.crawled_urls.add(url)
                progress.update(crawl_task, completed=len(self.crawled_urls))
                
                try:
                    response = requests.get(
                        url, 
                        timeout=self.crawl_timeout,
                        headers={"User-Agent": self.user_agent},
                        verify=self.verify_ssl
                    )
                    
                    # Extract URLs from the page
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Extract from HTML
                    self._extract_subdomains_from_text(response.text, root_domain)
                    progress.update(extracted_task, completed=len(self.potential_subdomains))
                    
                    # Only continue crawling if we're not at max depth
                    if depth < self.crawl_depth:
                        # Find links in the current page
                        for a_tag in soup.find_all('a', href=True):
                            link = a_tag['href']
                            absolute_link = urljoin(url, link)
                            
                            # Only follow links to the same domain or subdomains
                            parsed_link = urlparse(absolute_link)
                            link_domain = parsed_link.netloc
                            
                            if root_domain in link_domain and absolute_link not in self.crawled_urls:
                                queue.append((absolute_link, depth + 1))
                except Exception as e:
                    if self.args.verbose > 1:
                        progress.console.print(f"[{COLORS['error']}]Error crawling {url}: {str(e)}[/{COLORS['error']}]")
                    continue
        
        console.print(f"[bold {COLORS['success']}]Crawled {len(self.crawled_urls)} URLs[/bold {COLORS['success']}]")
        console.print(f"[bold {COLORS['success']}]Discovered {len(self.potential_subdomains)} potential subdomains[/bold {COLORS['success']}]")
    
    def _extract_subdomains_from_text(self, text, root_domain):
        """Extract potential subdomains from text."""
        # Extract full domains that might contain our target domain
        for pattern in self.crawl_patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                # For full domain pattern
                if '.' in match:
                    # Check if this is a subdomain of our root domain
                    if root_domain in match and not match == root_domain:
                        ext = tldextract.extract(match)
                        if ext.domain == tldextract.extract(root_domain).domain and ext.suffix == tldextract.extract(root_domain).suffix:
                            # This is a subdomain, extract the subdomain part
                            if ext.subdomain:
                                self.potential_subdomains.add(ext.subdomain)
                # For subdomain pattern - needs additional validation
                else:
                    # Simple validation to filter out common non-subdomain strings
                    if (len(match) >= 3 and                  # At least 3 chars
                        not match.isdigit() and             # Not just a number
                        not re.match(r'^[0-9a-f]{4,}

    def check_subdomain(self, subdomain, target_domain):
        """Check if a subdomain exists and gather information about it."""
        full_domain = f"{subdomain}.{target_domain}"
        result = {
            "subdomain": full_domain,
            "exists": False,
            "ip": None,
            "status_code": None,
            "server": None,
            "cname": None,
            "takeover_vulnerable": False,
            "open_ports": [],
            "http_headers": {}
        }
        
        # First check DNS resolution
        try:
            answers = self.resolver.resolve(full_domain, 'A')
            result["exists"] = True
            result["ip"] = str(answers[0])
            
            # Check for CNAME records
            try:
                cname_answers = self.resolver.resolve(full_domain, 'CNAME')
                result["cname"] = str(cname_answers[0])
                
                # Basic subdomain takeover check
                if self.takeover_check and result["cname"]:
                    try:
                        socket.gethostbyname(result["cname"])
                    except socket.gaierror:
                        # CNAME points to a non-existent domain
                        result["takeover_vulnerable"] = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass  # No CNAME records
                
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return result
        except Exception as e:
            if self.args.verbose:
                console.print(f"[{COLORS['error']}]DNS error for {full_domain}: {str(e)}[/{COLORS['error']}]")
            return result
        
        # If DNS resolved, check HTTP/HTTPS
        if result["exists"]:
            url = f"https://{full_domain}"
            try:
                response = requests.get(
                    url, 
                    timeout=self.timeout, 
                    verify=self.verify_ssl,
                    headers={"User-Agent": self.user_agent},
                    allow_redirects=True
                )
                result["status_code"] = response.status_code
                self.status_codes.add(response.status_code)
                result["http_headers"] = dict(response.headers)
                result["server"] = response.headers.get("Server", "Unknown")
            except requests.exceptions.RequestException:
                # Try HTTP if HTTPS fails
                try:
                    url = f"http://{full_domain}"
                    response = requests.get(
                        url, 
                        timeout=self.timeout, 
                        headers={"User-Agent": self.user_agent},
                        allow_redirects=True
                    )
                    result["status_code"] = response.status_code
                    self.status_codes.add(response.status_code)
                    result["http_headers"] = dict(response.headers)
                    result["server"] = response.headers.get("Server", "Unknown")
                except requests.exceptions.RequestException:
                    # Both HTTPS and HTTP failed, but DNS resolved
                    pass
            
            # Scan ports if requested
            if self.scan_ports and result["ip"]:
                for port in self.scan_ports.split(','):
                    try:
                        port = int(port.strip())
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        if sock.connect_ex((result["ip"], port)) == 0:
                            result["open_ports"].append(port)
                        sock.close()
                    except:
                        pass
        
        return result

    def scan_subdomains(self):
        """Scan for subdomains using the loaded wordlist."""
        self.scan_start_time = datetime.now()
        target_domain = self.parse_url(self.target_url)
        
        if not self.validate_domain(target_domain):
            console.print(f"[bold {COLORS['error']}]Error: Domain {target_domain} does not resolve. Please check your input.[/bold {COLORS['error']}]")
            return False
        
        console.print(f"[bold {COLORS['info']}]Target: [/bold {COLORS['info']}][bold {COLORS['primary']}]{target_domain}[/bold {COLORS['primary']}]")
        
        # Get domain info
        try:
            domain_info = whois.whois(target_domain)
            console.print(f"[bold {COLORS['info']}]Domain Registrar: [/bold {COLORS['info']}]{domain_info.registrar}")
            console.print(f"[bold {COLORS['info']}]Registration Date: [/bold {COLORS['info']}]{domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date}")
            console.print(f"[bold {COLORS['info']}]Expiration Date: [/bold {COLORS['info']}]{domain_info.expiration_date[0] if isinstance(domain_info.expiration_date, list) else domain_info.expiration_date}")
        except:
            console.print(f"[{COLORS['warning']}]Could not retrieve WHOIS information[/{COLORS['warning']}]")
        
        console.print()
        
        # Try to get the primary IP
        try:
            ip = socket.gethostbyname(target_domain)
            console.print(f"[bold {COLORS['info']}]Target IP: [/bold {COLORS['info']}][bold {COLORS['primary']}]{ip}[/bold {COLORS['primary']}]")
            
            # Reverse DNS lookup
            try:
                host_name = socket.gethostbyaddr(ip)[0]
                console.print(f"[bold {COLORS['info']}]Reverse DNS: [/bold {COLORS['info']}][bold {COLORS['primary']}]{host_name}[/bold {COLORS['primary']}]")
            except:
                pass
        except:
            console.print(f"[{COLORS['warning']}]Could not resolve IP for {target_domain}[/{COLORS['warning']}]")
        
        console.print()
        
        # Load subdomains
        subdomains = self.load_subdomains()
        total_subdomains = len(subdomains)
        
        console.print(f"[bold {COLORS['info']}]Scanning {total_subdomains} potential subdomains with {self.threads} threads[/bold {COLORS['info']}]")
        console.print(f"[bold {COLORS['info']}]Timeout: {self.timeout} seconds | DNS Servers: {', '.join(self.dns_servers)}[/bold {COLORS['info']}]")
        console.print()
        
        results = []
        completed = 0
        
        with Progress(
            TextColumn("[bold blue]{task.description}[/bold blue]"),
            BarColumn(),
            TextColumn("[bold green]{task.completed}/{task.total}[/bold green]"),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[bold blue]Scanning subdomains...", total=total_subdomains)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_subdomain = {
                    executor.submit(self.check_subdomain, subdomain, target_domain): subdomain 
                    for subdomain in subdomains
                }
                
                for future in concurrent.futures.as_completed(future_to_subdomain):
                    subdomain = future_to_subdomain[future]
                    completed += 1
                    
                    try:
                        result = future.result()
                        if result["exists"]:
                            self.discovered_subdomains.add(result["subdomain"])
                            results.append(result)
                            
                            if result["status_code"]:
                                status_color = {
                                    2: COLORS["success"],  # 2xx
                                    3: COLORS["secondary"],  # 3xx
                                    4: COLORS["warning"],  # 4xx
                                    5: COLORS["error"]  # 5xx
                                }.get(result["status_code"] // 100, COLORS["info"])
                                
                                status_info = f"[{status_color}]{result['status_code']}[/{status_color}]"
                            else:
                                status_info = "[gray]No HTTP[/gray]"
                            
                            # Only print if verbose or the subdomain exists
                            if self.args.verbose:
                                progress.console.print(
                                    f"[{COLORS['success']}][FOUND][/{COLORS['success']}] "
                                    f"{result['subdomain']} - "
                                    f"IP: {result['ip'] or 'N/A'} - "
                                    f"Status: {status_info} - "
                                    f"Server: {result['server'] or 'Unknown'}"
                                )
                        elif self.args.verbose > 1:  # Very verbose
                            progress.console.print(f"[{COLORS['error']}][NOT FOUND][/{COLORS['error']}] {subdomain}.{target_domain}")
                    
                    except Exception as e:
                        if self.args.verbose > 1:
                            progress.console.print(f"[{COLORS['error']}]Error checking {subdomain}: {str(e)}[/{COLORS['error']}]")
                    
                    progress.update(task, completed=completed)
        
        self.valid_subdomains = results
        self.scan_end_time = datetime.now()
        return True

    def output_results(self):
        """Output the scan results to files."""
        if not self.output_dir:
            return
        
        target_domain = self.parse_url(self.target_url)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"{target_domain}_{timestamp}"
        
        # Save simple list of subdomains
        with open(os.path.join(self.output_dir, f"{base_filename}_subdomains.txt"), "w") as f:
            for subdomain in sorted(self.discovered_subdomains):
                f.write(f"{subdomain}\n")
        
        # Save detailed JSON results
        with open(os.path.join(self.output_dir, f"{base_filename}_detailed.json"), "w") as f:
            json.dump(self.valid_subdomains, f, indent=4)
        
        # Save CSV results
        with open(os.path.join(self.output_dir, f"{base_filename}_results.csv"), "w", newline="") as f:
            fieldnames = ["subdomain", "ip", "status_code", "server", "cname", "takeover_vulnerable", "open_ports"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for result in self.valid_subdomains:
                writer.writerow({
                    "subdomain": result["subdomain"],
                    "ip": result["ip"],
                    "status_code": result["status_code"],
                    "server": result["server"],
                    "cname": result["cname"],
                    "takeover_vulnerable": result["takeover_vulnerable"],
                    "open_ports": ",".join(map(str, result["open_ports"]))
                })
        
        console.print(f"[bold {COLORS['success']}]Results saved to:[/bold {COLORS['success']}]")
        console.print(f"  - [bold {COLORS['info']}]{os.path.join(self.output_dir, f'{base_filename}_subdomains.txt')}[/bold {COLORS['info']}]")
        console.print(f"  - [bold {COLORS['info']}]{os.path.join(self.output_dir, f'{base_filename}_detailed.json')}[/bold {COLORS['info']}]")
        console.print(f"  - [bold {COLORS['info']}]{os.path.join(self.output_dir, f'{base_filename}_results.csv')}[/bold {COLORS['info']}]")
        
        # Generate HTML report if requested
        if self.generate_report:
            self.generate_html_report(base_filename, target_domain)

    def generate_html_report(self, base_filename, target_domain):
        """Generate an HTML report with visualizations."""
        try:
            html_file = os.path.join(self.output_dir, f"{base_filename}_report.html")
            
            # Basic HTML report template
            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SubCracker - Scan Report for {target_domain}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background-color: #f7f9fc; color: #333; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ background-color: #1a5276; color: white; padding: 20px; text-align: center; }}
        .summary-box {{ background-color: white; border-radius: 5px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .card {{ background-color: white; border-radius: 5px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
        tr:hover {{ background-color: #f5f5f5; }}
        .status-200 {{ color: #27ae60; }}
        .status-300 {{ color: #2980b9; }}
        .status-400 {{ color: #f39c12; }}
        .status-500 {{ color: #e74c3c; }}
        .takeover {{ background-color: #ffecb3; }}
        .footer {{ text-align: center; margin-top: 30px; padding: 20px; color: #777; }}
        .chart-container {{ display: flex; justify-content: space-between; flex-wrap: wrap; }}
        .chart {{ width: 48%; margin-bottom: 20px; background-color: white; border-radius: 5px; padding: 15px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
    </style>
</head>
<body>
    <header>
        <h1>SubCracker - Scan Report</h1>
        <p>Comprehensive subdomain reconnaissance for {target_domain}</p>
    </header>
    
    <div class="container">
        <div class="summary-box">
            <h2>Scan Summary</h2>
            <p><strong>Target Domain:</strong> {target_domain}</p>
            <p><strong>Scan Date:</strong> {self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Scan Duration:</strong> {str(self.scan_end_time - self.scan_start_time).split('.')[0]}</p>
            <p><strong>Discovered Subdomains:</strong> {len(self.discovered_subdomains)}</p>
        </div>
        
        <div class="card">
            <h2>Subdomain Analysis</h2>
            <table>
                <thead>
                    <tr>
                        <th>Subdomain</th>
                        <th>IP Address</th>
                        <th>Status</th>
                        <th>Server</th>
                        <th>CNAME</th>
                        <th>Takeover Risk</th>
                    </tr>
                </thead>
                <tbody>
"""
            
            # Add table rows for subdomains
            for result in sorted(self.valid_subdomains, key=lambda x: x["subdomain"]):
                status_class = ""
                if result["status_code"]:
                    status_class = f"status-{result['status_code'] // 100}00"
                
                takeover_class = "takeover" if result["takeover_vulnerable"] else ""
                
                html_content += f"""
                    <tr class="{takeover_class}">
                        <td>{result["subdomain"]}</td>
                        <td>{result["ip"] or 'N/A'}</td>
                        <td class="{status_class}">{result["status_code"] or 'N/A'}</td>
                        <td>{result["server"] or 'Unknown'}</td>
                        <td>{result["cname"] or 'N/A'}</td>
                        <td>{'Yes' if result["takeover_vulnerable"] else 'No'}</td>
                    </tr>
"""
            
            # Close table and add visualization placeholders
            html_content += """
                </tbody>
            </table>
        </div>
        
        <div class="chart-container">
            <div class="chart">
                <h3>Status Code Distribution</h3>
                <canvas id="statusChart"></canvas>
            </div>
            <div class="chart">
                <h3>Subdomain Server Distribution</h3>
                <canvas id="serverChart"></canvas>
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by SubCracker v2.5 - Subdomain Reconnaissance Tool</p>
            <p>&copy; 2025 SubCracker - All rights reserved</p>
        </div>
    </div>
    
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.7.0/chart.min.js"></script>
    <script>
        // Status code distribution chart
        const statusCtx = document.getElementById('statusChart').getContext('2d');
        const statusChart = new Chart(statusCtx, {
            type: 'pie',
            data: {
                labels: ["""
            
            # Add status code data
            status_counts = {}
            for result in self.valid_subdomains:
                if result["status_code"]:
                    status_counts[result["status_code"]] = status_counts.get(result["status_code"], 0) + 1
            
            status_labels = ", ".join([f"'{code}'" for code in status_counts.keys()])
            status_data = ", ".join([str(count) for count in status_counts.values()])
            
            html_content += f"""
                    {status_labels}
                ],
                datasets: [{{
                    data: [{status_data}],
                    backgroundColor: [
                        '#27ae60', '#2980b9', '#8e44ad', '#f39c12', '#e74c3c', '#7f8c8d'
                    ]
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        position: 'right',
                    }}
                }}
            }}
        }});
        
        // Server distribution chart
        const serverCtx = document.getElementById('serverChart').getContext('2d');
        const serverChart = new Chart(serverCtx, {{
            type: 'bar',
            data: {{
                labels: ["""
            
            # Add server data
            server_counts = {}
            for result in self.valid_subdomains:
                if result["server"] and result["server"] != "Unknown":
                    server_counts[result["server"]] = server_counts.get(result["server"], 0) + 1
            
            server_labels = ", ".join([f"'{server}'" for server in server_counts.keys()])
            server_data = ", ".join([str(count) for count in server_counts.values()])
            
            html_content += f"""
                    {server_labels}
                ],
                datasets: [{{
                    label: 'Server Types',
                    data: [{server_data}],
                    backgroundColor: '#3498db'
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        display: false
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>
"""
            
            with open(html_file, "w") as f:
                f.write(html_content)
            
            console.print(f"  - [bold {COLORS['info']}]{html_file}[/bold {COLORS['info']}]")
            
        except Exception as e:
            console.print(f"[{COLORS['error']}]Error generating HTML report: {str(e)}[/{COLORS['error']}]")

    def print_summary(self):
        """Print a summary of the scan results."""
        if not self.valid_subdomains:
            console.print(f"[bold {COLORS['error']}]No subdomains discovered.[/bold {COLORS['error']}]")
            return
        
        console.print()
        console.print(f"[bold {COLORS['primary']}]════════════════════ SCAN RESULTS SUMMARY ════════════════════[/bold {COLORS['primary']}]")
        console.print()
        
        # Summary statistics
        console.print(f"[bold {COLORS['info']}]Target Domain:[/bold {COLORS['info']}] [bold {COLORS['primary']}]{self.parse_url(self.target_url)}[/bold {COLORS['primary']}]")
        console.print(f"[bold {COLORS['info']}]Scan Duration:[/bold {COLORS['info']}] [bold {COLORS['primary']}]{str(self.scan_end_time - self.scan_start_time).split('.')[0]}[/bold {COLORS['primary']}]")
        console.print(f"[bold {COLORS['info']}]Total Discovered Subdomains:[/bold {COLORS['info']}] [bold {COLORS['primary']}]{len(self.discovered_subdomains)}[/bold {COLORS['primary']}]")
        
        # Count by status code
        status_counts = {}
        for result in self.valid_subdomains:
            if result["status_code"]:
                status_counts[result["status_code"]] = status_counts.get(result["status_code"], 0) + 1
        
        if status_counts:
            console.print()
            console.print(f"[bold {COLORS['info']}]Status Code Distribution:[/bold {COLORS['info']}]")
            for status, count in sorted(status_counts.items()):
                status_color = {
                    2: COLORS["success"],  # 2xx
                    3: COLORS["secondary"],  # 3xx
                    4: COLORS["warning"],  # 4xx
                    5: COLORS["error"]  # 5xx
                }.get(status // 100, COLORS["info"])
                console.print(f"  [{status_color}]{status}[/{status_color}]: {count}")
        
        # Count by server
        server_counts = {}
        for result in self.valid_subdomains:
            if result["server"]:
                server = result["server"]
                server_counts[server] = server_counts.get(server, 0) + 1
        
        if server_counts:
            console.print()
            console.print(f"[bold {COLORS['info']}]Server Distribution:[/bold {COLORS['info']}]")
            for server, count in sorted(server_counts.items(), key=lambda x: x[1], reverse=True)[:10]:  # Top 10
                console.print(f"  {server}: {count}")
        
        # Potential subdomain takeover vulnerabilities
        takeover_vulnerable = [r for r in self.valid_subdomains if r["takeover_vulnerable"]]
        if takeover_vulnerable:
            console.print()
            console.print(f"[bold {COLORS['warning']}]Potential Subdomain Takeover Vulnerabilities ({len(takeover_vulnerable)}):[/bold {COLORS['warning']}]")
            for result in takeover_vulnerable:
                console.print(f"  [bold {COLORS['error']}]{result['subdomain']}[/bold {COLORS['error']}] -> CNAME: {result['cname']}")
        
        # Display table of results
        console.print()
        table = Table(
            title=f"[bold {COLORS['primary']}]Discovered Subdomains[/bold {COLORS['primary']}]",
            box=None
        )
        
        table.add_column("Subdomain", style=f"bold {COLORS['primary']}")
        table.add_column("IP Address", style=COLORS["info"])
        table.add_column("Status", style=COLORS["success"])
        table.add_column("Server", style=COLORS["secondary"])
        table.add_column("CNAME", style=COLORS["info"])
        
        # Sort by subdomain
        for result in sorted(self.valid_subdomains, key=lambda x: x["subdomain"])[:50]:  # Show top 50
            status_str = str(result["status_code"]) if result["status_code"] else "No HTTP"
            status_style = {
                2: f"bold {COLORS['success']}",  # 2xx
                3: f"bold {COLORS['secondary']}",  # 3xx
                4: f"bold {COLORS['warning']}",  # 4xx
                5: f"bold {COLORS['error']}"  # 5xx
            }.get(result["status_code"] // 100 if result["status_code"] else 0, COLORS["info"])
            
            table.add_row(
                result["subdomain"],
                result["ip"] or "N/A",
                f"[{status_style}]{status_str}[/{status_style}]",
                result["server"] or "Unknown",
                result["cname"] or "N/A"
            )
        
        console.print(table)
        
        if len(self.valid_subdomains) > 50:
            console.print(f"[{COLORS['info']}]Showing 50 of {len(self.valid_subdomains)} discovered subdomains.[/{COLORS['info']}]")
        
        console.print()
        console.print(f"[bold {COLORS['primary']}]═════════════════════════ END OF REPORT ═════════════════════════[/bold {COLORS['primary']}]")
        console.print()

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="SubCracker - Subdomain Reconnaissance Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        "-u", "--url", 
        required=True,
        help="Target URL or domain to scan for subdomains"
    )
    parser.add_argument(
        "-w", "--wordlist", 
        nargs="+", 
        help="One or more wordlist files containing subdomains to check"
    )
    parser.add_argument(
        "-t", "--threads", 
        type=int, 
        default=50,
        help="Number of concurrent threads for scanning"
    )
    parser.add_argument(
        "-o", "--output-dir", 
        default="output",
        help="Directory to save output files"
    )
    parser.add_argument(
        "--timeout", 
        type=float, 
        default=3.0,
        help="Timeout in seconds for HTTP/DNS requests"
    )
    parser.add_argument(
        "--dns-servers", 
        nargs="+",
        help="Custom DNS servers to use for resolution"
    )
    parser.add_argument(
        "--user-agent", 
        help="Custom User-Agent string for HTTP requests"
    )
    parser.add_argument(
        "--ignore-ssl-errors", 
        action="store_true",
        help="Ignore SSL certificate errors"
    )
    parser.add_argument(
        "--report", 
        action="store_true",
        help="Generate an HTML report with visualizations"
    )
    parser.add_argument(
        "--ports", 
        default="80,443,8080,8443",
        help="Comma-separated list of ports to scan on discovered subdomains"
    )
    parser.add_argument(
        "--check-takeover", 
        action="store_true",
        help="Check for potential subdomain takeover vulnerabilities"
    )
    # Website crawling arguments
    parser.add_argument(
        "--crawl", 
        action="store_true",
        help="Crawl the website to discover potential subdomains in content"
    )
    parser.add_argument(
        "--crawl-depth", 
        type=int, 
        default=2,
        help="Maximum depth to crawl from the starting page"
    )
    parser.add_argument(
        "--crawl-timeout", 
        type=float, 
        default=5.0,
        help="Timeout in seconds for crawling requests"
    )
    parser.add_argument(
        "--max-crawl-urls", 
        type=int, 
        default=500,
        help="Maximum number of URLs to crawl"
    )
    parser.add_argument(
        "-v", "--verbose", 
        action="count", 
        default=0,
        help="Verbosity level (use -v for verbose, -vv for very verbose)"
    )
    
    return parser.parse_args()

def main():
    """Main entry point for the application."""
    try:
        args = parse_arguments()
        scanner = SubDomainHunter(args)
        scanner.print_banner()
        
        if scanner.scan_subdomains():
            scanner.print_summary()
            scanner.output_results()
    
    except KeyboardInterrupt:
        console.print(f"\n[bold {COLORS['error']}]Program interrupted by user.[/bold {COLORS['error']}]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold {COLORS['error']}]An error occurred: {str(e)}[/bold {COLORS['error']}]")
        if args.verbose > 1:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main(), match) and  # Not a hex number/hash
                        not match.lower() in ['www', 'api', 'mail', 'smtp', 'pop', 'imap', 'ftp']):  # Not a common service
                        self.potential_subdomains.add(match)

    def check_subdomain(self, subdomain, target_domain):
        """Check if a subdomain exists and gather information about it."""
        full_domain = f"{subdomain}.{target_domain}"
        result = {
            "subdomain": full_domain,
            "exists": False,
            "ip": None,
            "status_code": None,
            "server": None,
            "cname": None,
            "takeover_vulnerable": False,
            "open_ports": [],
            "http_headers": {}
        }
        
        # First check DNS resolution
        try:
            answers = self.resolver.resolve(full_domain, 'A')
            result["exists"] = True
            result["ip"] = str(answers[0])
            
            # Check for CNAME records
            try:
                cname_answers = self.resolver.resolve(full_domain, 'CNAME')
                result["cname"] = str(cname_answers[0])
                
                # Basic subdomain takeover check
                if self.takeover_check and result["cname"]:
                    try:
                        socket.gethostbyname(result["cname"])
                    except socket.gaierror:
                        # CNAME points to a non-existent domain
                        result["takeover_vulnerable"] = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass  # No CNAME records
                
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return result
        except Exception as e:
            if self.args.verbose:
                console.print(f"[{COLORS['error']}]DNS error for {full_domain}: {str(e)}[/{COLORS['error']}]")
            return result
        
        # If DNS resolved, check HTTP/HTTPS
        if result["exists"]:
            url = f"https://{full_domain}"
            try:
                response = requests.get(
                    url, 
                    timeout=self.timeout, 
                    verify=self.verify_ssl,
                    headers={"User-Agent": self.user_agent},
                    allow_redirects=True
                )
                result["status_code"] = response.status_code
                self.status_codes.add(response.status_code)
                result["http_headers"] = dict(response.headers)
                result["server"] = response.headers.get("Server", "Unknown")
            except requests.exceptions.RequestException:
                # Try HTTP if HTTPS fails
                try:
                    url = f"http://{full_domain}"
                    response = requests.get(
                        url, 
                        timeout=self.timeout, 
                        headers={"User-Agent": self.user_agent},
                        allow_redirects=True
                    )
                    result["status_code"] = response.status_code
                    self.status_codes.add(response.status_code)
                    result["http_headers"] = dict(response.headers)
                    result["server"] = response.headers.get("Server", "Unknown")
                except requests.exceptions.RequestException:
                    # Both HTTPS and HTTP failed, but DNS resolved
                    pass
            
            # Scan ports if requested
            if self.scan_ports and result["ip"]:
                for port in self.scan_ports.split(','):
                    try:
                        port = int(port.strip())
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        if sock.connect_ex((result["ip"], port)) == 0:
                            result["open_ports"].append(port)
                        sock.close()
                    except:
                        pass
        
        return result

    def scan_subdomains(self):
        """Scan for subdomains using the loaded wordlist."""
        self.scan_start_time = datetime.now()
        target_domain = self.parse_url(self.target_url)
        
        if not self.validate_domain(target_domain):
            console.print(f"[bold {COLORS['error']}]Error: Domain {target_domain} does not resolve. Please check your input.[/bold {COLORS['error']}]")
            return False
        
        console.print(f"[bold {COLORS['info']}]Target: [/bold {COLORS['info']}][bold {COLORS['primary']}]{target_domain}[/bold {COLORS['primary']}]")
        
        # Get domain info
        try:
            domain_info = whois.whois(target_domain)
            console.print(f"[bold {COLORS['info']}]Domain Registrar: [/bold {COLORS['info']}]{domain_info.registrar}")
            console.print(f"[bold {COLORS['info']}]Registration Date: [/bold {COLORS['info']}]{domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date}")
            console.print(f"[bold {COLORS['info']}]Expiration Date: [/bold {COLORS['info']}]{domain_info.expiration_date[0] if isinstance(domain_info.expiration_date, list) else domain_info.expiration_date}")
        except:
            console.print(f"[{COLORS['warning']}]Could not retrieve WHOIS information[/{COLORS['warning']}]")
        
        console.print()
        
        # Try to get the primary IP
        try:
            ip = socket.gethostbyname(target_domain)
            console.print(f"[bold {COLORS['info']}]Target IP: [/bold {COLORS['info']}][bold {COLORS['primary']}]{ip}[/bold {COLORS['primary']}]")
            
            # Reverse DNS lookup
            try:
                host_name = socket.gethostbyaddr(ip)[0]
                console.print(f"[bold {COLORS['info']}]Reverse DNS: [/bold {COLORS['info']}][bold {COLORS['primary']}]{host_name}[/bold {COLORS['primary']}]")
            except:
                pass
        except:
            console.print(f"[{COLORS['warning']}]Could not resolve IP for {target_domain}[/{COLORS['warning']}]")
        
        console.print()
        
        # Load subdomains
        subdomains = self.load_subdomains()
        total_subdomains = len(subdomains)
        
        console.print(f"[bold {COLORS['info']}]Scanning {total_subdomains} potential subdomains with {self.threads} threads[/bold {COLORS['info']}]")
        console.print(f"[bold {COLORS['info']}]Timeout: {self.timeout} seconds | DNS Servers: {', '.join(self.dns_servers)}[/bold {COLORS['info']}]")
        console.print()
        
        results = []
        completed = 0
        
        with Progress(
            TextColumn("[bold blue]{task.description}[/bold blue]"),
            BarColumn(),
            TextColumn("[bold green]{task.completed}/{task.total}[/bold green]"),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[bold blue]Scanning subdomains...", total=total_subdomains)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_subdomain = {
                    executor.submit(self.check_subdomain, subdomain, target_domain): subdomain 
                    for subdomain in subdomains
                }
                
                for future in concurrent.futures.as_completed(future_to_subdomain):
                    subdomain = future_to_subdomain[future]
                    completed += 1
                    
                    try:
                        result = future.result()
                        if result["exists"]:
                            self.discovered_subdomains.add(result["subdomain"])
                            results.append(result)
                            
                            if result["status_code"]:
                                status_color = {
                                    2: COLORS["success"],  # 2xx
                                    3: COLORS["secondary"],  # 3xx
                                    4: COLORS["warning"],  # 4xx
                                    5: COLORS["error"]  # 5xx
                                }.get(result["status_code"] // 100, COLORS["info"])
                                
                                status_info = f"[{status_color}]{result['status_code']}[/{status_color}]"
                            else:
                                status_info = "[gray]No HTTP[/gray]"
                            
                            # Only print if verbose or the subdomain exists
                            if self.args.verbose:
                                progress.console.print(
                                    f"[{COLORS['success']}][FOUND][/{COLORS['success']}] "
                                    f"{result['subdomain']} - "
                                    f"IP: {result['ip'] or 'N/A'} - "
                                    f"Status: {status_info} - "
                                    f"Server: {result['server'] or 'Unknown'}"
                                )
                        elif self.args.verbose > 1:  # Very verbose
                            progress.console.print(f"[{COLORS['error']}][NOT FOUND][/{COLORS['error']}] {subdomain}.{target_domain}")
                    
                    except Exception as e:
                        if self.args.verbose > 1:
                            progress.console.print(f"[{COLORS['error']}]Error checking {subdomain}: {str(e)}[/{COLORS['error']}]")
                    
                    progress.update(task, completed=completed)
        
        self.valid_subdomains = results
        self.scan_end_time = datetime.now()
        return True

    def output_results(self):
        """Output the scan results to files."""
        if not self.output_dir:
            return
        
        target_domain = self.parse_url(self.target_url)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"{target_domain}_{timestamp}"
        
        # Save simple list of subdomains
        with open(os.path.join(self.output_dir, f"{base_filename}_subdomains.txt"), "w") as f:
            for subdomain in sorted(self.discovered_subdomains):
                f.write(f"{subdomain}\n")
        
        # Save detailed JSON results
        with open(os.path.join(self.output_dir, f"{base_filename}_detailed.json"), "w") as f:
            json.dump(self.valid_subdomains, f, indent=4)
        
        # Save CSV results
        with open(os.path.join(self.output_dir, f"{base_filename}_results.csv"), "w", newline="") as f:
            fieldnames = ["subdomain", "ip", "status_code", "server", "cname", "takeover_vulnerable", "open_ports"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for result in self.valid_subdomains:
                writer.writerow({
                    "subdomain": result["subdomain"],
                    "ip": result["ip"],
                    "status_code": result["status_code"],
                    "server": result["server"],
                    "cname": result["cname"],
                    "takeover_vulnerable": result["takeover_vulnerable"],
                    "open_ports": ",".join(map(str, result["open_ports"]))
                })
        
        console.print(f"[bold {COLORS['success']}]Results saved to:[/bold {COLORS['success']}]")
        console.print(f"  - [bold {COLORS['info']}]{os.path.join(self.output_dir, f'{base_filename}_subdomains.txt')}[/bold {COLORS['info']}]")
        console.print(f"  - [bold {COLORS['info']}]{os.path.join(self.output_dir, f'{base_filename}_detailed.json')}[/bold {COLORS['info']}]")
        console.print(f"  - [bold {COLORS['info']}]{os.path.join(self.output_dir, f'{base_filename}_results.csv')}[/bold {COLORS['info']}]")
        
        # Generate HTML report if requested
        if self.generate_report:
            self.generate_html_report(base_filename, target_domain)

    def generate_html_report(self, base_filename, target_domain):
        """Generate an HTML report with visualizations."""
        try:
            html_file = os.path.join(self.output_dir, f"{base_filename}_report.html")
            
            # Basic HTML report template
            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SubCracker - Scan Report for {target_domain}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background-color: #f7f9fc; color: #333; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ background-color: #1a5276; color: white; padding: 20px; text-align: center; }}
        .summary-box {{ background-color: white; border-radius: 5px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .card {{ background-color: white; border-radius: 5px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
        tr:hover {{ background-color: #f5f5f5; }}
        .status-200 {{ color: #27ae60; }}
        .status-300 {{ color: #2980b9; }}
        .status-400 {{ color: #f39c12; }}
        .status-500 {{ color: #e74c3c; }}
        .takeover {{ background-color: #ffecb3; }}
        .footer {{ text-align: center; margin-top: 30px; padding: 20px; color: #777; }}
        .chart-container {{ display: flex; justify-content: space-between; flex-wrap: wrap; }}
        .chart {{ width: 48%; margin-bottom: 20px; background-color: white; border-radius: 5px; padding: 15px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
    </style>
</head>
<body>
    <header>
        <h1>SubCracker - Scan Report</h1>
        <p>Comprehensive subdomain reconnaissance for {target_domain}</p>
    </header>
    
    <div class="container">
        <div class="summary-box">
            <h2>Scan Summary</h2>
            <p><strong>Target Domain:</strong> {target_domain}</p>
            <p><strong>Scan Date:</strong> {self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Scan Duration:</strong> {str(self.scan_end_time - self.scan_start_time).split('.')[0]}</p>
            <p><strong>Discovered Subdomains:</strong> {len(self.discovered_subdomains)}</p>
        </div>
        
        <div class="card">
            <h2>Subdomain Analysis</h2>
            <table>
                <thead>
                    <tr>
                        <th>Subdomain</th>
                        <th>IP Address</th>
                        <th>Status</th>
                        <th>Server</th>
                        <th>CNAME</th>
                        <th>Takeover Risk</th>
                    </tr>
                </thead>
                <tbody>
"""
            
            # Add table rows for subdomains
            for result in sorted(self.valid_subdomains, key=lambda x: x["subdomain"]):
                status_class = ""
                if result["status_code"]:
                    status_class = f"status-{result['status_code'] // 100}00"
                
                takeover_class = "takeover" if result["takeover_vulnerable"] else ""
                
                html_content += f"""
                    <tr class="{takeover_class}">
                        <td>{result["subdomain"]}</td>
                        <td>{result["ip"] or 'N/A'}</td>
                        <td class="{status_class}">{result["status_code"] or 'N/A'}</td>
                        <td>{result["server"] or 'Unknown'}</td>
                        <td>{result["cname"] or 'N/A'}</td>
                        <td>{'Yes' if result["takeover_vulnerable"] else 'No'}</td>
                    </tr>
"""
            
            # Close table and add visualization placeholders
            html_content += """
                </tbody>
            </table>
        </div>
        
        <div class="chart-container">
            <div class="chart">
                <h3>Status Code Distribution</h3>
                <canvas id="statusChart"></canvas>
            </div>
            <div class="chart">
                <h3>Subdomain Server Distribution</h3>
                <canvas id="serverChart"></canvas>
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by SubCracker v2.5 - Subdomain Reconnaissance Tool</p>
            <p>&copy; 2025 SubCracker - All rights reserved</p>
        </div>
    </div>
    
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.7.0/chart.min.js"></script>
    <script>
        // Status code distribution chart
        const statusCtx = document.getElementById('statusChart').getContext('2d');
        const statusChart = new Chart(statusCtx, {
            type: 'pie',
            data: {
                labels: ["""
            
            # Add status code data
            status_counts = {}
            for result in self.valid_subdomains:
                if result["status_code"]:
                    status_counts[result["status_code"]] = status_counts.get(result["status_code"], 0) + 1
            
            status_labels = ", ".join([f"'{code}'" for code in status_counts.keys()])
            status_data = ", ".join([str(count) for count in status_counts.values()])
            
            html_content += f"""
                    {status_labels}
                ],
                datasets: [{{
                    data: [{status_data}],
                    backgroundColor: [
                        '#27ae60', '#2980b9', '#8e44ad', '#f39c12', '#e74c3c', '#7f8c8d'
                    ]
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        position: 'right',
                    }}
                }}
            }}
        }});
        
        // Server distribution chart
        const serverCtx = document.getElementById('serverChart').getContext('2d');
        const serverChart = new Chart(serverCtx, {{
            type: 'bar',
            data: {{
                labels: ["""
            
            # Add server data
            server_counts = {}
            for result in self.valid_subdomains:
                if result["server"] and result["server"] != "Unknown":
                    server_counts[result["server"]] = server_counts.get(result["server"], 0) + 1
            
            server_labels = ", ".join([f"'{server}'" for server in server_counts.keys()])
            server_data = ", ".join([str(count) for count in server_counts.values()])
            
            html_content += f"""
                    {server_labels}
                ],
                datasets: [{{
                    label: 'Server Types',
                    data: [{server_data}],
                    backgroundColor: '#3498db'
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        display: false
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>
"""
            
            with open(html_file, "w") as f:
                f.write(html_content)
            
            console.print(f"  - [bold {COLORS['info']}]{html_file}[/bold {COLORS['info']}]")
            
        except Exception as e:
            console.print(f"[{COLORS['error']}]Error generating HTML report: {str(e)}[/{COLORS['error']}]")

    def print_summary(self):
        """Print a summary of the scan results."""
        if not self.valid_subdomains:
            console.print(f"[bold {COLORS['error']}]No subdomains discovered.[/bold {COLORS['error']}]")
            return
        
        console.print()
        console.print(f"[bold {COLORS['primary']}]════════════════════ SCAN RESULTS SUMMARY ════════════════════[/bold {COLORS['primary']}]")
        console.print()
        
        # Summary statistics
        console.print(f"[bold {COLORS['info']}]Target Domain:[/bold {COLORS['info']}] [bold {COLORS['primary']}]{self.parse_url(self.target_url)}[/bold {COLORS['primary']}]")
        console.print(f"[bold {COLORS['info']}]Scan Duration:[/bold {COLORS['info']}] [bold {COLORS['primary']}]{str(self.scan_end_time - self.scan_start_time).split('.')[0]}[/bold {COLORS['primary']}]")
        console.print(f"[bold {COLORS['info']}]Total Discovered Subdomains:[/bold {COLORS['info']}] [bold {COLORS['primary']}]{len(self.discovered_subdomains)}[/bold {COLORS['primary']}]")
        
        # Count by status code
        status_counts = {}
        for result in self.valid_subdomains:
            if result["status_code"]:
                status_counts[result["status_code"]] = status_counts.get(result["status_code"], 0) + 1
        
        if status_counts:
            console.print()
            console.print(f"[bold {COLORS['info']}]Status Code Distribution:[/bold {COLORS['info']}]")
            for status, count in sorted(status_counts.items()):
                status_color = {
                    2: COLORS["success"],  # 2xx
                    3: COLORS["secondary"],  # 3xx
                    4: COLORS["warning"],  # 4xx
                    5: COLORS["error"]  # 5xx
                }.get(status // 100, COLORS["info"])
                console.print(f"  [{status_color}]{status}[/{status_color}]: {count}")
        
        # Count by server
        server_counts = {}
        for result in self.valid_subdomains:
            if result["server"]:
                server = result["server"]
                server_counts[server] = server_counts.get(server, 0) + 1
        
        if server_counts:
            console.print()
            console.print(f"[bold {COLORS['info']}]Server Distribution:[/bold {COLORS['info']}]")
            for server, count in sorted(server_counts.items(), key=lambda x: x[1], reverse=True)[:10]:  # Top 10
                console.print(f"  {server}: {count}")
        
        # Potential subdomain takeover vulnerabilities
        takeover_vulnerable = [r for r in self.valid_subdomains if r["takeover_vulnerable"]]
        if takeover_vulnerable:
            console.print()
            console.print(f"[bold {COLORS['warning']}]Potential Subdomain Takeover Vulnerabilities ({len(takeover_vulnerable)}):[/bold {COLORS['warning']}]")
            for result in takeover_vulnerable:
                console.print(f"  [bold {COLORS['error']}]{result['subdomain']}[/bold {COLORS['error']}] -> CNAME: {result['cname']}")
        
        # Display table of results
        console.print()
        table = Table(
            title=f"[bold {COLORS['primary']}]Discovered Subdomains[/bold {COLORS['primary']}]",
            box=None
        )
        
        table.add_column("Subdomain", style=f"bold {COLORS['primary']}")
        table.add_column("IP Address", style=COLORS["info"])
        table.add_column("Status", style=COLORS["success"])
        table.add_column("Server", style=COLORS["secondary"])
        table.add_column("CNAME", style=COLORS["info"])
        
        # Sort by subdomain
        for result in sorted(self.valid_subdomains, key=lambda x: x["subdomain"])[:50]:  # Show top 50
            status_str = str(result["status_code"]) if result["status_code"] else "No HTTP"
            status_style = {
                2: f"bold {COLORS['success']}",  # 2xx
                3: f"bold {COLORS['secondary']}",  # 3xx
                4: f"bold {COLORS['warning']}",  # 4xx
                5: f"bold {COLORS['error']}"  # 5xx
            }.get(result["status_code"] // 100 if result["status_code"] else 0, COLORS["info"])
            
            table.add_row(
                result["subdomain"],
                result["ip"] or "N/A",
                f"[{status_style}]{status_str}[/{status_style}]",
                result["server"] or "Unknown",
                result["cname"] or "N/A"
            )
        
        console.print(table)
        
        if len(self.valid_subdomains) > 50:
            console.print(f"[{COLORS['info']}]Showing 50 of {len(self.valid_subdomains)} discovered subdomains.[/{COLORS['info']}]")
        
        console.print()
        console.print(f"[bold {COLORS['primary']}]═════════════════════════ END OF REPORT ═════════════════════════[/bold {COLORS['primary']}]")
        console.print()

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="SubCracker - Subdomain Reconnaissance Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        "-u", "--url", 
        required=True,
        help="Target URL or domain to scan for subdomains"
    )
    parser.add_argument(
        "-w", "--wordlist", 
        nargs="+", 
        help="One or more wordlist files containing subdomains to check"
    )
    parser.add_argument(
        "-t", "--threads", 
        type=int, 
        default=50,
        help="Number of concurrent threads for scanning"
    )
    parser.add_argument(
        "-o", "--output-dir", 
        default="output",
        help="Directory to save output files"
    )
    parser.add_argument(
        "--timeout", 
        type=float, 
        default=3.0,
        help="Timeout in seconds for HTTP/DNS requests"
    )
    parser.add_argument(
        "--dns-servers", 
        nargs="+",
        help="Custom DNS servers to use for resolution"
    )
    parser.add_argument(
        "--user-agent", 
        help="Custom User-Agent string for HTTP requests"
    )
    parser.add_argument(
        "--ignore-ssl-errors", 
        action="store_true",
        help="Ignore SSL certificate errors"
    )
    parser.add_argument(
        "--report", 
        action="store_true",
        help="Generate an HTML report with visualizations"
    )
    parser.add_argument(
        "--ports", 
        default="80,443,8080,8443",
        help="Comma-separated list of ports to scan on discovered subdomains"
    )
    parser.add_argument(
        "--check-takeover", 
        action="store_true",
        help="Check for potential subdomain takeover vulnerabilities"
    )
    parser.add_argument(
        "-v", "--verbose", 
        action="count", 
        default=0,
        help="Verbosity level (use -v for verbose, -vv for very verbose)"
    )
    
    return parser.parse_args()

def main():
    """Main entry point for the application."""
    try:
        args = parse_arguments()
        scanner = SubDomainHunter(args)
        scanner.print_banner()
        
        if scanner.scan_subdomains():
            scanner.print_summary()
            scanner.output_results()
    
    except KeyboardInterrupt:
        console.print(f"\n[bold {COLORS['error']}]Program interrupted by user.[/bold {COLORS['error']}]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold {COLORS['error']}]An error occurred: {str(e)}[/bold {COLORS['error']}]")
        if args.verbose > 1:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()
