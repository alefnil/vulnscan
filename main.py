# Website Scanner Tools - by Jordan
# Github: @j0rrdnn

# Importing necessary libraries
import requests
import re
import urllib.parse
import argparse
import json
import logging
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich.text import Text
import warnings
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

# Define payload manager
class PayloadManager:
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "'-alert(1)-'",
        "<ScRiPt>alert('XSS')</ScRiPt>"
    ]
    
    SQL_PAYLOADS = [
        "'", "' OR '1'='1", "'; DROP TABLE users; --",
        "1' ORDER BY 1--+", "1' UNION SELECT NULL--+",
        "1' WAITFOR DELAY '0:0:5'--", "1' AND 1=CONVERT(int,@@version)--",
        "')) OR '1'='1'--"
    ]
    
    TRAVERSAL_PAYLOADS = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//etc/passwd",
        "..%252f..%252f..%252fetc%252fpasswd"
    ]
    
    SSRF_PAYLOADS = [
        "http://localhost",
        "http://127.0.0.1",
        "http://[::1]",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd"
    ]

# Create a main class to scan vulnerabilities
class VulnerabilityScanner:
    def __init__(self, target_url, max_threads=10, depth=2, output_file=None):
        self.target_url = target_url
        self.target_domain = urllib.parse.urlparse(target_url).netloc
        self.visited_urls = set()
        self.vulnerabilities = []
        self.max_threads = max_threads
        self.depth = depth
        self.output_file = output_file or f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=max_threads * 2,
            pool_maxsize=max_threads * 2,
            max_retries=3,
            pool_block=False
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        self.session.verify = False
        self.setup_logging()

    def setup_logging(self):
        logging.basicConfig(
            filename='scanner.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def scan(self):
        console.print(Panel.fit(
            "[bold cyan]Web Vulnerability Scanner[/bold cyan]\n"
            f"[yellow]Target:[/yellow] {self.target_url}\n"
            f"[yellow]Depth:[/yellow] {self.depth}\n"
            f"[yellow]Threads:[/yellow] {self.max_threads}",
            title="Scan Configuration"
        ))

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        ) as progress:
            scan_task = progress.add_task("[cyan]Scanning...", total=100)
            self._crawl(self.target_url, self.depth, progress, scan_task)
            progress.update(scan_task, completed=100)

        self.save_results()
        return self.vulnerabilities

    def _crawl(self, url, depth, progress, task_id):
        if depth <= 0 or url in self.visited_urls:
            return

        self.visited_urls.add(url)
        progress.update(task_id, description=f"[cyan]Scanning: {url[:50]}...")

        try:
            response = self.session.get(url, timeout=10)
            content_type = response.headers.get('Content-Type', '')

            if 'text/html' in content_type:
                soup = BeautifulSoup(response.text, 'html.parser')
                self._process_page(url, response, soup, depth, progress, task_id)

        except Exception as e:
            logging.error(f"Error crawling {url}: {str(e)}")
            console.print(f"[bold red]Error scanning {url}: {str(e)}[/bold red]")

    def _process_page(self, url, response, soup, depth, progress, task_id):
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for link in soup.find_all('a', href=True):
                next_url = urljoin(url, link['href'])
                if self.target_domain in next_url and next_url not in self.visited_urls:
                    futures.append(
                        executor.submit(self._crawl, next_url, depth - 1, progress, task_id)
                    )

            self._check_vulnerabilities(url, response, soup)

    def _check_vulnerabilities(self, url, response, soup):
        with console.status(f"[bold blue]Testing {url}...", spinner="dots"):
            self._check_xss(url, response.text, soup)
            self._check_sql_injection(url)
            self._check_open_redirect(url)
            self._check_header_security(url, response.headers)
            self._check_ssrf(url)
            self._check_directory_traversal(url)

    def _check_header_security(self, url, headers):
        security_headers = {
            'Strict-Transport-Security': {
                'message': 'Missing HSTS header',
                'severity': 'Medium'
            },
            'X-Content-Type-Options': {
                'message': 'Missing X-Content-Type-Options header',
                'severity': 'Low'
            },
            'X-Frame-Options': {
                'message': 'Missing X-Frame-Options header',
                'severity': 'Medium'
            },
            'Content-Security-Policy': {
                'message': 'Missing Content-Security-Policy header',
                'severity': 'High'
            },
            'X-XSS-Protection': {
                'message': 'Missing X-XSS-Protection header',
                'severity': 'Low'
            },
            'Referrer-Policy': {
                'message': 'Missing Referrer-Policy header',
                'severity': 'Low'
            }
        }
        
        for header, info in security_headers.items():
            if header not in headers:
                self._add_vulnerability(
                    "Missing Security Header",
                    url,
                    info['message'],
                    info['severity']
                )

    def _check_xss(self, url, html_content, soup):
        input_fields = soup.find_all(['input', 'textarea'])
        forms = soup.find_all('form')
        
        for field in input_fields:
            field_name = field.get('name')
            if field_name:
                for payload in PayloadManager.XSS_PAYLOADS:
                    self._test_xss_payload(url, field_name, payload)

        for form in forms:
            self._test_form_xss(url, form)

    def _test_xss_payload(self, url, field_name, payload):
        test_url = f"{url}?{field_name}={urllib.parse.quote(payload)}"
        try:
            response = self.session.get(test_url, timeout=5)
            if payload in response.text:
                self._add_vulnerability("XSS", test_url, 
                    f"Parameter '{field_name}' reflects input without sanitization",
                    "High")
        except Exception as e:
            logging.error(f"XSS test error on {test_url}: {str(e)}")

    def _test_form_xss(self, url, form):
        try:
            action = urljoin(url, form.get('action', ''))
            method = form.get('method', 'get').lower()
            inputs = form.find_all(['input', 'textarea'])
            
            for input_field in inputs:
                field_name = input_field.get('name')
                if field_name:
                    for payload in PayloadManager.XSS_PAYLOADS:
                        if method == 'get':
                            test_url = f"{action}?{field_name}={urllib.parse.quote(payload)}"
                            response = self.session.get(test_url, timeout=5)
                        else:
                            data = {field_name: payload}
                            response = self.session.post(action, data=data, timeout=5)
                            
                        if payload in response.text:
                            self._add_vulnerability(
                                "XSS",
                                action,
                                f"Form field '{field_name}' vulnerable to XSS",
                                "High"
                            )
        except Exception as e:
            logging.error(f"Form XSS test error on {url}: {str(e)}")

    def _check_sql_injection(self, url):
        parsed_url = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)
        
        if params:
            for param, value in params.items():
                for payload in PayloadManager.SQL_PAYLOADS:
                    self._test_sql_payload(url, param, payload)

    def _test_sql_payload(self, url, param, payload):
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        params[param] = [payload]
        query = urllib.parse.urlencode(params, doseq=True)
        test_url = url.split('?')[0] + '?' + query

        try:
            response = self.session.get(test_url, timeout=5)
            error_patterns = [
                "mysql_fetch_array()", "ORA-", "SQL syntax",
                "Microsoft SQL Server", "MySQL Error", "SQLException",
                "PostgreSQL", "SQLite/JDBCDriver", "System.Data.SQLite"
            ]
            
            for pattern in error_patterns:
                if pattern in response.text:
                    self._add_vulnerability("SQL Injection", test_url,
                        f"Parameter '{param}' vulnerable to SQL injection",
                        "Critical")
                    break
        except Exception as e:
            logging.error(f"SQL injection test error on {test_url}: {str(e)}")

    def _check_open_redirect(self, url):
        parsed_url = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)
        redirect_params = ['redirect', 'url', 'next', 'redir', 'return', 'return_url', 'redirect_uri']
        
        for param_name in redirect_params:
            if param_name in params:
                malicious_url = "https://evil-example.com"
                test_params = params.copy()
                test_params[param_name] = [malicious_url]
                
                query = urllib.parse.urlencode(test_params, doseq=True)
                test_url = url.split('?')[0] + '?' + query
                
                try:
                    response = self.session.get(test_url, timeout=5, allow_redirects=False)
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        if malicious_url in location:
                            self._add_vulnerability(
                                "Open Redirect",
                                test_url,
                                f"Parameter '{param_name}' vulnerable to open redirect",
                                "Medium"
                            )
                except Exception as e:
                    logging.error(f"Open redirect test error on {test_url}: {str(e)}")

    def _check_ssrf(self, url):
        parsed_url = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)
        
        if params:
            for param in params:
                for payload in PayloadManager.SSRF_PAYLOADS:
                    test_params = params.copy()
                    test_params[param] = [payload]
                    query = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = url.split('?')[0] + '?' + query
                    
                    try:
                        response = self.session.get(test_url, timeout=5)
                        if response.status_code == 200:
                            self._add_vulnerability(
                                "Potential SSRF",
                                test_url,
                                f"Parameter '{param}' might be vulnerable to SSRF",
                                "High"
                            )
                    except Exception as e:
                        logging.error(f"SSRF test error on {test_url}: {str(e)}")

    def _check_directory_traversal(self, url):
        parsed_url = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)
        
        if params:
            for param in params:
                for payload in PayloadManager.TRAVERSAL_PAYLOADS:
                    test_params = params.copy()
                    test_params[param] = [payload]
                    query = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = url.split('?')[0] + '?' + query
                    
                    try:
                        response = self.session.get(test_url, timeout=5)
                        if any(pattern in response.text for pattern in ["root:x:", "[drivers]", "boot loader"]):
                            self._add_vulnerability(
                                "Directory Traversal",
                                test_url,
                                f"Parameter '{param}' vulnerable to directory traversal",
                                "Critical"
                            )
                    except Exception as e:
                        logging.error(f"Directory traversal test error on {test_url}: {str(e)}")

    def _add_vulnerability(self, vuln_type, url, details, severity):
        vulnerability = {
            "type": vuln_type,
            "url": url,
            "details": details,
            "severity": severity,
            "timestamp": datetime.now().isoformat()
        }
        self.vulnerabilities.append(vulnerability)
        console.print(f"[bold red]🚨 {vuln_type} found![/bold red]")
        console.print(f"   URL: {url}")
        console.print(f"   Details: {details}")
        console.print(f"   Severity: [bold red]{severity}[/bold red]")

    def save_results(self):
        results = {
            "scan_info": {
                "target_url": self.target_url,
                "scan_date": datetime.now().isoformat(),
                "urls_scanned": len(self.visited_urls)
            },
            "vulnerabilities": self.vulnerabilities
        }
        
        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=4)
        console.print(f"\n[green]Results saved to {self.output_file}[/green]")

# Create a main class to handle all functions and run it
def main():
    parser = argparse.ArgumentParser(description='Advanced Web Vulnerability Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--depth', type=int, default=2, help='Crawling depth (default: 2)')
    parser.add_argument('--output', help='Output file for results (JSON format)')
    args = parser.parse_args()

    if not args.url.startswith(('http://', 'https://')):
        args.url = 'http://' + args.url

    try:
        scanner = VulnerabilityScanner(
            args.url,
            max_threads=args.threads,
            depth=args.depth,
            output_file=args.output
        )
        
        vulnerabilities = scanner.scan()
        
        table = Table(title="Scan Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("URLs Scanned", str(len(scanner.visited_urls)))
        table.add_row("Vulnerabilities Found", str(len(vulnerabilities)))
        
        console.print("\n")
        console.print(table)
        
        if vulnerabilities:
            vuln_table = Table(title="Vulnerability Details")
            vuln_table.add_column("Type", style="red")
            vuln_table.add_column("Severity", style="yellow")
            vuln_table.add_column("URL", style="blue")
            
            for vuln in vulnerabilities:
                vuln_table.add_row(
                    vuln['type'],
                    vuln['severity'],
                    Text(vuln['url'], overflow='fold')
                )
            
            console.print("\n")
            console.print(vuln_table)

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[bold red]Error during scan: {str(e)}[/bold red]")

# Run the main class function
if __name__ == "__main__":
    main()