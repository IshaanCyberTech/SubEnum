import sys
import subprocess
import pkg_resources
import requests
import dns.resolver
import dns.exception
import concurrent.futures
import time
import re
import os
import json
import aiohttp
import asyncio
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.prompt import Prompt, IntPrompt, Confirm
from bs4 import BeautifulSoup

def install_required_modules():
    required = {'requests', 'dnspython', 'rich', 'beautifulsoup4', 'aiohttp'}
    installed = {pkg.key for pkg in pkg_resources.working_set}
    missing = required - installed

    if missing:
        print(f"[*] Installing missing modules: {', '.join(missing)}...")
        try:
            python = sys.executable
            subprocess.check_call([python, '-m', 'pip', 'install', *missing], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"[+] Successfully installed required modules!")
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to install modules: {e}")
            sys.exit(1)
    else:
        print(f"[*] All required modules are already installed.")

install_required_modules()

console = Console()

def print_banner():
    console.print("[bold cyan]┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓[/bold cyan]")
    console.print("[bold magenta]┃               SubEnum v1.0 - Elite Subdomain Tool            ┃[/bold magenta]")
    console.print("[bold green]┃                 Created by IshaanCyberTech                   ┃[/bold green]")
    console.print("[bold green]┃        GitHub: https://github.com/IshaanCyberTech            ┃[/bold green]")
    console.print("[bold cyan]┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫[/bold cyan]")
    console.print("[bold cyan]┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫[/bold cyan]")
    console.print("[bold yellow]┃ Modes: Brute-Force | Scraping                                ┃[/bold yellow]")
    console.print("[bold yellow]┃ Features: Ultra-Fast | JSON Output | Subdomain Hunt          ┃[/bold yellow]")
    console.print("[bold yellow]┃ Tagline: Find What’s Hidden! with IshaanCyberTech!           ┃[/bold yellow]")
    console.print("[bold cyan]┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛[/bold cyan]\n")

def validate_domain(domain):
    pattern = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    if not re.match(pattern, domain):
        console.print(f"[bold red][!] Invalid domain format: {domain}. Expected format: example.com[/bold red]")
        return False
    return True

def download_wordlist():
    console.print("[bold yellow][*] Downloading wordlist...[/bold yellow]")
    sources = [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
        "https://raw.githubusercontent.com/rbsec/dnscan/master/subdomains-10000.txt",
        "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt"
    ]
    for url in sources:
        try:
            response = requests.get(url, stream=True, timeout=10)
            total_size = int(response.headers.get('content-length', 0))
            with open("auto_wordlist.txt", "wb") as f, Progress(
                TextColumn("[bold cyan]Downloading...[/bold cyan]"),
                BarColumn(),
                "[progress.percentage]{task.percentage:>3.0f}%",
                TimeRemainingColumn()
            ) as progress:
                task = progress.add_task("download", total=total_size)
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        progress.update(task, advance=len(chunk))
            console.print(f"[bold green][+] Wordlist downloaded successfully from {url}! [/bold green]")
            return "auto_wordlist.txt"
        except Exception as e:
            console.print(f"[bold red][!] Failed to download from {url}: {str(e)}[/bold red]")
    console.print("[bold yellow][*] All sources failed. Using fallback default wordlist.[/bold yellow]")
    default_wordlist = [
        "admin", "api", "dev", "test", "staging", "blog", "mail", "www", "shop", "app",
        "login", "secure", "dashboard", "portal", "web", "ftp", "smtp", "pop", "imap", "vpn",
        "beta", "prod", "stage", "auth", "gateway", "cdn", "media", "files", "support", "help",
        "news", "store", "cloud", "data", "api2", "dev2", "test2", "staging2", "backup", "demo"
    ]
    with open("default_wordlist.txt", "w") as f:
        for word in default_wordlist:
            f.write(word + "\n")
    console.print("[bold yellow][*] Using fallback default wordlist (50 subdomains).[/bold yellow]")
    return "default_wordlist.txt"

def check_subdomain(domain, subdomain, output_file, found_records, verbose, retry):
    full_domain = f"{subdomain}.{domain}"
    record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS']
    results = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2
    if retry:
        resolver.nameservers = ['8.8.8.8', '8.8.4.4']

    for record_type in record_types:
        try:
            answers = resolver.resolve(full_domain, record_type)
            for answer in answers:
                result = f"{full_domain} => ({record_type}) {answer.to_text()}"
                results.append(result)
                with open(output_file, "a") as f:
                    f.write(result + "\n")
                found_records.append((full_domain, record_type, answer.to_text()))
                table = Table(show_edge=False, style="bold green")
                table.add_column("🌟 Subdomain", style="bold bright_green")
                table.add_column("Record", style="bold cyan")
                table.add_row(full_domain, f"({record_type}) {answer.to_text()}")
                console.print(table)
        except dns.resolver.NXDOMAIN:
            if verbose:
                table = Table(show_edge=False, style="bold red")
                table.add_column("❌ Subdomain", style="bold bright_red")
                table.add_column("Status", style="bold red")
                table.add_row(full_domain, f"No {record_type} record found")
                console.print(table)
        except dns.exception.Timeout:
            if verbose:
                console.print(f"[bold yellow][!] Timeout checking {full_domain} for {record_type}[/bold yellow]")
        except Exception as e:
            if verbose:
                console.print(f"[bold yellow][!] Error checking {full_domain} for {record_type}: {str(e)}[/bold yellow]")
    return results

def brute_force_mode(domain, wordlist_path, threads, output_file, verbose, retry, save_json):
    found_records = []
    console.print(f"[bold cyan][*] Initiating brute-force on {domain} with {threads} threads...[/bold cyan]")
    
    if os.path.exists(output_file):
        os.remove(output_file)

    with open(wordlist_path, "r") as f:
        subdomains = [line.strip() for line in f if line.strip()]

    start_time = time.time()
    with Progress(
        TextColumn("[bold cyan]Brute-Forcing...[/bold cyan]"),
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeElapsedColumn(),
        TimeRemainingColumn()
    ) as progress:
        task_id = progress.add_task("bruteforce", total=len(subdomains))
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(check_subdomain, domain, subdomain, output_file, found_records, verbose, retry) for subdomain in subdomains]
            for future in concurrent.futures.as_completed(futures):
                progress.advance(task_id)

    end_time = time.time()
    console.print(f"\n[bold cyan][*] Brute-force completed in {end_time - start_time:.2f} seconds.[/bold cyan]")
    console.print(f"[bold green][+] Found {len(found_records)} records. Results saved to {output_file}[/bold green]")
    if found_records:
        console.print("[bold yellow][*] Summary of Found Records:[/bold yellow]")
        table = Table(show_edge=False, style="bold yellow")
        table.add_column("Subdomain", style="bold bright_green")
        table.add_column("Record Type", style="bold cyan")
        table.add_column("Value", style="bold white")
        found_records.sort(key=lambda x: (x[0], x[1]))
        for subdomain, record_type, value in found_records:
            table.add_row(subdomain, record_type, value)
        console.print(table)

    if save_json:
        json_file = output_file.replace('.txt', '.json')
        with open(json_file, 'w') as f:
            json.dump([{"subdomain": r[0], "record_type": r[1], "value": r[2]} for r in found_records], f, indent=4)
        console.print(f"[bold green][+] Results saved in JSON format to {json_file}[/bold green]")

async def scrape_crtsh(domain, found_records, timeout):
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=timeout) as response:
                data = await response.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    if name.endswith(f".{domain}") and not name.startswith("*"):
                        found_records.add((name, "Scraped", "crt.sh"))
                console.print(f"[bold green][+] Scraped {len(found_records)} subdomains from crt.sh[/bold green]")
        except Exception as e:
            console.print(f"[bold red][!] Error scraping from crt.sh: {str(e)}[/bold red]")

async def scrape_hackertarget(domain, found_records, timeout):
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=timeout) as response:
                subdomains = (await response.text()).splitlines()
                for subdomain in subdomains:
                    if subdomain.endswith(f".{domain}"):
                        found_records.add((subdomain, "Scraped", "HackerTarget"))
                console.print(f"[bold green][+] Scraped {len(found_records)} subdomains from HackerTarget[/bold green]")
        except Exception as e:
            console.print(f"[bold red][!] Error scraping from HackerTarget: {str(e)}[/bold red]")

async def scrape_certspotter(domain, found_records, timeout):
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names", timeout=timeout) as response:
                data = await response.json()
                for entry in data:
                    for dns_name in entry.get("dns_names", []):
                        if dns_name.endswith(f".{domain}"):
                            found_records.add((dns_name, "Scraped", "CertSpotter"))
                console.print(f"[bold green][+] Scraped {len(found_records)} subdomains from CertSpotter[/bold green]")
        except Exception as e:
            console.print(f"[bold red][!] Error scraping from CertSpotter: {str(e)}[/bold red]")

async def scrape_dnsdumpster(domain, found_records, timeout):
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(f"https://dnsdumpster.com/", timeout=timeout) as response:
                soup = BeautifulSoup(await response.text(), 'html.parser')
                token = soup.find("input", {"name": "csrfmiddlewaretoken"})["value"]
            async with session.post(f"https://dnsdumpster.com/", data={"csrfmiddlewaretoken": token, "targetip": domain, "user": "free"}, headers={"Referer": "https://dnsdumpster.com/"}, timeout=timeout) as response:
                soup = BeautifulSoup(await response.text(), 'html.parser')
                tables = soup.find_all("table")
                for table in tables:
                    for row in table.find_all("tr"):
                        tds = row.find_all("td")
                        if len(tds) > 0:
                            subdomain = tds[0].text.strip().split("\n")[0]
                            if subdomain.endswith(f".{domain}"):
                                found_records.add((subdomain, "Scraped", "DNSDumpster"))
                console.print(f"[bold green][+] Scraped {len(found_records)} subdomains from DNSDumpster[/bold green]")
        except Exception as e:
            console.print(f"[bold red][!] Error scraping from DNSDumpster: {str(e)}[/bold red]")

async def scrape_wayback(domain, found_records, timeout):
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey", timeout=timeout) as response:
                data = await response.json()
                for entry in data[1:]:
                    url = entry[0]
                    if "://" in url:
                        subdomain = url.split("://")[1].split("/")[0]
                        if subdomain.endswith(f".{domain}"):
                            found_records.add((subdomain, "Scraped", "Wayback Machine"))
                console.print(f"[bold green][+] Scraped {len(found_records)} subdomains from Wayback Machine[/bold green]")
        except Exception as e:
            console.print(f"[bold red][!] Error scraping from Wayback Machine: {str(e)}[/bold red]")

async def scrape_rapid_dns(domain, found_records, timeout):
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(f"https://rapiddns.io/subdomain/{domain}?full=1", timeout=timeout) as response:
                soup = BeautifulSoup(await response.text(), 'html.parser')
                table = soup.find("table", {"id": "table"})
                if table:
                    for row in table.find_all("tr")[1:]:
                        subdomain = row.find_all("td")[0].text.strip()
                        if subdomain.endswith(f".{domain}"):
                            found_records.add((subdomain, "Scraped", "RapidDNS"))
                console.print(f"[bold green][+] Scraped {len(found_records)} subdomains from RapidDNS[/bold green]")
        except Exception as e:
            console.print(f"[bold red][!] Error scraping from RapidDNS: {str(e)}[/bold red]")

async def scrape_alienvault(domain, found_records, timeout):
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=timeout) as response:
                data = await response.json()
                for entry in data.get("passive_dns", []):
                    hostname = entry.get("hostname", "")
                    if hostname.endswith(f".{domain}"):
                        found_records.add((hostname, "Scraped", "AlienVault OTX"))
                console.print(f"[bold green][+] Scraped {len(found_records)} subdomains from AlienVault OTX[/bold green]")
        except Exception as e:
            console.print(f"[bold red][!] Error scraping from AlienVault OTX: {str(e)}[/bold red]")

async def scrape_bufferover(domain, found_records, timeout):
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(f"https://dns.bufferover.run/dns?q=.{domain}", timeout=timeout) as response:
                data = await response.json()
                for entry in data.get("FDNS_A", []):
                    subdomain = entry.split(",")[1]
                    if subdomain.endswith(f".{domain}"):
                        found_records.add((subdomain, "Scraped", "BufferOver"))
                console.print(f"[bold green][+] Scraped {len(found_records)} subdomains from BufferOver[/bold green]")
        except Exception as e:
            console.print(f"[bold red][!] Error scraping from BufferOver: {str(e)}[/bold red]")

async def scrape_securitytrails(domain, found_records, timeout):
    # Placeholder: Requires SecurityTrails API key
    console.print("[bold yellow][!] SecurityTrails scraping requires an API key. Skipping...[/bold yellow]")

async def scrape_shodan(domain, found_records, timeout):
    # Placeholder: Requires Shodan API key
    console.print("[bold yellow][!] Shodan scraping requires an API key. Skipping...[/bold yellow]")

async def scrape_censys(domain, found_records, timeout):
    # Placeholder: Requires Censys API key
    console.print("[bold yellow][!] Censys scraping requires an API key. Skipping...[/bold yellow]")

async def scrape_all_sources(domain, found_records, deep, timeout):
    tasks = [scrape_crtsh(domain, found_records, timeout)]
    if deep:
        tasks.extend([
            scrape_hackertarget(domain, found_records, timeout),
            scrape_certspotter(domain, found_records, timeout),
            scrape_dnsdumpster(domain, found_records, timeout),
            scrape_wayback(domain, found_records, timeout),
            scrape_rapid_dns(domain, found_records, timeout),
            scrape_alienvault(domain, found_records, timeout),
            scrape_bufferover(domain, found_records, timeout),
            scrape_securitytrails(domain, found_records, timeout),
            scrape_shodan(domain, found_records, timeout),
            scrape_censys(domain, found_records, timeout)
        ])
    await asyncio.gather(*tasks)

def scraping_mode(domain, output_file, verbose, retry, save_json, deep, timeout=10, max_results=None):
    found_records = set()
    console.print(f"[bold cyan][*] Initiating {'deep' if deep else 'normal'} scraping mode on {domain}...[/bold cyan]")
    
    if os.path.exists(output_file):
        os.remove(output_file)

    with Progress(SpinnerColumn(), TextColumn("[bold cyan]Scraping Subdomains...[/bold cyan]")) as progress:
        task = progress.add_task("scraping", total=None)
        asyncio.run(scrape_all_sources(domain, found_records, deep, timeout))

    found_records = sorted(list(found_records), key=lambda x: x[0])
    if max_results and not deep:
        found_records = found_records[:max_results]

    for subdomain, _, source in found_records:
        result = f"{subdomain} => Found via {source}"
        with open(output_file, "a") as f:
            f.write(result + "\n")
        table = Table(show_edge=False, style="bold green")
        table.add_column("🌟 Subdomain", style="bold bright_green")
        table.add_column("Source", style="bold cyan")
        table.add_row(subdomain, f"Found via {source}")
        console.print(table)

    console.print(f"\n[bold cyan][*] Scraping completed.[/bold cyan]")
    console.print(f"[bold green][+] Found {len(found_records)} subdomains. Results saved to {output_file}[/bold green]")
    if found_records:
        console.print("[bold yellow][*] Summary of Found Subdomains:[/bold yellow]")
        table = Table(show_edge=False, style="bold yellow")
        table.add_column("Subdomain", style="bold bright_green")
        table.add_column("Source", style="bold cyan")
        for subdomain, _, source in found_records:
            table.add_row(subdomain, source)
        console.print(table)

    if save_json:
        json_file = output_file.replace('.txt', '.json')
        with open(json_file, 'w') as f:
            json.dump([{"subdomain": r[0], "source": r[2]} for r in found_records], f, indent=4)
        console.print(f"[bold green][+] Results saved in JSON format to {json_file}[/bold green]")

def save_config(config):
    with open("subenum_config.json", "w") as f:
        json.dump(config, f)
    console.print("[bold green][+] Configuration saved![/bold green]")

def load_config():
    try:
        with open("subenum_config.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {
            "mode": "bruteforce",
            "wordlist_mode": "auto",
            "threads": 10,
            "verbose": False,
            "retry": False,
            "save_json": False,
            "depth": "normal",
            "timeout": 10,
            "max_results": 50
        }

def interactive_mode():
    print_banner()
    console.print("[bold magenta][*] Welcome to Ishaan💀CyberTech SubEnum Interactive Mode![/bold magenta]")
    console.print("[bold green]Type 'help' for available commands or 'exit' to quit.[/bold green]")

    config = load_config()
    current_found_records = set()  # For status command
    while True:
        command = Prompt.ask("[bold magenta][Ishaan💀CyberTech]$[/bold magenta]").strip().lower()
        if command == "exit":
            console.print("[bold yellow][*] Exiting Ishaan💀CyberTech mode. Goodbye![/bold yellow]")
            break
        elif command == "help":
            console.print("[bold cyan]Available Commands:[/bold cyan]")
            console.print("  - run: Start subdomain enumeration")
            console.print("  - config: Show current configuration")
            console.print("  - set <key> <value>: Set configuration (e.g., set mode scraping)")
            console.print("  - save: Save current configuration")
            console.print("  - status: Show current operation status")
            console.print("  - clear: Clear the terminal screen")
            console.print("  - help: Show this help message")
            console.print("  - exit: Exit the interactive mode")
        elif command == "config":
            console.print("[bold cyan]Current Configuration:[/bold cyan]")
            for key, value in config.items():
                console.print(f"  - {key}: {value}")
        elif command.startswith("set "):
            try:
                _, key, value = command.split(maxsplit=2)
                if key in ["threads", "timeout", "max_results"]:
                    value = int(value)
                elif key in ["verbose", "retry", "save_json"]:
                    value = value.lower() == "true"
                elif key not in config:
                    console.print(f"[bold red][!] Invalid config key: {key}[/bold red]")
                    continue
                config[key] = value
                console.print(f"[bold green][+] Set {key} to {value}[/bold green]")
            except ValueError:
                console.print("[bold red][!] Usage: set <key> <value> (e.g., set mode scraping)[/bold red]")
        elif command == "save":
            save_config(config)
        elif command == "status":
            if not current_found_records:
                console.print("[bold yellow][*] No operation in progress or no subdomains found yet.[/bold yellow]")
            else:
                console.print(f"[bold green][+] Currently found {len(current_found_records)} subdomains:[/bold green]")
                for subdomain, _, source in sorted(list(current_found_records), key=lambda x: x[0]):
                    console.print(f"  - {subdomain} (Source: {source})")
        elif command == "clear":
            os.system('cls' if os.name == 'nt' else 'clear')
            print_banner()
        elif command == "run":
            domain = Prompt.ask("[bold cyan]Enter target domain (e.g., example.com)[/bold cyan]")
            if not validate_domain(domain):
                continue

            mode = config["mode"]
            if Confirm.ask(f"[bold cyan]Use default mode ({mode})? (y/n)[/bold cyan]", default=True):
                mode = config["mode"]
            else:
                mode = Prompt.ask("[bold cyan]Enter mode (bruteforce/scraping)[/bold cyan]", choices=["bruteforce", "scraping"], default="bruteforce")

            depth = config["depth"]
            if mode == "scraping":
                if Confirm.ask(f"[bold cyan]Use default depth ({depth})? (y/n)[/bold cyan]", default=True):
                    depth = config["depth"]
                else:
                    depth = Prompt.ask("[bold cyan]Enter depth (normal/deep)[/bold cyan]", choices=["normal", "deep"], default="normal")

            wordlist_mode = config["wordlist_mode"]
            wordlist_path = None
            if mode == "bruteforce":
                if Confirm.ask(f"[bold cyan]Use default wordlist mode ({wordlist_mode})? (y/n)[/bold cyan]", default=True):
                    wordlist_mode = config["wordlist_mode"]
                else:
                    wordlist_mode = Prompt.ask("[bold cyan]Enter wordlist mode (auto/custom)[/bold cyan]", choices=["auto", "custom"], default="auto")
                if wordlist_mode == "custom":
                    wordlist_path = Prompt.ask("[bold cyan]Enter path to custom wordlist[/bold cyan]")
                    if not os.path.exists(wordlist_path):
                        console.print(f"[bold red][!] Wordlist file not found: {wordlist_path}[/bold red]")
                        continue
                else:
                    wordlist_path = download_wordlist()

            threads = config["threads"]
            if mode == "bruteforce":
                if Confirm.ask(f"[bold cyan]Use default threads ({threads})? (y/n)[/bold cyan]", default=True):
                    threads = config["threads"]
                else:
                    threads = IntPrompt.ask("[bold cyan]Enter number of threads[/bold cyan]", default=10)

            output_file = Prompt.ask("[bold cyan]Enter output file name[/bold cyan]", default=f"{'subdomains' if mode == 'bruteforce' else 'scraped_subdomains'}_{domain}.txt")

            verbose = config["verbose"]
            verbose = Confirm.ask(f"[bold cyan]Use verbose mode ({verbose})? (y/n)[/bold cyan]", default=verbose)

            retry = config["retry"]
            retry = Confirm.ask(f"[bold cyan]Use retry with Google DNS ({retry})? (y/n)[/bold cyan]", default=retry)

            save_json = config["save_json"]
            save_json = Confirm.ask(f"[bold cyan]Save results in JSON format ({save_json})? (y/n)[/bold cyan]", default=save_json)

            timeout = config["timeout"]
            if mode == "scraping":
                if Confirm.ask(f"[bold cyan]Use default timeout ({timeout} seconds)? (y/n)[/bold cyan]", default=True):
                    timeout = config["timeout"]
                else:
                    timeout = IntPrompt.ask("[bold cyan]Enter timeout (seconds)[/bold cyan]", default=10)

            max_results = config["max_results"]
            if mode == "scraping" and not (depth == "deep"):
                if Confirm.ask(f"[bold cyan]Use default max results ({max_results})? (y/n)[/bold cyan]", default=True):
                    max_results = config["max_results"]
                else:
                    max_results = IntPrompt.ask("[bold cyan]Enter max results for normal mode[/bold cyan]", default=50)

            current_found_records = set()  # Reset for status command
            if mode == "bruteforce":
                brute_force_mode(domain, wordlist_path, threads, output_file, verbose, retry, save_json)
            else:
                scraping_mode(domain, output_file, verbose, retry, save_json, deep=(depth == "deep"), timeout=timeout, max_results=max_results if not (depth == "deep") else None)
        else:
            console.print(f"[bold red][!] Unknown command: {command}. Type 'help' for available commands.[/bold red]")

def main():
    interactive_mode()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("[bold red]\n[!] Process interrupted by user.[/bold red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red][!] An error occurred: {str(e)}[/bold red]")
        sys.exit(1)