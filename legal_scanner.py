import asyncio
import re
import sqlite3
from datetime import datetime

# Color formatting for terminal output
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RED = "\033[91m"
RESET = "\033[0m"

# Regex Signature Database
SIGNATURES = {
    "http": [
        (re.compile(r"Server:\s*(SimpleHTTP/[\d\.]+)", re.IGNORECASE), "Python SimpleHTTP Server"),
        (re.compile(r"Server:\s*(BaseHTTP/[\d\.]+)", re.IGNORECASE), "Python BaseHTTP Server"),
        (re.compile(r"Server:\s*(Apache/[\d\.]+)", re.IGNORECASE), "Apache Web Server"),
        (re.compile(r"Server:\s*(nginx/[\d\.]+)", re.IGNORECASE), "Nginx Web Server"),
    ],
    "ssh": [
        (re.compile(r"SSH-\d+\.\d+-OpenSSH_([\d\.]+p\d+)", re.IGNORECASE), "OpenSSH Server"),
    ]
}

def init_db():
    """Initializes the SQLite database evidence ledger table."""
    conn = sqlite3.connect("scan_ledger.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS evidence_ledger (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            target_ip TEXT,
            port INTEGER,
            status TEXT,
            service_identity TEXT,
            raw_banner TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_to_ledger(target_ip, port, status, service, raw_banner):
    """Inserts a scan discovery record into the database."""
    conn = sqlite3.connect("scan_ledger.db")
    cursor = conn.cursor()
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO evidence_ledger (timestamp, target_ip, port, status, service_identity, raw_banner)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (current_time, target_ip, port, status, service, raw_banner))
    conn.commit()
    conn.close()

def generate_markdown_report(target_ip):
    """
    Reads data from the SQLite ledger and builds a professional Markdown audit report.
    """
    conn = sqlite3.connect("scan_ledger.db")
    cursor = conn.cursor()
    
    # Grab only the records for our current scan target
    cursor.execute("""
        SELECT timestamp, port, status, service_identity, raw_banner 
        FROM evidence_ledger 
        WHERE target_ip = ? 
        ORDER BY id DESC LIMIT 4
    """, (target_ip,))
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        return
        
    scan_time = rows[0][0]
    report_filename = f"audit_report_{target_ip.replace('.', '_')}.md"
    
    with open(report_filename, "w") as f:
        # Document Header
        f.write(f"# Network Infrastructure & Security Audit Report\n\n")
        f.write(f"**Audit Timestamp:** {scan_time}  \n")
        f.write(f"**Target System IP:** `{target_ip}`  \n")
        f.write(f"**Assessment Status:** Completed  \n\n")
        f.write(f"---\n\n")
        
        # Executive Summary Box
        f.write(f"## 1. Executive Summary\n")
        f.write(f"> This automated compliance scan evaluated the target IP perimeter endpoints via non-intrusive asynchronous probers to discover active exposures, misconfigurations, and software service identities.\n\n")
        
        # Findings Table
        f.write(f"## 2. Port Discovery & Service Mapping Table\n\n")
        f.write(f"| Network Port | Perimeter Status | Discovered Service Identity | Raw Data Evidence Ledger |\n")
        f.write(f"| :--- | :--- | :--- | :--- |\n")
        
        for row in rows:
            port, status, service, banner = row[1], row[2], row[3], row[4]
            # Replace pipe characters to avoid breaking the markdown table grid syntax
            banner_clean = banner.replace("|", "-") if banner else "N/A"
            f.write(f"| **{port}** | `{status}` | {service} | `{banner_clean}` |\n")
            
        f.write(f"\n\n---\n\n")
        
        # Remediation / Compliance Section
        f.write(f"## 3. Compliance & Risk Mitigation Guidelines\n\n")
        f.write(f"* **Review Open Endpoints:** Ensure that any endpoint marked as `OPEN` is actively protected by enterprise-grade firewall access lists.\n")
        f.write(f"* **Software Version Shielding:** If a web server version signature is explicitly leaked in the 'Raw Data Evidence Ledger', consider configuring the service properties to drop version banners to limit reconnaissance profiling by malicious actors.\n")
        
    print(f"{GREEN}[+] Automated Compliance Report Generated: ./{report_filename}{RESET}")

def identify_service(banner: str, port: int) -> str:
    """Matches raw banner strings against known regex signatures."""
    if "HTTP/" in banner or "Server:" in banner:
        for pattern, label in SIGNATURES["http"]:
            match = pattern.search(banner)
            if match:
                return f"{label} (Version: {match.group(1)})"
        return "Unknown Web Server"
    if "SSH-" in banner:
        for pattern, label in SIGNATURES["ssh"]:
            match = pattern.search(banner)
            if match:
                return f"{label} (Version: {match.group(1)})"
        return "Unknown SSH Service"
    if port in [80, 443, 8080]:
        return "Generic Web Service"
    elif port == 22:
        return "Generic Secure Shell (SSH)"
    return "Unknown Service"

async def grab_banner(reader, writer, port: int) -> str:
    """Sends an active probe to capture server response metadata headers."""
    try:
        if port in [80, 443, 8080]:
            probe = b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            writer.write(probe)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            return data.decode('utf-8', errors='ignore')
        elif port == 22:
            data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            return data.decode('utf-8', errors='ignore')
    except Exception:
        pass
    return ""

async def probe_port(target_ip: str, port: int, timeout: float = 2.5):
    """Probes a port, records the telemetry, and saves to database ledger."""
    try:
        connect_coroutine = asyncio.open_connection(target_ip, port)
        reader, writer = await asyncio.wait_for(connect_coroutine, timeout=timeout)
        
        raw_banner = await grab_banner(reader, writer, port)
        raw_banner_clean = raw_banner.replace('\r', '').replace('\n', ' ').strip()[:120]
        service_identity = identify_service(raw_banner, port)
        
        print(f"{GREEN}[ASYNC] Port {port:<5} --> OPEN | {CYAN}{service_identity}{RESET}")
        
        save_to_ledger(target_ip, port, "OPEN", service_identity, raw_banner_clean)
            
        writer.close()
        await writer.wait_closed()
        return {"port": port, "status": "OPEN", "service": service_identity}
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return {"port": port, "status": "CLOSED", "service": "None"}

async def main():
    init_db()
    print("-" * 65)
    print(f"{YELLOW}[+] Legal Scanner Engine v4.0 [Automated Reporting Mode]{RESET}")
    print("-" * 65)
    
    target = input("Enter the target IP address to scan: ").strip()
    if not target:
        target = "127.0.0.1"
    
    ports_to_scan = list(range(1, 65535)) # [22, 80, 443, 8080, 9929, 31337]
    print(f"\n{YELLOW}[+] Launching Parallel Scan against: {target}...{RESET}\n")

    tasks = [probe_port(target, port) for port in ports_to_scan]
    await asyncio.gather(*tasks)
    
    print("-" * 65)
    # Trigger the automated compilation of the report document
    generate_markdown_report(target)
    print("-" * 65)

if __name__ == "__main__":
    asyncio.run(main())
