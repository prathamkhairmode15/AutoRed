import asyncio
import json
import re
import threading
import queue
import subprocess
from sqlalchemy.ext.asyncio import AsyncSession
from database import Scan, ScanResult, AsyncSessionLocal

class ScanSession:
    def __init__(self):
        self.logs = []
        self.new_data_event = asyncio.Event()
        self.is_completed = False

ACTIVE_SCANS: dict[int, ScanSession] = {}


def is_valid_target(target: str) -> bool:
    # Match IP Address
    if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', target):
        return True
    # Match basic domain name format
    if re.match(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', target):
        return True
    return False

async def run_command_and_stream_output(cmd_args, prefix=""):
    """
    Run a subprocess in a background thread and stream its stdout via async queue.
    Yields tuple: (is_output_line, content)
    """
    cmd_str = " ".join(cmd_args)
    q = queue.Queue()
    
    def target_proc():
        try:
            # We use standard subprocess to avoid asyncio's Windows loop restrictions
            process = subprocess.Popen(
                cmd_str,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            for line in process.stdout:
                q.put((True, line.strip()))
            process.wait()
            q.put((False, None))
        except Exception as e:
            q.put((True, f"[error] Process failed: {e}"))
            q.put((False, None))
            
    thread = threading.Thread(target=target_proc, daemon=True)
    thread.start()
    
    full_output = []
    while True:
        try:
            is_line, content = q.get_nowait()
            if not is_line:
                break
            full_output.append(content)
            yield (True, f"data: [{prefix}] {content}\n\n")
        except queue.Empty:
            # Yield control back to the event loop so SSE can flush/run
            await asyncio.sleep(0.05)
            
    yield (False, "\n".join(full_output))

def parse_nslookup(output: str) -> dict:
    parsed_data = {
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
        "ip_addresses": []
    }
    
    if not output:
        return parsed_data
        
    lines = output.split('\n')
    for i, line in enumerate(lines):
        line = line.strip()
        
        # A / IPv4
        match_a = re.search(r'internet address\s*=\s*([0-9\.]+)', line, re.IGNORECASE)
        if match_a:
            ip = match_a.group(1)
            parsed_data["a_records"].append(ip)
            parsed_data["ip_addresses"].append(ip)
            
        # AAAA / IPv6
        match_aaaa = re.search(r'AAAA IPv6 address\s*=\s*([0-9a-fA-F:]+)', line, re.IGNORECASE)
        if match_aaaa:
            ip = match_aaaa.group(1)
            parsed_data["aaaa_records"].append(ip)
            parsed_data["ip_addresses"].append(ip)
            
        # MX
        match_mx = re.search(r'mail exchanger\s*=\s*(.*)', line, re.IGNORECASE)
        if match_mx:
            parsed_data["mx_records"].append(match_mx.group(1).strip())
            
        # NS
        match_ns = re.search(r'(?:primary )?name server\s*=\s*(.*)', line, re.IGNORECASE)
        if match_ns:
            parsed_data["ns_records"].append(match_ns.group(1).strip())
        
        # TXT
        match_txt = re.search(r'text\s*=\s*(.*)', line, re.IGNORECASE)
        if match_txt:
            parsed_data["txt_records"].append(match_txt.group(1).strip())
            
        # Addresses: (plural) - handles multi-IP results elegantly
        if line.lower().startswith("addresses:"):
            first_addr = line.split(":", 1)[1].strip()
            if first_addr:
                parsed_data["ip_addresses"].append(first_addr)
            j = i + 1
            while j < len(lines) and (lines[j].startswith(" ") or lines[j].startswith("\t")):
                addr = lines[j].strip()
                if addr:
                    parsed_data["ip_addresses"].append(addr)
                j += 1
        
        # Address: fallback
        elif line.lower().startswith("address:"):
            addr = line.split(":", 1)[1].strip()
            if addr and addr not in parsed_data["ip_addresses"]:
                parsed_data["ip_addresses"].append(addr)
                    
    # Deduplicate
    for key in parsed_data:
        parsed_data[key] = list(set([item for item in parsed_data[key] if item]))
        
    return parsed_data

def parse_whois(output: str) -> dict:
    parsed_data = {
        "registrar": "Unknown",
        "creation_date": "Unknown",
        "expiry_date": "Unknown",
        "updated_date": "Unknown",
        "organization": "Unknown",
        "email": "Unknown",
        "phone": "Unknown",
        "registrant_name": "Unknown",
        "name_servers": []
    }
    
    if not output:
        return parsed_data
        
    patterns = {
        "registrar": r'Registrar:\s*(.*)',
        "creation_date": r'Creation Date:\s*(.*)',
        "expiry_date": r'(?:Registry Expiry Date|Registrar Registration Expiration Date):\s*(.*)',
        "updated_date": r'Updated Date:\s*(.*)',
        "organization": r'Registrant Organization:\s*(.*)',
        "email": r'Registrant Email:\s*(.*)',
        "phone": r'Registrant Phone:\s*(.*)',
        "registrant_name": r'Registrant Name:\s*(.*)',
    }
    
    for key, pattern in patterns.items():
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            value = match.group(1).strip()
            if value and value.lower() != "not available":
                parsed_data[key] = value
            
    # Name Servers
    ns_matches = re.finditer(r'Name Server:\s*(.*)', output, re.IGNORECASE)
    for m in ns_matches:
        ns = m.group(1).strip()
        if ns:
            parsed_data["name_servers"].append(ns)
                
    parsed_data["name_servers"] = list(set(parsed_data["name_servers"]))
    return parsed_data

def parse_theharvester(output: str) -> dict:
    emails = []
    subdomains = []
    
    if not output:
        return {"emails": emails, "subdomains": subdomains}
        
    lines = output.split('\n')
    parsing_emails = False
    parsing_hosts = False
    
    for line in lines:
        lower_line = line.lower()
        if "emails found" in lower_line:
            parsing_emails = True
            parsing_hosts = False
            continue
        if "hosts found" in lower_line:
            parsing_hosts = True
            parsing_emails = False
            continue
            
        line = line.strip()
        if not line or "---" in line or line.startswith("[*]"):
            continue
            
        if parsing_emails and "@" in line:
            emails.append(line)
        elif parsing_hosts:
            # Handle formats like "host:ip" or just "host"
            host = line.split(":")[0].strip()
            if host and host.lower() != "no hosts found":
                # Basic domain validation
                if "." in host:
                    subdomains.append(host)
                
    return {
        "emails": list(set(emails)),
        "subdomains": list(set(subdomains))
    }

def parse_nmap(output: str) -> dict:
    ports = []
    if not output:
        return {"ports": ports}
        
    lines = output.split('\n')
    for line in lines:
        line = line.strip()
        if not line or not line[0].isdigit():
            continue
            
        match = re.match(r'^(\d+/\w+)\s+(\w+)\s+([^\s]+)\s*(.*)', line)
        if match:
            port_proto = match.group(1)
            state = match.group(2)
            service = match.group(3)
            version = match.group(4).strip()
            
            ports.append({
                "port": port_proto,
                "state": state,
                "service": service,
                "version": version if version else "Unknown"
            })
            
    return {"ports": list(ports)}


async def background_passive_scan(scan_id: int, target: str):
    """
    Executes passive scanning tools in the background, parses results, and outputs logs to memory for SSE.
    """
    session = ACTIVE_SCANS.get(scan_id)
    if not session:
        return
        
    def append_log(msg):
        session.logs.append(msg)
        # We must set the event in the event loop thread
        try:
            asyncio.get_running_loop().call_soon_threadsafe(session.new_data_event.set)
        except RuntimeError:
            pass
        
    append_log(f"Initializing scan for target: {target}\n")
    
    if not is_valid_target(target):
        append_log("[error] Target is invalid. Prevented potential command injection.\n")
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan:
                scan.status = "failed"
                await db.commit()
        session.is_completed = True
        try:
            asyncio.get_running_loop().call_soon_threadsafe(session.new_data_event.set)
        except RuntimeError:
            pass
        return

    async with AsyncSessionLocal() as db:
        # Tool 1: nslookup
        append_log("Starting nslookup...\n")
        nslookup_output = ""
        try:
            async for is_line, content in run_command_and_stream_output(["nslookup", "-debug", target], "nslookup"):
                if is_line:
                    append_log(content.replace("data: ", "") + "\n")
                else:
                    nslookup_output = content
                    
            nslookup_parsed = parse_nslookup(nslookup_output)
            db.add(ScanResult(scan_id=scan_id, type="nslookup", raw_output=nslookup_output, parsed_data=nslookup_parsed))
            await db.commit()
        except Exception as e:
            append_log(f"[error] nslookup failed: {repr(e)}\n")

        # Tool 2: whois
        append_log("Starting whois...\n")
        whois_output = ""
        try:
            async for is_line, content in run_command_and_stream_output(["whois", target], "whois"):
                if is_line:
                    append_log(content.replace("data: ", "") + "\n")
                else:
                    whois_output = content
                    
            whois_parsed = parse_whois(whois_output)
            db.add(ScanResult(scan_id=scan_id, type="whois", raw_output=whois_output, parsed_data=whois_parsed))
            await db.commit()
        except Exception as e:
            append_log(f"[error] whois failed: {repr(e)}\n")

        # Tool 3: theHarvester
        append_log("Starting theHarvester...\n")
        theharvester_output = ""
        try:
            async for is_line, content in run_command_and_stream_output(
                ["theHarvester", "-d", target, "-l", "200", "-b", "crtsh"], "theHarvester"
            ):
                if is_line:
                    append_log(content.replace("data: ", "") + "\n")
                else:
                    theharvester_output = content
                    
            theharvester_parsed = parse_theharvester(theharvester_output)
            db.add(ScanResult(scan_id=scan_id, type="theHarvester", raw_output=theharvester_output, parsed_data=theharvester_parsed))
            await db.commit()
        except Exception as e:
            append_log(f"[error] theHarvester failed: {repr(e)}\n")

        # Tool 4: Nmap
        append_log("Starting nmap port scan...\n")
        nmap_output = ""
        try:
            # -sV: Service/Version detection, -F: Fast scan (top 100 ports)
            async for is_line, content in run_command_and_stream_output(
                ["nmap", "-sV", "-F", target], "nmap"
            ):
                if is_line:
                    append_log(content.replace("data: ", "") + "\n")
                else:
                    nmap_output = content
                    
            nmap_parsed = parse_nmap(nmap_output)
            db.add(ScanResult(scan_id=scan_id, type="nmap", raw_output=nmap_output, parsed_data=nmap_parsed))
            await db.commit()
        except Exception as e:
            append_log(f"[error] nmap failed: {repr(e)}\n")

        # Mark scan as completed
        scan = await db.get(Scan, scan_id)
        if scan:
            scan.status = "completed"
            await db.commit()
            
        append_log("Scan completed successfully.\n")
        
        session.is_completed = True
        try:
            asyncio.get_running_loop().call_soon_threadsafe(session.new_data_event.set)
        except RuntimeError:
            pass


async def stream_passive_scan(scan_id: int):
    """
    Generator yielding SSE strings by reading from the ACTIVE_SCANS memory buffer.
    """
    session = ACTIVE_SCANS.get(scan_id)
    if not session:
        yield "data: Scan not found or already completed.\n\n"
        yield f"event: end\ndata: {json.dumps({'status': 'completed'})}\n\n"
        return
        
    last_idx = 0
    while True:
        # Yield all new lines
        while last_idx < len(session.logs):
            line = session.logs[last_idx]
            # avoid double newlines if line already has one
            clean_line = line.strip()
            if clean_line:
                yield f"data: {clean_line}\n\n"
            last_idx += 1
            
        if session.is_completed:
            yield f"event: end\ndata: {json.dumps({'status': 'completed'})}\n\n"
            # Do NOT aggressively delete from ACTIVE_SCANS here so other tabs can still stream
            break
            
        # Wait for new data
        session.new_data_event.clear()
        # use asyncio wait with timeout to ensure we don't hang if event is missed
        try:
            await asyncio.wait_for(session.new_data_event.wait(), timeout=1.0)
        except asyncio.TimeoutError:
            pass
