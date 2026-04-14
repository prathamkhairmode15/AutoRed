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
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "ip_addresses": []
    }
    
    if not output:
        return parsed_data
        
    for line in output.split('\n'):
        line = line.strip()
        
        # A / IPv4
        match_a = re.search(r'internet address = ([0-9\.]+)', line)
        if match_a:
            ip = match_a.group(1)
            parsed_data["A"].append(ip)
            parsed_data["ip_addresses"].append(ip)
            
        # AAAA / IPv6
        match_aaaa = re.search(r'AAAA IPv6 address = ([0-9a-fA-F:]+)', line)
        if match_aaaa:
            ip = match_aaaa.group(1)
            parsed_data["AAAA"].append(ip)
            parsed_data["ip_addresses"].append(ip)
            
        # MX
        match_mx = re.search(r'mail exchanger = (.*)', line, re.IGNORECASE)
        if match_mx:
            parsed_data["MX"].append(match_mx.group(1).strip())
            
        # NS
        match_ns = re.search(r'(?:primary )?name server = (.*)', line, re.IGNORECASE)
        if match_ns:
            parsed_data["NS"].append(match_ns.group(1).strip())
        
        # TXT
        match_txt = re.search(r'text = (.*)', line, re.IGNORECASE)
        if match_txt:
            parsed_data["TXT"].append(match_txt.group(1).strip())
            
        # Address: fallback
        if line.startswith("Address:"):
            parts = line.split("Address:")
            if len(parts) > 1:
                ip = parts[1].strip()
                if re.match(r'^[0-9\.]+$', ip):
                    parsed_data["ip_addresses"].append(ip)
                    
    # Deduplicate
    for key in parsed_data:
        parsed_data[key] = list(set([item for item in parsed_data[key] if item]))
        
    return parsed_data

def parse_whois(output: str) -> dict:
    parsed_data = {
        "Registrar": "Unknown",
        "Creation Date": "Unknown",
        "Expiry Date": "Unknown",
        "Updated Date": "Unknown",
        "Organization": "Unknown",
        "Email": "Unknown",
        "Phone": "Unknown",
        "Registrant Name": "Unknown",
        "Name Servers": []
    }
    
    if not output:
        return parsed_data
        
    for line in output.split('\n'):
        line = line.strip()
        lower_line = line.lower()
        
        if lower_line.startswith("registrar:") and parsed_data["Registrar"] == "Unknown":
            parsed_data["Registrar"] = line.split(":", 1)[1].strip()
        elif (lower_line.startswith("creation date:") or lower_line.startswith("created date:")) and parsed_data["Creation Date"] == "Unknown":
            parsed_data["Creation Date"] = line.split(":", 1)[1].strip()
        elif (lower_line.startswith("registry expiry date:") or lower_line.startswith("registrar registration expiration date:")) and parsed_data["Expiry Date"] == "Unknown":
            parsed_data["Expiry Date"] = line.split(":", 1)[1].strip()
        elif lower_line.startswith("updated date:") and parsed_data["Updated Date"] == "Unknown":
            parsed_data["Updated Date"] = line.split(":", 1)[1].strip()
        elif lower_line.startswith("registrant organization:") and parsed_data["Organization"] == "Unknown":
            parsed_data["Organization"] = line.split(":", 1)[1].strip()
        elif lower_line.startswith("registrant email:") and parsed_data["Email"] == "Unknown":
            parsed_data["Email"] = line.split(":", 1)[1].strip()
        elif lower_line.startswith("registrant phone:") and parsed_data["Phone"] == "Unknown":
            parsed_data["Phone"] = line.split(":", 1)[1].strip()
        elif lower_line.startswith("registrant name:") and parsed_data["Registrant Name"] == "Unknown":
            parsed_data["Registrant Name"] = line.split(":", 1)[1].strip()
        elif lower_line.startswith("name server:"):
            ns = line.split(":", 1)[1].strip()
            if ns:
                parsed_data["Name Servers"].append(ns)
                
    parsed_data["Name Servers"] = list(set(parsed_data["Name Servers"]))
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
        if "--- Emails found ---" in line or "[*] Emails found:" in line:
            parsing_emails = True
            parsing_hosts = False
            continue
        if "--- Hosts found ---" in line or "[*] Hosts found:" in line:
            parsing_hosts = True
            parsing_emails = False
            continue
            
        line = line.strip()
        if not line or "---" in line:
            continue
            
        if parsing_emails and "@" in line:
            emails.append(line)
        elif parsing_hosts:
            host = line.split(":")[0].strip()
            if host and host != "No hosts found":
                subdomains.append(host)
                
    return {
        "emails": list(set(emails)),
        "subdomains": list(set(subdomains))
    }

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
