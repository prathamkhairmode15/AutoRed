import asyncio
import json
import re
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

import threading
import queue
import subprocess

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
    ip_addresses = []
    lines = output.split('\n')
    parsing_answers = False
    
    for line in lines:
        if "Name:" in line or "Non-authoritative answer:" in line:
            parsing_answers = True
        
        # When parsing addresses after Name:
        if "Address:" in line:
            parts = line.split("Address:")
            if len(parts) > 1:
                ip_addresses.append(parts[1].strip())
        elif "Addresses:" in line:
            parts = line.split("Addresses:")
            if len(parts) > 1:
                ip_addresses.append(parts[1].strip())
        elif parsing_answers and re.match(r'^\s*([0-9]{1,3}\.){3}[0-9]{1,3}\s*$', line):
            ip_addresses.append(line.strip())
            
    # Simple deduplication
    ip_addresses = list(set([ip for ip in ip_addresses if not '192.168' in ip and not '127.0.0.1' in ip and not '::' in ip]))
    return {"ip_addresses": ip_addresses}

def parse_whois(output: str) -> dict:
    registrar = None
    creation_date = None
    
    for line in output.split('\n'):
        lower_line = line.lower()
        if ("registrar:" in lower_line or "registrar name:" in lower_line) and not registrar:
            parts = line.split(":")
            if len(parts) > 1:
                registrar = parts[1].strip()
        elif ("creation date:" in lower_line or "created:" in lower_line) and not creation_date:
            parts = line.split(":")
            if len(parts) > 1:
                creation_date = parts[1].strip()
                
    return {
        "registrar": registrar or "Unknown",
        "creation_date": creation_date or "Unknown"
    }

def parse_theharvester(output: str) -> dict:
    emails = []
    subdomains = []
    
    lines = output.split('\n')
    parsing_emails = False
    parsing_hosts = False
    
    for line in lines:
        if "--- Emails found ---" in line:
            parsing_emails = True
            parsing_hosts = False
            continue
        if "--- Hosts found ---" in line:
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
            if host:
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
        append_log(f"[error] Target is invalid. Prevented potential command injection.\n")
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
            async for is_line, content in run_command_and_stream_output(["nslookup", target], "nslookup"):
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
                ["theHarvester", "-d", target, "-l", "50", "-b", "all"], "theHarvester"
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
        yield f"data: Scan not found or already completed.\n\n"
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
