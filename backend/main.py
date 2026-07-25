import os
import json
import re
from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import firebase_admin
from firebase_admin import credentials, auth
import sys
import asyncio

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from database import init_db, get_db, User, Scan, ScanResult, UserSettings
from scanner import ACTIVE_SCANS, ScanSession, background_passive_scan, stream_passive_scan

app = FastAPI(title="AutoRed Scanning API")

# Setup CORS for the frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Firebase initialization
firebase_env_json = os.getenv("FIREBASE_CREDENTIALS_JSON")
if firebase_env_json:
    try:
        cred_dict = json.loads(firebase_env_json)
        cred = credentials.Certificate(cred_dict)
        firebase_admin.initialize_app(cred)
        print("Firebase admin initialized from environment variable.")
    except Exception as e:
        print(f"WARNING: Failed to parse FIREBASE_CREDENTIALS_JSON: {e}")
else:
    FIREBASE_CREDENTIALS = os.getenv("FIREBASE_CREDENTIALS", "serviceAccountKey.json")
    if os.path.exists(FIREBASE_CREDENTIALS):
        cred = credentials.Certificate(FIREBASE_CREDENTIALS)
        firebase_admin.initialize_app(cred)
        print("Firebase admin initialized from file.")
    else:
        print(f"WARNING: Firebase credentials ({FIREBASE_CREDENTIALS}) not found. Authentication will fail.")

security = HTTPBearer()

async def verify_firebase_token(creds: HTTPAuthorizationCredentials = Depends(security)):
    token = creds.credentials
    try:
        if not firebase_admin._apps:
            # Fallback for dev if no firebase configs
            # If FIREBASE_AUTH_MOCK is set, allow mock user
            if os.getenv("FIREBASE_AUTH_MOCK") == "true":
                return {"uid": "mock_uid_123", "email": "mock@test.com"}
            raise Exception("Firebase app is not initialized.")
        decoded_token = auth.verify_id_token(token)
        return decoded_token
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid authentication credentials: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_user(token_data: dict = Depends(verify_firebase_token), db: AsyncSession = Depends(get_db)):
    uid = token_data.get("uid")
    email = token_data.get("email")
    if not uid:
        raise HTTPException(status_code=401, detail="UID not found in token")
        
    result = await db.execute(select(User).where(User.firebase_uid == uid))
    user = result.scalars().first()
    
    if not user:
        user = User(firebase_uid=uid, email=email)
        db.add(user)
        await db.commit()
        await db.refresh(user)
        
    return user

@app.on_event("startup")
async def on_startup():
    await init_db()

@app.get("/")
async def root_health_check(db: AsyncSession = Depends(get_db)):
    """Health check endpoint used by Render and cron jobs to keep the server and DB awake."""
    try:
        # Ping the database to keep Aiven awake
        await db.execute(select(1))
        return {"status": "ok", "message": "AutoRed API and Database are running"}
    except Exception as e:
        return {"status": "error", "message": f"Database connection failed: {str(e)}"}

class ScanStartRequest(BaseModel):
    target: str

@app.post("/api/scan/start")
async def start_scan(request: ScanStartRequest, background_tasks: BackgroundTasks, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    target = request.target.strip()
    target = re.sub(r'^https?://', '', target)
    target = target.split('/')[0]

    # Read user scan settings
    settings_result = await db.execute(select(UserSettings).where(UserSettings.user_id == current_user.id))
    user_settings = settings_result.scalars().first()
    
    scan_config = {
        "port_scan_mode": user_settings.port_scan_mode if user_settings else "fast",
        "enable_vuln_scripts": (user_settings.enable_vuln_scripts if user_settings else "true") == "true",
        "scan_timeout": user_settings.scan_timeout if user_settings else 300
    }
    
    # Create the scan record with 'running' status
    new_scan = Scan(user_id=current_user.id, target=target, status="running")
    db.add(new_scan)
    await db.commit()
    await db.refresh(new_scan)
    
    # Initialize memory buffer session and trigger standalone background scanning
    ACTIVE_SCANS[new_scan.id] = ScanSession()
    background_tasks.add_task(background_passive_scan, new_scan.id, target, scan_config)
    
    return {"scan_id": new_scan.id, "target": new_scan.target, "status": new_scan.status}

@app.get("/api/scan/stream/{scan_id}")
async def stream_scan(scan_id: int, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    # Verify scan exists and belongs to the current user
    result = await db.execute(select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id))
    scan = result.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found or access denied")
        
    # Hook into the active memory buffer to spectate the background scan log stream
    return StreamingResponse(
        stream_passive_scan(scan_id),
        media_type="text/event-stream"
    )

@app.get("/api/scans")
async def get_scans(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.user_id == current_user.id).order_by(Scan.created_at.desc()))
    scans = result.scalars().all()
    
    if not scans:
        return {"scans": [], "stats": {"critical": 0, "high": 0, "medium": 0, "low": 0}}
        
    scan_ids = [scan.id for scan in scans]
    nmap_results = await db.execute(
        select(ScanResult).where(ScanResult.scan_id.in_(scan_ids), ScanResult.type == 'nmap')
    )
    nmap_rows = nmap_results.scalars().all()
    
    vuln_counts = {}
    severity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    
    for r in nmap_rows:
        count = 0
        if r.parsed_data and "ports" in r.parsed_data:
            for port in r.parsed_data["ports"]:
                vulns = port.get("vulnerabilities", [])
                count += len(vulns)
                for v in vulns:
                    match = re.search(r'\s+(\d+\.\d+)\s+', v)
                    if match:
                        score = float(match.group(1))
                        if score >= 9.0: severity_totals["critical"] += 1
                        elif score >= 7.0: severity_totals["high"] += 1
                        elif score >= 4.0: severity_totals["medium"] += 1
                        else: severity_totals["low"] += 1
                    else:
                        severity_totals["low"] += 1
                        
        vuln_counts[r.scan_id] = vuln_counts.get(r.scan_id, 0) + count
        
    response_data = []
    for scan in scans:
        response_data.append({
            "id": scan.id,
            "target": scan.target,
            "status": scan.status,
            "created_at": scan.created_at,
            "vulnerabilities_count": vuln_counts.get(scan.id, 0)
        })
        
    return {
        "scans": response_data,
        "stats": severity_totals
    }

@app.get("/api/scan/{scan_id}")
async def get_scan_details(scan_id: int, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id))
    scan = scan_result.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    result = await db.execute(select(ScanResult).where(ScanResult.scan_id == scan_id))
    results = result.scalars().all()
    
    return {
        "scan": scan,
        "results": results
    }

# ===== Settings Endpoints =====

class SettingsUpdateRequest(BaseModel):
    port_scan_mode: str = "fast"
    enable_vuln_scripts: str = "true"
    scan_timeout: int = 300
    terminal_font_size: int = 14

@app.get("/api/settings")
async def get_settings(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserSettings).where(UserSettings.user_id == current_user.id))
    settings = result.scalars().first()
    
    if not settings:
        return {
            "port_scan_mode": "fast",
            "enable_vuln_scripts": "true",
            "scan_timeout": 300,
            "terminal_font_size": 14,
            "email": current_user.email,
            "user_id": current_user.id
        }
    
    return {
        "port_scan_mode": settings.port_scan_mode,
        "enable_vuln_scripts": settings.enable_vuln_scripts,
        "scan_timeout": settings.scan_timeout,
        "terminal_font_size": settings.terminal_font_size,
        "email": current_user.email,
        "user_id": current_user.id
    }

@app.put("/api/settings")
async def update_settings(request: SettingsUpdateRequest, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserSettings).where(UserSettings.user_id == current_user.id))
    settings = result.scalars().first()
    
    if not settings:
        settings = UserSettings(user_id=current_user.id)
        db.add(settings)
    
    settings.port_scan_mode = request.port_scan_mode
    settings.enable_vuln_scripts = request.enable_vuln_scripts
    settings.scan_timeout = request.scan_timeout
    settings.terminal_font_size = request.terminal_font_size
    
    await db.commit()
    return {"message": "Settings saved successfully"}

@app.delete("/api/scans/clear")
async def clear_scan_history(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    # Get all user scan IDs
    scan_result = await db.execute(select(Scan).where(Scan.user_id == current_user.id))
    scans = scan_result.scalars().all()
    
    for scan in scans:
        # Delete scan results first
        results = await db.execute(select(ScanResult).where(ScanResult.scan_id == scan.id))
        for r in results.scalars().all():
            await db.delete(r)
        await db.delete(scan)
    
    await db.commit()
    return {"message": f"Cleared {len(scans)} scans and all associated data."}

@app.get("/api/scans/export")
async def export_scan_data(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    scan_result = await db.execute(select(Scan).where(Scan.user_id == current_user.id).order_by(Scan.created_at.desc()))
    scans = scan_result.scalars().all()
    
    export_data = []
    for scan in scans:
        results_query = await db.execute(select(ScanResult).where(ScanResult.scan_id == scan.id))
        results = results_query.scalars().all()
        
        export_data.append({
            "id": scan.id,
            "target": scan.target,
            "status": scan.status,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "results": [{
                "type": r.type,
                "parsed_data": r.parsed_data
            } for r in results]
        })
    
    return {"export": export_data, "total_scans": len(export_data)}
