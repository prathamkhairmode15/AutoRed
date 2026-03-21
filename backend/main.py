import os
import json
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

from database import init_db, get_db, User, Scan, ScanResult
from scanner import ACTIVE_SCANS, ScanSession, background_passive_scan, stream_passive_scan

app = FastAPI(title="AutoRed Scanning API")

# Setup CORS for the frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Firebase initialization
FIREBASE_CREDENTIALS = os.getenv("FIREBASE_CREDENTIALS", "serviceAccountKey.json")
if os.path.exists(FIREBASE_CREDENTIALS):
    cred = credentials.Certificate(FIREBASE_CREDENTIALS)
    firebase_admin.initialize_app(cred)
    print("Firebase admin initialized.")
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

class ScanStartRequest(BaseModel):
    target: str

@app.post("/api/scan/start")
async def start_scan(request: ScanStartRequest, background_tasks: BackgroundTasks, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    # Create the scan record with 'running' status
    new_scan = Scan(user_id=current_user.id, target=request.target, status="running")
    db.add(new_scan)
    await db.commit()
    await db.refresh(new_scan)
    
    # Initialize memory buffer session and trigger standalone background scanning
    ACTIVE_SCANS[new_scan.id] = ScanSession()
    background_tasks.add_task(background_passive_scan, new_scan.id, request.target)
    
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
    return scans

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
