import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import Column, Integer, String, Enum, DateTime, ForeignKey, Text, JSON
from sqlalchemy.sql import func
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "mysql+aiomysql://root:@localhost:3306/autored")

# Aiven adds ?ssl-mode=REQUIRED which aiomysql doesn't parse correctly. 
# We need to replace it with ?ssl=true or remove it if using standard aiomysql defaults.
if "ssl-mode=" in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("ssl-mode=REQUIRED", "ssl=true")

engine = create_async_engine(DATABASE_URL, echo=True)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    firebase_uid = Column(String(128), unique=True, index=True, nullable=False)
    email = Column(String(255), nullable=True)

class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    target = Column(String(255), nullable=False)
    status = Column(Enum("running", "completed", "failed", name="scan_status"), default="running")
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class ScanResult(Base):
    __tablename__ = "scan_results"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    type = Column(String(50), nullable=False) # e.g. nslookup, whois, theharvester
    raw_output = Column(Text, nullable=True)
    parsed_data = Column(JSON, nullable=True)

class UserSettings(Base):
    __tablename__ = "user_settings"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    port_scan_mode = Column(String(20), default="fast")      # fast, standard, full
    enable_vuln_scripts = Column(String(5), default="true")   # true / false
    scan_timeout = Column(Integer, default=300)                # seconds
    terminal_font_size = Column(Integer, default=14)           # px
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
