# Log upload endpoint, parsing, detectors, and analysis persistence

import re
import json
from typing import List, Dict
from datetime import datetime, timedelta
import logging

from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import func

from . import database, models, schemas, auth

router = APIRouter(prefix="/logs", tags=["logs"])
logger = logging.getLogger("loglens")

# Regex for common/combined log format (IP - - [timestamp] "METHOD URL PROTOCOL" status bytes "referrer" "user-agent")
LOG_REGEX = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<url>[^"\s]+)(?:\s+[^"]*)?"\s+(?P<status>\d{3})\s+\S+\s*(?:"[^"]*"\s*)?(?:"(?P<user_agent>[^"]*)")?'
)

# Simple SQLi patterns
SQLI_PATTERNS = [
    r"\'\s*or\s*\'1\'\s*=\s*\'1",
    r"union\s+select",
    r"%27",  # URL-encoded '
    r"(\bselect\b.*\bfrom\b)",  # naive
]

TRAVERSAL_PATTERNS = [r"\.\./", r"\.\.\\"]


async def _count_uploads_today(db: AsyncSession, user_id: int) -> int:
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    q = await db.execute(
        select(func.count(models.Analysis.id)).where(
            models.Analysis.user_id == user_id,
            models.Analysis.created_at >= today_start,
        )
    )
    return q.scalar_one() or 0


def _parse_line(line: str):
    m = LOG_REGEX.search(line)
    if not m:
        return None
    return m.groupdict()


@router.post("/upload", response_model=schemas.AnalysisCreateOut)
async def upload_logs(
    file: UploadFile = File(...),
    token: str = Depends(lambda: None),  # will be overridden in main to read Authorization header
    db: AsyncSession = Depends(database.get_db),
    current_user: models.User = Depends(lambda: None),  # overridden in main
):
    """
    Upload an access log file (multipart form). Returns analysis summary.
    """
    if current_user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    # Rate limit for free users
    if not current_user.is_premium:
        uploads_today = await _count_uploads_today(db, current_user.id)
        if uploads_today >= 5:
            raise HTTPException(status_code=429, detail="Upload limit reached for today (free user)")

    # Read file contents into memory (sensible for MVP)
    content_bytes = await file.read()
    try:
        text = content_bytes.decode(errors="replace")
    except Exception:
        text = content_bytes.decode("utf-8", errors="replace")

    lines = [l for l in text.splitlines() if l.strip()]
    total_lines = len(lines)

    threats_count = 0
    top_threats: Dict[str, int] = {}
    suspicious_ips_set = set()

    failed_counts_by_ip: Dict[str, int] = {}

    for line in lines:
        parsed = _parse_line(line)
        if parsed:
            ip = parsed.get("ip")
            status = parsed.get("status")
            ua = parsed.get("user_agent") or ""
            url = parsed.get("url") or ""
        else:
            # attempt naive extraction
            ip = None
            status = None
            ua = ""
            url = line

        detected = False

        # Check SQLi patterns
        lowered = line.lower()
        for pat in SQLI_PATTERNS:
            if re.search(pat, lowered):
                top_threats["sql_injection"] = top_threats.get("sql_injection", 0) + 1
                threats_count += 1
                detected = True
                if ip:
                    suspicious_ips_set.add(ip)
                break

        # Directory traversal
        if not detected:
            for pat in TRAVERSAL_PATTERNS:
                if re.search(pat, url) or re.search(pat, lowered):
                    top_threats["dir_traversal"] = top_threats.get("dir_traversal", 0) + 1
                    threats_count += 1
                    detected = True
                    if ip:
                        suspicious_ips_set.add(ip)
                    break

        # Count failed authentication responses for brute force detection
        if status and ip:
            try:
                status_code = int(status)
                if status_code in (401, 403):
                    failed_counts_by_ip[ip] = failed_counts_by_ip.get(ip, 0) + 1
                    # don't mark as a detected threat yet; decide after scanning all lines
            except ValueError:
                pass

        # Optionally record user-agent anomalies (not in spec)
        # We keep it minimal.

    # After scan, evaluate brute-force detectors
    brute_force_ips = [ip for ip, cnt in failed_counts_by_ip.items() if cnt > 20]
    if brute_force_ips:
        top_threats["brute_force"] = len(brute_force_ips)
        threats_count += sum(failed_counts_by_ip[ip] for ip in brute_force_ips)
        suspicious_ips_set.update(brute_force_ips)

    suspicious_ips = list(suspicious_ips_set)

    # Persist analysis summary
    analysis = models.Analysis(
        user_id=current_user.id,
        total_lines=total_lines,
        threats_count=threats_count,
        suspicious_ips=json.dumps(suspicious_ips),
        top_threats=json.dumps(top_threats),
    )
    db.add(analysis)
    await db.commit()
    await db.refresh(analysis)

    logger.info(f"User {current_user.id} uploaded file {file.filename}: lines={total_lines}, threats={threats_count}")

    return {
        "analysis_id": analysis.id,
        "total_lines": total_lines,
        "threats_count": threats_count,
        "top_threats": top_threats,
        "suspicious_ips": suspicious_ips,
    }


@router.get("/{analysis_id}", response_model=schemas.AnalysisOut)
async def get_analysis(
    analysis_id: int,
    current_user: models.User = Depends(lambda: None),  # overridden in main
    db: AsyncSession = Depends(database.get_db),
):
    """
    Retrieve a stored analysis (user must own it).
    """
    if current_user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    q = await db.execute(select(models.Analysis).where(models.Analysis.id == analysis_id))
    analysis = q.scalars().first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    if analysis.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Forbidden")

    # parse JSON fields back into Python objects
    try:
        top_threats = json.loads(analysis.top_threats or "{}")
    except Exception:
        top_threats = {}
    try:
        suspicious_ips = json.loads(analysis.suspicious_ips or "[]")
    except Exception:
        suspicious_ips = []

    return {
        "id": analysis.id,
        "user_id": analysis.user_id,
        "total_lines": analysis.total_lines,
        "threats_count": analysis.threats_count,
        "top_threats": top_threats,
        "suspicious_ips": suspicious_ips,
        "created_at": analysis.created_at,
    }