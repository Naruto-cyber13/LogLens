```markdown
# LogLens (FastAPI)

A minimal FastAPI backend for log upload & rule-based analysis.

Features
- User registration & JWT login
- Upload Apache/Nginx access logs
- Rule-based detectors (SQLi, directory traversal, brute-force)
- Rate limit uploads for free users (5/day)
- Store analysis summaries in SQLite

Requirements
- Python 3.10+
- Install deps:
  pip install -r requirements.txt

Environment
- SECRET_KEY (required) — used to sign JWTs
- DATABASE_URL (optional) — SQLAlchemy async URL (default: sqlite+aiosqlite:///./loglens.db)

Run
1. Export a secret:
   export SECRET_KEY="please_set_a_strong_secret"

2. Initialize DB (optional — app will ensure tables on startup):
   python -m scripts.init_db

3. Start server:
   uvicorn app.main:app --reload

API examples (curl)

Register:
curl -X POST "http://127.0.0.1:8000/auth/register" -H "Content-Type: application/json" -d '{"email":"alice@example.com","password":"secret"}'

Login:
curl -X POST "http://127.0.0.1:8000/auth/login" -H "Content-Type: application/json" -d '{"email":"alice@example.com","password":"secret"}'

Upload (replace <TOKEN> with Bearer token from login):
curl -X POST "http://127.0.0.1:8000/logs/upload" -H "Authorization: Bearer <TOKEN>" -F "file=@sample_logs/sample.log"

Get analysis:
curl -X GET "http://127.0.0.1:8000/logs/{analysis_id}" -H "Authorization: Bearer <TOKEN>"

Sample log file
- sample_logs/sample.log included with a few example lines.

Notes
- This is an MVP focused on a working end-to-end flow. For production:
  - Use HTTPS
  - Rotate secrets and adjust token expiry
  - Add background processing if large files
  - Add migrations (alembic) as needed
```