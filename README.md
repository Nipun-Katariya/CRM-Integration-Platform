# CRM-Integration-Platform

Setup
-----

1) Create environment variables (do NOT commit secrets):

Required variables (example names):

- `AIRTABLE_CLIENT_ID`
- `AIRTABLE_CLIENT_SECRET`
- `HUBSPOT_CLIENT_ID`
- `HUBSPOT_CLIENT_SECRET`
- `NOTION_CLIENT_ID`
- `NOTION_CLIENT_SECRET`

Create a `.env` file locally (not tracked) or set them in your environment. See `.env.example` for the shape.

2) Install backend dependencies and run locally

```bash
python -m venv .venv
source .venv/bin/activate   # macOS / Linux
.venv\Scripts\Activate.ps1 # Windows PowerShell
pip install -r backend/requirements.txt
uvicorn backend.main:app --reload --port 8000
```

3) Frontend

Install and run the React frontend from the `frontend/` directory:

```bash
cd frontend
npm install
npm start
```

Security notes before publishing
- Do NOT commit `.env` or any files containing secrets.
- Rotate any client secrets that were previously hardcoded in source — assume they are compromised.
- Remove sensitive data files (e.g. `dump.rdb`) from git history before pushing public. Tools: `git-filter-repo` or `BFG Repo-Cleaner`.
