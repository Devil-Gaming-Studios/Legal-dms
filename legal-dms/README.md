# LexiGuard CaseVault: Secure Legal DMS + Police Asset Lifecycle

Run: `pip install -r requirements.txt`, set `GROQ_API_KEY` (optional `GROQ_MODEL`, `JWT_SECRET`, `DEFAULT_PASSWORD`), then `uvicorn app:app --reload` and open http://localhost:8000 (API docs at /docs).

Users (password `changeme`): admin, officer, clerk, prosecutor, judge, auditor.

Demo flow: officer creates a case, ingests a document, registers an exhibit, starts a handoff; then sign in as officer, prosecutor and judge in that order to sign it. Auditor or judge can verify the ledger and export a Merkle proof.

Files: `app.py` (API), `static/index.html` (UI), `static/logo.svg`, `requirements.txt`. Data is created in `data/` on first run.

Production swaps: Keycloak for auth, Vault for keys, PKI/smartcards for signatures, Postgres/MinIO/OpenSearch for storage.
