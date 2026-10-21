# LinkAlive

LinkAlive is an early-stage, self-hosted public website link auditing application. It includes an admin interface, saved websites, audit results and optional scheduled rescans.

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export ADMIN_TOKEN='replace-with-a-long-random-secret'
export DATABASE_PATH=./linkalive.db
python app.py
```

Visit http://localhost:8080 and enter the configured admin token.

## Docker deployment

1. Deploy the repository as a Docker service on an authorized cloud provider.
2. Set `ADMIN_TOKEN` to a long random secret; never commit it.
3. Set `DATABASE_PATH=/data/linkalive.db` and mount persistent storage at `/data`.
4. Use `ENABLE_SCHEDULER=1` only on one instance. Use a single Gunicorn worker.
5. Configure HTTPS and check `/health` after deployment.

## Routes

- `/` browser interface; API calls require `X-Admin-Token`.
- `/health` health endpoint.
- `GET /api/sites` lists saved sites.
- `POST /api/sites` with JSON `{"url":"https://example.com"}` adds a site.
- `POST /api/sites/{id}/scan` scans a homepage and up to 20 links.
- `GET /api/sites/{id}/issues` returns scan issues.

## Current limitations

This code is an **initial prototype**. It does **not** yet discover prospects automatically, send emails, accept payments, repair third-party sites, execute distributed hybrid audits or sustain 100,000 websites/hour. It requires runtime testing, security hardening and production integrations.

Only scan properties you own or are authorized to assess. Respect access restrictions and rate limits. Prevent private-network access at the deployment's outbound firewall; application-only URL filtering cannot fully prevent DNS rebinding or related attacks. Scans may produce false positives. Do not automatically send unsolicited mass outreach.
