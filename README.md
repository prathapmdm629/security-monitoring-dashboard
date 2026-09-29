# Security Monitoring Dashboard

A production-style defensive SOC dashboard built with Flask, SQLite, server-rendered HTML, and Chart.js. It simulates an analyst workflow for triaging alerts, correlating potentially related activity, managing incidents, documenting investigations, and reviewing an audit trail.

## Why this project

This portfolio project demonstrates practical SOC Analyst and full-stack engineering skills: alert lifecycle design, role-based access control, secure form handling, server-side validation, data modeling, and operator-focused UI design.

## Features

- Dashboard KPIs and severity, source, and status charts
- Searchable and filterable alert queue
- Alert detail pages with MITRE ATT&CK mappings and correlation signals
- Alert status changes, assignment, notes, and audit history
- Incident creation, status management, assignment, and alert linking
- Admin-only analyst account and role management
- Viewer read-only access
- SQLite initialization with 15 safe demo alerts
- CSRF protection, password hashing, parameterized SQL, secure cookies, security headers, and custom error pages

## Technology and architecture

Python 3, Flask 3, Flask-WTF, SQLite, Jinja2, CSS, vanilla JavaScript, and Chart.js CDN. `app.py` owns routes, access control, database helpers, seed data, and error handling. Templates provide the UI and static files provide the visual system and charts.

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:SECRET_KEY = "replace-with-a-long-random-value"
python app.py
```

Open http://127.0.0.1:5000.

The database is created automatically at `instance/security_monitoring.db`. Set `DATABASE_PATH` to use another location. Database files and `.env` files are ignored by Git.

## Demo credentials

These are development-only credentials. Change or remove them before any production deployment.

| Username | Password | Role |
| --- | --- | --- |
| admin | Admin@123 | Full access |
| analyst | Analyst@123 | Investigations and incidents |
| viewer | Viewer@123 | Read-only |

## RBAC and lifecycles

Admins manage users and all security records. Analysts view the dashboard, update alerts, add investigation notes, and manage incidents. Viewers can read dashboards, alerts, and incidents but cannot mutate data.

Alerts move from Open to Investigating, Resolved, and Closed. Incidents move from Open to Investigating, Contained, Resolved, and Closed. Correlation looks for shared hostname, source IP, or username and labels results **Potentially Related Activity**; it does not claim that an attack occurred.

MITRE technique IDs are mapped to static descriptions in `app.py` for this demo. No external threat infrastructure is contacted.

## Database schema

The schema includes `users`, `alerts`, `incidents`, `incident_alerts`, `investigation_notes`, and `activity_logs`. Foreign keys connect assignments, linked alerts, and notes. Every state-changing operation uses POST and produces an audit event.

## Security controls

- Werkzeug password hashes, never plaintext passwords
- Flask sessions with HttpOnly and SameSite cookies
- Flask-WTF CSRF protection on forms
- Parameterized SQLite queries
- Server-side role and input validation
- Jinja autoescaping for user-generated content
- Generic 403, 404, and 500 pages
- `X-Content-Type-Options`, `X-Frame-Options`, and `Referrer-Policy` can be added at the deployment proxy; do not run debug mode in production
- Store `SECRET_KEY` in the environment and use HTTPS with `SESSION_COOKIE_SECURE=1`

## Testing

```powershell
pytest -q
```

The test suite covers startup/seeding, login success and failure, logout, protected routes, RBAC, alert details and status changes, incident creation, notes, and audit logging.

## Project structure

```text
app.py              Flask routes, database, auth, seed data
config.py           Environment-based configuration
requirements.txt    Python dependencies
templates/          Server-rendered views
static/             CSS and JavaScript
instance/           Runtime SQLite database (ignored)
tests/              pytest coverage
```

## GitHub preparation

Commit source code, templates, static assets, tests, requirements, and this README. Do not commit `instance/`, any `.db` or `.sqlite` file, `.env`, virtual environments, Python caches, secrets, or production user data. Before publishing, replace demo credentials, rotate `SECRET_KEY`, disable debug mode, use HTTPS, and configure a production WSGI server.

## Future improvements and limitations

A production version would add pagination, immutable audit storage, password reset and MFA, external log ingestion, alert deduplication, background jobs, stronger CSP headers, database migrations, and a persistent production database. This is a local simulation with seeded data, not a replacement for an EDR, SIEM, or incident response platform.

## Interview explanation

The central design choice is to keep authorization on the server and model operator workflows as auditable POST actions. The dashboard is a read model over normalized SQLite tables; incidents correlate alerts without asserting causality; and all user-entered values are validated and escaped before rendering.
