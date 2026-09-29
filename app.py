import os
import sqlite3
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, abort, flash, g, jsonify, redirect, render_template, request, session, url_for
from flask_wtf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

from config import Config

app = Flask(__name__)
app.config.from_object(Config)
csrf = CSRFProtect(app)

SEVERITIES = ("Critical", "High", "Medium", "Low")
ALERT_STATUSES = ("Open", "Investigating", "Resolved", "Closed")
INCIDENT_STATUSES = ("Open", "Investigating", "Contained", "Resolved", "Closed")
ROLES = ("admin", "analyst", "viewer")
TECHNIQUES = {
    "T1110": "Brute Force", "T1059.001": "PowerShell", "T1046": "Network Service Scanning",
    "T1071.001": "Web Protocols", "T1136.001": "Local Account", "T1204.002": "Malicious File",
    "T1548.002": "Bypass User Account Control", "T1567": "Exfiltration Over Web Service",
    "T1078": "Valid Accounts", "T1070.008": "Clear Mailbox Data",
}


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def get_db():
    if "db" not in g:
        Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query(sql, args=(), one=False):
    cursor = get_db().execute(sql, args)
    rows = cursor.fetchall()
    cursor.close()
    return (rows[0] if rows else None) if one else rows


def execute(sql, args=()):
    db = get_db()
    cursor = db.execute(sql, args)
    db.commit()
    return cursor.lastrowid


def log_activity(action, target_type="", target_id=""):
    if g.get("user"):
        execute("INSERT INTO activity_logs (username, action, target_type, target_id, timestamp) VALUES (?, ?, ?, ?, ?)",
                (g.user["username"], action, target_type, str(target_id), utc_now()))


def init_db():
    db = get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','analyst','viewer')), created_at TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
    CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT UNIQUE NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL, source TEXT NOT NULL, source_ip TEXT, destination_ip TEXT, hostname TEXT, username TEXT, event_type TEXT, mitre_technique TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, assigned_to INTEGER REFERENCES users(id));
    CREATE TABLE IF NOT EXISTS incidents (id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT UNIQUE NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL, assigned_to INTEGER REFERENCES users(id), created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS incident_alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE, alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE, UNIQUE(incident_id, alert_id));
    CREATE TABLE IF NOT EXISTS investigation_notes (id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE, username TEXT NOT NULL, note TEXT NOT NULL, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS activity_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, action TEXT NOT NULL, target_type TEXT, target_id TEXT, timestamp TEXT NOT NULL);
    """)
    if query("SELECT COUNT(*) AS count FROM users", one=True)["count"] == 0:
        for username, password, role in (("admin", "Admin@123", "admin"), ("analyst", "Analyst@123", "analyst"), ("viewer", "Viewer@123", "viewer")):
            db.execute("INSERT INTO users (username,password_hash,role,created_at) VALUES (?,?,?,?)", (username, generate_password_hash(password), role, utc_now()))
    if query("SELECT COUNT(*) AS count FROM alerts", one=True)["count"] == 0:
        samples = [
            ("Multiple Failed Login Attempts", "Repeated authentication failures observed over a short period.", "High", "Windows Event Log", "10.10.20.15", "", "WIN-CLIENT-07", "", "Authentication Failure", "T1110"),
            ("Suspicious PowerShell Execution", "PowerShell launched with an unusual encoded command pattern.", "High", "Windows Event Log", "", "", "WIN-CLIENT-07", "analyst", "Process Creation", "T1059.001"),
            ("Port Scan Detected", "Horizontal scan pattern detected at the perimeter.", "Medium", "Firewall", "10.10.20.45", "", "", "", "Network Scan", "T1046"),
            ("Suspicious Outbound Connection", "Endpoint contacted an unclassified external destination.", "Critical", "Network Monitoring", "10.10.20.15", "185.XXX.XXX.XXX", "WIN-CLIENT-07", "", "Command and Control", "T1071.001"),
            ("New Local Administrator Account", "A local administrator account was created outside the change window.", "High", "Windows Event Log", "", "", "WIN-CLIENT-09", "", "Account Creation", "T1136.001"),
            ("Malware Detection Quarantined", "Endpoint protection quarantined a suspicious executable.", "Critical", "Endpoint", "", "", "WIN-CLIENT-12", "", "Malware Detection", "T1204.002"),
            ("Brute-Force Attempt", "Authentication attempts exceeded the configured threshold.", "High", "Linux", "10.10.30.22", "", "LINUX-APP-01", "", "Authentication Failure", "T1110"),
            ("Privilege Escalation Signal", "A process requested elevated privileges unexpectedly.", "High", "Endpoint", "", "", "WIN-CLIENT-04", "", "Privilege Escalation", "T1548.002"),
            ("Suspicious File Download", "A newly registered domain delivered an executable archive.", "Medium", "Web Proxy", "10.10.20.32", "", "WIN-CLIENT-03", "", "File Download", "T1204.002"),
            ("DNS Query Anomaly", "High-volume queries for randomized subdomains observed.", "Medium", "DNS", "10.10.20.17", "", "WIN-CLIENT-17", "", "DNS Anomaly", "T1071.001"),
            ("Firewall Block", "Outbound traffic was blocked by an egress policy.", "Low", "Firewall", "10.10.20.28", "203.0.113.44", "", "", "Firewall Block", "T1071.001"),
            ("Unusual Login Location", "Successful login originated from an unusual network segment.", "Medium", "Identity", "10.10.40.8", "", "", "j.smith", "Authentication Success", "T1078"),
            ("Account Disabled", "An account was disabled after repeated policy violations.", "Low", "Identity", "", "", "", "m.lee", "Account Management", "T1070.008"),
            ("Endpoint Policy Violation", "Removable media policy was violated on a workstation.", "Medium", "Endpoint", "", "", "WIN-CLIENT-21", "", "Policy Violation", "T1204.002"),
            ("Possible Data Exfiltration", "An unusual volume of outbound traffic was observed.", "High", "Network Monitoring", "10.10.20.21", "203.0.113.80", "WIN-CLIENT-21", "", "Data Transfer", "T1567"),
        ]
        now = utc_now()
        for index, sample in enumerate(samples, 1):
            db.execute("INSERT INTO alerts (alert_id,title,description,severity,status,source,source_ip,destination_ip,hostname,username,event_type,mitre_technique,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (f"ALT-{1000 + index}", *sample[:2], sample[2], "Open" if index % 4 else "Investigating", *sample[3:], now, now))
    db.commit()


@app.before_request
def load_user():
    user_id = session.get("user_id")
    g.user = query("SELECT * FROM users WHERE id = ? AND active = 1", (user_id,), one=True) if user_id else None


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return response


@app.context_processor
def inject_globals():
    return {"current_user": g.get("user"), "techniques": TECHNIQUES, "now": utc_now()}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def roles_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not g.user:
                return redirect(url_for("login"))
            if g.user["role"] not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def get_alert(alert_id):
    alert = query("SELECT a.*, u.username AS analyst_name FROM alerts a LEFT JOIN users u ON a.assigned_to = u.id WHERE a.id = ?", (alert_id,), one=True)
    if not alert:
        abort(404)
    return alert


@app.route("/")
def index():
    return redirect(url_for("dashboard")) if g.user else redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        user = query("SELECT * FROM users WHERE username = ? AND active = 1", (username,), one=True)
        if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
            session.clear(); session["user_id"] = user["id"]
            g.user = user; log_activity("Login", "User", user["id"])
            return redirect(request.args.get("next") or url_for("dashboard"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    log_activity("Logout", "User", g.user["id"]); session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    metrics = {"total": query("SELECT COUNT(*) c FROM alerts", one=True)["c"], "critical": query("SELECT COUNT(*) c FROM alerts WHERE severity='Critical'", one=True)["c"], "high": query("SELECT COUNT(*) c FROM alerts WHERE severity='High'", one=True)["c"], "open": query("SELECT COUNT(*) c FROM alerts WHERE status IN ('Open','Investigating')", one=True)["c"], "incidents": query("SELECT COUNT(*) c FROM incidents WHERE status NOT IN ('Resolved','Closed')", one=True)["c"]}
    return render_template("dashboard.html", metrics=metrics, severity=chart_rows("severity"), sources=chart_rows("source"), statuses=chart_rows("status"), recent=query("SELECT * FROM alerts ORDER BY id DESC LIMIT 6"))


def chart_rows(column):
    return [dict(row) for row in query(f"SELECT {column} AS label, COUNT(*) AS value FROM alerts GROUP BY {column} ORDER BY value DESC")]


@app.route("/alerts")
@login_required
def alerts():
    search = request.args.get("q", "").strip(); severity = request.args.get("severity", ""); status = request.args.get("status", ""); source = request.args.get("source", "")
    sql = "SELECT a.*, u.username AS analyst_name FROM alerts a LEFT JOIN users u ON a.assigned_to=u.id WHERE 1=1"; args = []
    for field, value in (("a.severity", severity), ("a.status", status), ("a.source", source)):
        if value: sql += f" AND {field} = ?"; args.append(value)
    if search: sql += " AND (a.alert_id LIKE ? OR a.title LIKE ? OR a.hostname LIKE ? OR a.source_ip LIKE ?)"; args.extend([f"%{search}%"] * 4)
    sql += " ORDER BY a.id DESC"
    return render_template("alerts.html", alerts=query(sql, args), severities=SEVERITIES, statuses=ALERT_STATUSES, sources=query("SELECT DISTINCT source FROM alerts ORDER BY source"), filters={"q": search, "severity": severity, "status": status, "source": source})


@app.route("/alerts/<int:alert_id>")
@login_required
def alert_detail(alert_id):
    alert = get_alert(alert_id)
    related = query("SELECT DISTINCT a.* FROM alerts a WHERE a.id != ? AND ((a.hostname IS NOT NULL AND a.hostname != '' AND a.hostname = ?) OR (a.source_ip IS NOT NULL AND a.source_ip != '' AND a.source_ip = ?) OR (a.username IS NOT NULL AND a.username != '' AND a.username = ?)) ORDER BY a.created_at DESC", (alert_id, alert["hostname"], alert["source_ip"], alert["username"]))
    return render_template("alert_detail.html", alert=alert, notes=query("SELECT * FROM investigation_notes WHERE alert_id=? ORDER BY id DESC", (alert_id,)), related=related, activity=query("SELECT * FROM activity_logs WHERE target_type='Alert' AND target_id=? ORDER BY id DESC", (alert["id"],)), analysts=query("SELECT id,username FROM users WHERE role IN ('admin','analyst') AND active=1 ORDER BY username"))


@app.route("/alerts/<int:alert_id>/status", methods=["POST"])
@roles_required("admin", "analyst")
def alert_status(alert_id):
    alert = get_alert(alert_id); status = request.form.get("status", "")
    if status not in ALERT_STATUSES: abort(400)
    execute("UPDATE alerts SET status=?, updated_at=? WHERE id=?", (status, utc_now(), alert_id)); log_activity(f"Alert status changed to {status}", "Alert", alert_id); flash(f"{alert['alert_id']} marked {status}.", "success")
    return redirect(url_for("alert_detail", alert_id=alert_id))


@app.route("/alerts/<int:alert_id>/assign", methods=["POST"])
@roles_required("admin", "analyst")
def alert_assign(alert_id):
    get_alert(alert_id); analyst_id = request.form.get("analyst_id") or None
    if analyst_id and not query("SELECT id FROM users WHERE id=? AND role IN ('admin','analyst') AND active=1", (analyst_id,), one=True): abort(400)
    execute("UPDATE alerts SET assigned_to=?, updated_at=? WHERE id=?", (analyst_id, utc_now(), alert_id)); log_activity("Alert assigned", "Alert", alert_id)
    return redirect(url_for("alert_detail", alert_id=alert_id))


@app.route("/alerts/<int:alert_id>/notes", methods=["POST"])
@roles_required("admin", "analyst")
def add_note(alert_id):
    get_alert(alert_id); note = request.form.get("note", "").strip()
    if not note or len(note) > 2000: abort(400)
    execute("INSERT INTO investigation_notes (alert_id,username,note,created_at) VALUES (?,?,?,?)", (alert_id, g.user["username"], note, utc_now())); log_activity("Investigation note added", "Alert", alert_id)
    return redirect(url_for("alert_detail", alert_id=alert_id))


@app.route("/incidents")
@login_required
def incidents():
    return render_template("incidents.html", incidents=query("SELECT i.*, u.username AS analyst_name, COUNT(ia.alert_id) AS alert_count FROM incidents i LEFT JOIN users u ON i.assigned_to=u.id LEFT JOIN incident_alerts ia ON i.id=ia.incident_id GROUP BY i.id ORDER BY i.id DESC"))


@app.route("/incidents/create", methods=["GET", "POST"])
@roles_required("admin", "analyst")
def incident_create():
    if request.method == "POST":
        title = request.form.get("title", "").strip(); description = request.form.get("description", "").strip(); severity = request.form.get("severity", "")
        if not title or not description or severity not in SEVERITIES: abort(400)
        incident_id = f"INC-{1000 + (query('SELECT COUNT(*) c FROM incidents', one=True)['c'] + 1)}"
        new_id = execute("INSERT INTO incidents (incident_id,title,description,severity,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?)", (incident_id,title,description,severity,"Open",utc_now(),utc_now())); log_activity("Incident created", "Incident", new_id)
        return redirect(url_for("incident_detail", incident_id=new_id))
    return render_template("incident_form.html", severities=SEVERITIES)


@app.route("/incidents/<int:incident_id>")
@login_required
def incident_detail(incident_id):
    incident = query("SELECT i.*, u.username AS analyst_name FROM incidents i LEFT JOIN users u ON i.assigned_to=u.id WHERE i.id=?", (incident_id,), one=True)
    if not incident: abort(404)
    linked = query("SELECT a.* FROM alerts a JOIN incident_alerts ia ON ia.alert_id=a.id WHERE ia.incident_id=? ORDER BY a.id DESC", (incident_id,))
    return render_template("incident_detail.html", incident=incident, alerts=linked, all_alerts=query("SELECT id,alert_id,title FROM alerts WHERE id NOT IN (SELECT alert_id FROM incident_alerts WHERE incident_id=?) ORDER BY id DESC", (incident_id,)), analysts=query("SELECT id,username FROM users WHERE role IN ('admin','analyst') AND active=1"), statuses=INCIDENT_STATUSES)


@app.route("/incidents/<int:incident_id>/status", methods=["POST"])
@roles_required("admin", "analyst")
def incident_status(incident_id):
    if not query("SELECT id FROM incidents WHERE id=?", (incident_id,), one=True): abort(404)
    status = request.form.get("status", "")
    if status not in INCIDENT_STATUSES: abort(400)
    execute("UPDATE incidents SET status=?, updated_at=? WHERE id=?", (status,utc_now(),incident_id)); log_activity(f"Incident status changed to {status}", "Incident", incident_id)
    return redirect(url_for("incident_detail", incident_id=incident_id))


@app.route("/incidents/<int:incident_id>/assign", methods=["POST"])
@roles_required("admin", "analyst")
def incident_assign(incident_id):
    if not query("SELECT id FROM incidents WHERE id=?", (incident_id,), one=True): abort(404)
    analyst_id = request.form.get("analyst_id") or None; execute("UPDATE incidents SET assigned_to=?, updated_at=? WHERE id=?", (analyst_id,utc_now(),incident_id)); log_activity("Incident assigned", "Incident", incident_id)
    return redirect(url_for("incident_detail", incident_id=incident_id))


@app.route("/incidents/<int:incident_id>/alerts", methods=["POST"])
@roles_required("admin", "analyst")
def incident_add_alert(incident_id):
    if not query("SELECT id FROM incidents WHERE id=?", (incident_id,), one=True): abort(404)
    alert_id = request.form.get("alert_id")
    if not query("SELECT id FROM alerts WHERE id=?", (alert_id,), one=True): abort(400)
    execute("INSERT OR IGNORE INTO incident_alerts (incident_id,alert_id) VALUES (?,?)", (incident_id,alert_id)); log_activity("Alert linked to incident", "Incident", incident_id)
    return redirect(url_for("incident_detail", incident_id=incident_id))


@app.route("/analysts")
@roles_required("admin")
def analysts():
    return render_template("analysts.html", analysts=query("SELECT * FROM users ORDER BY username"))


@app.route("/analysts/create", methods=["POST"])
@roles_required("admin")
def analyst_create():
    username = request.form.get("username", "").strip(); password = request.form.get("password", ""); role = request.form.get("role", "analyst")
    if len(username) < 3 or len(password) < 8 or role not in ROLES: abort(400)
    try: new_id = execute("INSERT INTO users (username,password_hash,role,created_at) VALUES (?,?,?,?)", (username,generate_password_hash(password),role,utc_now()))
    except sqlite3.IntegrityError: flash("That username is already in use.", "error")
    else: log_activity("User created", "User", new_id)
    return redirect(url_for("analysts"))


@app.route("/analysts/<int:user_id>/role", methods=["POST"])
@roles_required("admin")
def analyst_role(user_id):
    if user_id == g.user["id"]: abort(400)
    role = request.form.get("role", "")
    if role not in ROLES: abort(400)
    execute("UPDATE users SET role=? WHERE id=?", (role,user_id)); log_activity("User role changed", "User", user_id)
    return redirect(url_for("analysts"))


@app.route("/analysts/<int:user_id>/toggle", methods=["POST"])
@roles_required("admin")
def analyst_toggle(user_id):
    if user_id == g.user["id"]: abort(400)
    execute("UPDATE users SET active=CASE active WHEN 1 THEN 0 ELSE 1 END WHERE id=?", (user_id,)); log_activity("User status changed", "User", user_id)
    return redirect(url_for("analysts"))


@app.route("/activity")
@roles_required("admin", "analyst")
def activity():
    return render_template("activity.html", activity=query("SELECT * FROM activity_logs ORDER BY id DESC LIMIT 200"))


@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html")


@app.errorhandler(403)
def forbidden(_error): return render_template("403.html"), 403

@app.errorhandler(404)
def not_found(_error): return render_template("404.html"), 404

@app.errorhandler(500)
def server_error(_error): return render_template("500.html"), 500


with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")
