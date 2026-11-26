#!/usr/bin/env python3
"""Local CSU app server with username/password authentication."""

import argparse
import builtins
import email.message
import getpass
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import smtplib
import ssl
import sqlite3
import sys
import time
import unicodedata
import webbrowser
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

try:
    from openpyxl import Workbook, load_workbook
    from openpyxl.styles import Font
except ImportError:
    Workbook = None
    load_workbook = None
    Font = None


ROOT = Path(__file__).resolve().parent
APP_FILE = ROOT / "client-service-management.html"
LOGIN_FILE = ROOT / "login.html"
PUBLIC_FEEDBACK_FILE = ROOT / "public-feedback.html"
DATA_DIR = ROOT / "data"
DATABASE = DATA_DIR / "csu_auth.sqlite3"
WORKBOOK_TEMPLATE = ROOT / "Client_Service_Management_Forms.xlsx"
HOST = "127.0.0.1"
PORT = builtins.int(os.environ.get("CSU_PORT", "8765"))
SESSION_LIFETIME = 8 * 60 * 60
PASSWORD_ITERATIONS = 600_000
USERNAME_PATTERN = re.compile(r"^[a-z0-9._@-]{3,64}$")
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
FEEDBACK_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{40,64}$")
FEEDBACK_LIFETIME = 14 * 24 * 60 * 60
LOGIN_FAILURES = {}


@contextmanager
def connect_db():
    DATA_DIR.mkdir(exist_ok=True)
    db = sqlite3.connect(DATABASE, timeout=10)
    try:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        db.execute(
            """CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                disabled INTEGER NOT NULL DEFAULT 0,
                role TEXT NOT NULL DEFAULT 'staff'
            )"""
        )
        user_columns = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
        if "role" not in user_columns:
            db.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'staff'")
        db.execute("UPDATE users SET role = 'dcd' WHERE role = 'operator'")
        db.commit()
        db.execute(
            """CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            )"""
        )
        db.execute("CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at)")
        db.execute(
            """CREATE TABLE IF NOT EXISTS user_data (
                user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                payload TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            )"""
        )
        db.execute(
            """CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                client_name TEXT NOT NULL,
                email TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE (user_id, email)
            )"""
        )
        db.execute(
            """CREATE TABLE IF NOT EXISTS client_feedback (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                client_id INTEGER NOT NULL REFERENCES clients(id),
                client_name TEXT NOT NULL,
                client_email TEXT NOT NULL,
                complaint_id TEXT NOT NULL,
                complaint_date TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                sent_at TEXT,
                expires_at INTEGER NOT NULL,
                invitation_status TEXT NOT NULL
                    CHECK (invitation_status IN ('Pending', 'Sent', 'Completed', 'Expired')),
                submission_status TEXT NOT NULL DEFAULT 'Pending'
                    CHECK (submission_status IN ('Pending', 'Completed')),
                satisfaction_rating TEXT,
                staff_behaviour_rating TEXT,
                response_time_rating TEXT,
                comments TEXT,
                suggestions TEXT,
                submitted_at TEXT,
                UNIQUE (user_id, complaint_id)
            )"""
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS client_feedback_user_status "
            "ON client_feedback(user_id, invitation_status, submitted_at)"
        )
        with db:
            yield db
    finally:
        db.close()


def canonical_username(username):
    return unicodedata.normalize("NFKC", username.strip()).casefold()


def password_digest(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    result = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${salt.hex()}${result.hex()}"


def verify_password(password, encoded):
    try:
        algorithm, iterations, salt_hex, expected_hex = encoded.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
        )
        return hmac.compare_digest(actual.hex(), expected_hex)
    except (ValueError, TypeError):
        return False


def public_base_url():
    value = os.environ.get("CSU_PUBLIC_BASE_URL", "").strip().rstrip("/")
    if not value:
        raise RuntimeError(
            "Feedback email delivery is not configured. Set CSU_PUBLIC_BASE_URL to the "
            "HTTPS address clients can access."
        )
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        parsed.port
    except ValueError as exc:
        raise RuntimeError("CSU_PUBLIC_BASE_URL is not a valid URL.") from exc
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
        or (parsed.scheme != "https" and hostname not in ("localhost", "127.0.0.1"))
    ):
        raise RuntimeError("CSU_PUBLIC_BASE_URL must be an HTTPS URL (HTTP is allowed for localhost testing).")
    return value


def send_feedback_invitation(recipient, client_name, complaint_id, link):
    host = os.environ.get("CSU_SMTP_HOST", "").strip()
    username = os.environ.get("CSU_SMTP_USERNAME", "")
    password = os.environ.get("CSU_SMTP_PASSWORD", "")
    sender = os.environ.get("CSU_SMTP_FROM", "").strip()
    if not all((host, username, password, sender)):
        raise RuntimeError(
            "Feedback email delivery is not configured. Set CSU_SMTP_HOST, "
            "CSU_SMTP_USERNAME, CSU_SMTP_PASSWORD, and CSU_SMTP_FROM."
        )

    message = email.message.EmailMessage()
    message["Subject"] = f"Please share your feedback about complaint {complaint_id}"
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        f"""Dear {client_name},

Your complaint has been successfully resolved. We value your opinion and would appreciate your feedback on the service provided.

Please click the link below to complete our feedback form:
{link}

This secure link expires in 14 days and can be used once.

Thank you for helping us improve our services."""
    )

    port = int(os.environ.get("CSU_SMTP_PORT", "587"))
    timeout = 15
    if os.environ.get("CSU_SMTP_SSL", "").strip().casefold() in ("1", "true", "yes"):
        with smtplib.SMTP_SSL(
            host, port, timeout=timeout, context=ssl.create_default_context()
        ) as client:
            client.login(username, password)
            client.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=timeout) as client:
            client.ehlo()
            client.starttls(context=ssl.create_default_context())
            client.ehlo()
            client.login(username, password)
            client.send_message(message)


def create_user():
    username = canonical_username(input("Username (3-64 letters, digits, ., _, -, @): "))
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValueError("Use 3-64 letters, numbers, periods, underscores, hyphens, or @.")
    display_name = input("Display name: ").strip()
    if not display_name or len(display_name) > 100:
        raise ValueError("Display name is required and must be at most 100 characters.")
    password = getpass.getpass("Password (at least 12 characters): ")
    if len(password) < 12 or len(password) > 1024:
        raise ValueError("Choose a password between 12 and 1024 characters.")
    confirmation = getpass.getpass("Confirm password: ")
    if not hmac.compare_digest(password, confirmation):
        raise ValueError("Passwords do not match.")

    with connect_db() as db:
        try:
            role = (
                "dcd"
                if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
                else "staff"
            )
            db.execute(
                "INSERT INTO users (username, display_name, password_hash, created_at, role) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    username,
                    display_name,
                    password_digest(password),
                    datetime.now(timezone.utc).isoformat(),
                    role,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ValueError("That username already exists.") from exc
    print(
        f"{role.title()} account created for {username}. "
        "No password was displayed or saved in plain text."
    )


def reset_password():
    username = canonical_username(input("Username for password reset: "))
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValueError("Use 3-64 letters, numbers, periods, underscores, hyphens, or @.")

    with connect_db() as db:
        user = db.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
    if not user:
        raise ValueError("No account exists with that username.")

    password = getpass.getpass("New password (at least 12 characters): ")
    if len(password) < 12 or len(password) > 1024:
        raise ValueError("Choose a password between 12 and 1024 characters.")
    confirmation = getpass.getpass("Confirm new password: ")
    if not hmac.compare_digest(password, confirmation):
        raise ValueError("Passwords do not match.")

    with connect_db() as db:
        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (password_digest(password), user["id"]),
        )
        db.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))
    print("Password updated. The account's existing sessions have been signed out.")


def set_template_value(sheet, cell, value):
    if value is not None and value != "":
        sheet[cell] = value


def append_register_sheet(workbook, title, headers, rows):
    sheet = workbook.create_sheet(title)
    sheet.append(headers)
    for row in rows:
        sheet.append(row)
    sheet.freeze_panes = "A2"
    sheet.auto_filter.ref = sheet.dimensions


CASE_WORKBOOK_COLUMNS = [
    ("Reference", "id"),
    ("Type", "type"),
    ("Received date", "date"),
    ("Client / institution", "client"),
    ("Contact details", "contact"),
    ("Registered email", "email"),
    ("Age bracket", "age"),
    ("Gender", "gender"),
    ("Disability", "disability"),
    ("Disability type", "disabilityType"),
    ("District", "district"),
    ("Community / location", "location"),
    ("Channel", "channel"),
    ("Department / Unit", "department"),
    ("Action officer", "officer"),
    ("Follow-up due date", "due"),
    ("Resolved date", "resolvedDate"),
    ("Closed date", "closedDate"),
    ("Status", "status"),
    ("Preferred feedback method", "feedbackMethod"),
    ("Brief", "summary"),
    ("Actions / updates", "actions"),
    ("Outcome / remarks", "remarks"),
    ("Client signature", "signature-case-client-text"),
    ("CSU officer signature", "signature-case-csu-officer-text"),
    ("Administrative head signature", "signature-case-administrative-head-text"),
    ("Action officer signature", "signature-case-action-officer-text"),
    ("Created", "created"),
    ("Last updated", "updated"),
]


def create_case_workbook(cases):
    if Workbook is None:
        raise RuntimeError("The Excel export dependency is not installed.")

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Case Register"
    sheet.append([label for label, _key in CASE_WORKBOOK_COLUMNS])
    for case in cases:
        values = []
        for _label, key in CASE_WORKBOOK_COLUMNS:
            value = case.get(key)
            if key == "resolvedDate" and not value and case.get("status") == "Resolved":
                value = case.get("closedDate") or case.get("updated") or case.get("date")
            values.append(
                json.dumps(value, ensure_ascii=False)
                if isinstance(value, (dict, list))
                else "" if value is None
                else str(value)
            )
        sheet.append(values)
    for cell in sheet[1]:
        cell.font = Font(bold=True)
    for row in sheet.iter_rows():
        for cell in row:
            if isinstance(cell.value, str):
                cell.data_type = "s"
    sheet.freeze_panes = "A2"
    sheet.auto_filter.ref = sheet.dimensions
    output = io.BytesIO()
    workbook.save(output)
    return output.getvalue()


def create_export_workbook(payload):
    if load_workbook is None:
        raise RuntimeError("The Excel export dependency is not installed.")
    if not WORKBOOK_TEMPLATE.is_file():
        raise RuntimeError("The supplied Excel workbook template is unavailable.")

    workbook = load_workbook(WORKBOOK_TEMPLATE)
    cases = payload.get("cases") or []
    visitors = payload.get("visitors") or []
    feedback = payload.get("feedback") or []
    client_feedback = payload.get("clientFeedback") or []
    schedules = payload.get("schedules") or []

    complaint = next((item for item in cases if item.get("type") == "Complaint"), None)
    if complaint:
        sheet = workbook["A Complaint Form"]
        set_template_value(sheet, "C3", complaint.get("institution"))
        set_template_value(sheet, "G3", complaint.get("date"))
        set_template_value(sheet, "C4", complaint.get("client"))
        set_template_value(sheet, "G4", complaint.get("contact"))
        set_template_value(sheet, "C5", complaint.get("age"))
        set_template_value(sheet, "G5", complaint.get("channel"))
        set_template_value(sheet, "C6", complaint.get("gender"))
        set_template_value(sheet, "G6", complaint.get("disability"))
        set_template_value(sheet, "A8", complaint.get("summary"))
        set_template_value(sheet, "C16", complaint.get("writtenBy"))
        set_template_value(sheet, "E16", complaint.get("signature-case-client-text"))
        set_template_value(sheet, "C17", complaint.get("signature-case-csu-officer-text"))
        set_template_value(sheet, "A20", complaint.get("remarks"))
        set_template_value(sheet, "C23", complaint.get("date"))
        set_template_value(sheet, "E23", complaint.get("signature-case-administrative-head-text"))

    enquiry = next((item for item in cases if item.get("type") == "Enquiry"), None)
    if enquiry:
        sheet = workbook["D Client Enquiry"]
        set_template_value(sheet, "C3", enquiry.get("institution"))
        set_template_value(sheet, "G3", enquiry.get("date"))
        set_template_value(sheet, "C4", enquiry.get("client"))
        set_template_value(sheet, "G4", enquiry.get("contact"))
        set_template_value(sheet, "C5", enquiry.get("age"))
        set_template_value(sheet, "G5", enquiry.get("channel"))
        set_template_value(sheet, "C6", enquiry.get("gender"))
        set_template_value(sheet, "G6", enquiry.get("disability"))
        set_template_value(sheet, "A8", enquiry.get("summary"))
        set_template_value(sheet, "C16", enquiry.get("writtenBy"))
        set_template_value(sheet, "E16", enquiry.get("signature-case-client-text"))
        set_template_value(sheet, "C17", enquiry.get("signature-case-csu-officer-text"))
        set_template_value(sheet, "A20", enquiry.get("remarks"))
        set_template_value(sheet, "C23", enquiry.get("date"))
        set_template_value(sheet, "E23", enquiry.get("signature-case-administrative-head-text"))

    visitor_sheet = workbook["G Visitors Log"]
    for row_number, visitor in enumerate(visitors, start=5):
        if row_number > visitor_sheet.max_row:
            visitor_sheet.insert_rows(row_number)
        values = [
            visitor.get("name"),
            visitor.get("contact"),
            visitor.get("location"),
            visitor.get("gender"),
            visitor.get("vulnerability"),
            visitor.get("purpose"),
            visitor.get("timeIn"),
            visitor.get("timeOut"),
            visitor.get("date"),
        ]
        for column, value in enumerate(values, start=1):
            if value is not None:
                visitor_sheet.cell(row_number, column).value = value

    if feedback:
        latest_feedback = feedback[0]
        sheet = workbook["F Customer Satisfaction"]
        set_template_value(sheet, "C3", latest_feedback.get("institution"))
        set_template_value(sheet, "G3", latest_feedback.get("date"))
        set_template_value(sheet, "C4", latest_feedback.get("client"))
        set_template_value(sheet, "G4", latest_feedback.get("contact"))
        set_template_value(sheet, "C5", latest_feedback.get("age"))
        set_template_value(sheet, "G5", latest_feedback.get("gender"))
        set_template_value(sheet, "C6", latest_feedback.get("disability"))
        set_template_value(sheet, "C16", latest_feedback.get("comment"))
        rating_columns = {
            "Strongly Agree": 2,
            "Agree": 3,
            "Disagree": 4,
            "Strongly Disagree": 5,
        }
        for rating_row, rating in enumerate(latest_feedback.get("ratings") or [], start=9):
            if rating_row <= 15:
                column = rating_columns.get(rating.get("rating"))
                if column:
                    sheet.cell(rating_row, column).value = "✓"
                sheet.cell(rating_row, 6).value = rating.get("remarks")

    append_register_sheet(
        workbook,
        "Case Register",
        [
            "Reference", "Type", "Received date", "Client / institution",
            "Contact details", "Age bracket", "Gender", "Disability", "District",
            "Location", "Channel", "Department / Unit", "Action officer",
            "Due date", "Resolved date", "Status", "Brief", "Actions / updates",
            "Outcome / remarks",
        ],
        [
            [
                item.get("id"), item.get("type"), item.get("date"),
                item.get("client"), item.get("contact"), item.get("age"),
                item.get("gender"), item.get("disability"), item.get("district"),
                item.get("location"), item.get("channel"), item.get("department"),
                item.get("officer"), item.get("due"),
                item.get("resolvedDate") or (
                    item.get("closedDate") or item.get("updated") or item.get("date")
                    if item.get("status") == "Resolved"
                    else None
                ),
                item.get("status"), item.get("summary"), item.get("actions"),
                item.get("remarks"),
            ]
            for item in cases
        ],
    )
    append_register_sheet(
        workbook,
        "Schedules",
        ["Department / Unit", "Category", "Monthly workload", "Minimum staff", "Maximum staff"],
        [[item.get("department"), item.get("category"), item.get("workload"), item.get("minimum"), item.get("maximum")] for item in schedules],
    )
    append_register_sheet(
        workbook,
        "Client Feedback",
        [
            "Feedback ID",
            "Client ID",
            "Client Name",
            "Complaint ID",
            "Date Sent",
            "Invitation Status",
            "Submission Status",
            "Satisfaction Rating",
            "Staff Behaviour Rating",
            "Response Time Rating",
            "Comments",
            "Suggestions",
            "Date Submitted",
        ],
        [
            [
                item.get("id"),
                item.get("client_id"),
                item.get("client_name"),
                item.get("complaint_id"),
                item.get("sent_at"),
                item.get("invitation_status"),
                item.get("submission_status"),
                item.get("satisfaction_rating"),
                item.get("staff_behaviour_rating"),
                item.get("response_time_rating"),
                item.get("comments"),
                item.get("suggestions"),
                item.get("submitted_at"),
            ]
            for item in client_feedback
        ],
    )

    output = io.BytesIO()
    workbook.save(output)
    return output.getvalue()


class CSURequestHandler(BaseHTTPRequestHandler):
    server_version = "CSUApp"
    sys_version = ""

    def log_message(self, _format, *_args):
        return

    def send_security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; connect-src 'self'; "
            "img-src 'self' data:; object-src 'none'; base-uri 'self'; "
            "frame-ancestors 'none'",
        )
        if self.server.scheme == "https":
            self.send_header("Strict-Transport-Security", "max-age=31536000")

    def send_json(self, status, payload, extra_headers=None):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_security_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def send_html(self):
        try:
            content = APP_FILE.read_bytes()
        except OSError:
            self.send_json(500, {"error": "The CSU application file is unavailable."})
            return
        self.send_response(200)
        self.send_security_headers()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def send_login_html(self):
        try:
            content = LOGIN_FILE.read_bytes()
        except OSError:
            self.send_json(500, {"error": "The CSU sign-in page is unavailable."})
            return
        self.send_response(200)
        self.send_security_headers()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length < 1 or length > 8192:
            return None
        try:
            data = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        return data if isinstance(data, dict) else None

    def origin_is_local(self):
        origin = self.headers.get("Origin")
        if not origin:
            return False
        parsed = urlsplit(origin)
        host = self.headers.get("Host", "")
        if parsed.netloc.casefold() != host.casefold():
            return False
        allowed_local = {
            f"{HOST}:{PORT}".casefold(),
            f"localhost:{PORT}".casefold(),
        }
        if host.casefold() in allowed_local and parsed.scheme == "http":
            return True
        try:
            public = urlsplit(public_base_url())
        except RuntimeError:
            return False
        return (
            parsed.netloc.casefold() == public.netloc.casefold()
            and parsed.scheme == public.scheme
        )

    def session_cookie(self, token, max_age):
        parts = [
            f"csu_session={token}",
            "Path=/",
            "HttpOnly",
            "SameSite=Strict",
            f"Max-Age={max_age}",
        ]
        if self.server.scheme == "https":
            parts.append("Secure")
        return "; ".join(parts)

    def authenticated_user(self):
        cookie_header = self.headers.get("Cookie", "")
        token = None
        for item in cookie_header.split(";"):
            key, separator, value = item.strip().partition("=")
            if separator and key == "csu_session":
                token = value
                break
        if not token or len(token) > 128:
            return None
        digest = hashlib.sha256(token.encode("ascii", "ignore")).hexdigest()
        now = int(time.time())
        with connect_db() as db:
            db.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
            row = db.execute(
                """SELECT users.id, users.username, users.display_name, users.role
                   FROM sessions JOIN users ON users.id = sessions.user_id
                   WHERE sessions.token_hash = ? AND sessions.expires_at > ?
                     AND users.disabled = 0""",
                (digest, now),
            ).fetchone()
        return dict(row) if row else None

    def do_GET(self):
        path = urlsplit(self.path).path
        if path.startswith("/feedback/"):
            token = path[len("/feedback/"):]
            if not FEEDBACK_TOKEN_PATTERN.fullmatch(token):
                self.send_json(404, {"error": "This feedback link is invalid."})
                return
            try:
                content = PUBLIC_FEEDBACK_FILE.read_bytes()
            except OSError:
                self.send_json(500, {"error": "The client feedback form is unavailable."})
                return
            self.send_response(200)
            self.send_security_headers()
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return
        if path.startswith("/api/public-feedback/"):
            token = path[len("/api/public-feedback/"):]
            self.handle_public_feedback(token)
            return
        if path == "/api/admin/feedback":
            user = self.authenticated_user()
            if not user:
                self.send_json(401, {"error": "Sign in required."})
                return
            self.handle_admin_feedback(user)
            return
        if path == "/bia-west-district-assembly.jpg":
            try:
                content = (ROOT / "bia-west-district-assembly.jpg").read_bytes()
            except OSError:
                self.send_json(404, {"error": "Identity image not found."})
                return
            self.send_response(200)
            self.send_security_headers()
            self.send_header("Content-Type", "image/jpeg")
            self.send_header("Cache-Control", "public, max-age=86400")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return
        if path == "/api/session":
            with connect_db() as db:
                configured = db.execute(
                    "SELECT EXISTS(SELECT 1 FROM users)"
                ).fetchone()[0]
            user = self.authenticated_user()
            self.send_json(
                200,
                {
                    "authenticated": bool(user),
                    "user": user,
                    "configured": bool(configured),
                },
            )
            return
        if path == "/api/data":
            user = self.authenticated_user()
            if not user:
                self.send_json(401, {"error": "Sign in required."})
                return
            with connect_db() as db:
                row = db.execute(
                    "SELECT payload FROM user_data WHERE user_id = ?",
                    (user["id"],),
                ).fetchone()
            payload = json.loads(row["payload"]) if row else {
                "cases": [],
                "visitors": [],
                "feedback": [],
                "schedules": [],
            }
            self.send_json(200, payload)
            return
        if path in ("/", "/client-service-management.html"):
            if self.authenticated_user():
                self.send_html()
            else:
                self.send_login_html()
            return
        if path in ("/login", "/login.html"):
            if self.authenticated_user():
                self.send_response(303)
                self.send_header("Location", "/")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
            else:
                self.send_login_html()
            return
        self.send_json(404, {"error": "Not found."})

    def do_POST(self):
        path = urlsplit(self.path).path
        if path not in (
            "/api/login",
            "/api/logout",
            "/api/setup",
            "/api/signup",
            "/api/data",
            "/api/export-workbook",
            "/api/export-cases-workbook",
            "/api/feedback/website",
            "/api/admin/feedback/invite",
            "/api/public-feedback/submit",
        ):
            self.send_json(404, {"error": "Not found."})
            return
        if not self.origin_is_local():
            self.send_json(403, {"error": "Request origin was rejected."})
            return

        if path == "/api/public-feedback/submit":
            self.handle_feedback_submission()
        elif path == "/api/admin/feedback/invite":
            self.handle_feedback_invitation()
        elif path == "/api/login":
            self.handle_login()
        elif path == "/api/setup":
            self.handle_setup()
        elif path == "/api/signup":
            self.handle_signup()
        elif path == "/api/data":
            self.handle_data()
        elif path == "/api/export-workbook":
            self.handle_export_workbook()
        elif path == "/api/export-cases-workbook":
            self.handle_export_cases_workbook()
        elif path == "/api/feedback/website":
            self.handle_feedback_website()
        else:
            self.handle_logout()

    def handle_admin_feedback(self, user):
        now = int(time.time())
        with connect_db() as db:
            db.execute(
                """UPDATE client_feedback SET invitation_status = 'Expired'
                   WHERE user_id = ? AND invitation_status IN ('Pending', 'Sent')
                     AND expires_at <= ?""",
                (user["id"], now),
            )
            rows = db.execute(
                """SELECT id, client_id, client_name, complaint_id, complaint_date, created_at,
                          sent_at, expires_at, invitation_status, submission_status,
                          satisfaction_rating, staff_behaviour_rating,
                          response_time_rating, comments, suggestions, submitted_at
                   FROM client_feedback WHERE user_id = ?
                   ORDER BY created_at DESC""",
                (user["id"],),
            ).fetchall()
        feedback = [dict(row) for row in rows]
        completed = [row for row in feedback if row["submission_status"] == "Completed"]
        satisfaction_values = {
            "Very Satisfied": 5,
            "Satisfied": 4,
            "Neutral": 3,
            "Dissatisfied": 2,
            "Very Dissatisfied": 1,
        }
        satisfaction = [
            satisfaction_values[row["satisfaction_rating"]]
            for row in completed
            if row["satisfaction_rating"] in satisfaction_values
        ]
        satisfied = sum(
            row["satisfaction_rating"] in ("Very Satisfied", "Satisfied")
            for row in completed
        )
        self.send_json(
            200,
            {
                "feedback": feedback,
                "stats": {
                    "sent": sum(bool(row["sent_at"]) for row in feedback),
                    "received": len(completed),
                    "pending": sum(row["invitation_status"] == "Sent" for row in feedback),
                    "completed": len(completed),
                    "average_satisfaction": (
                        round(sum(satisfaction) / len(satisfaction), 1)
                        if satisfaction
                        else None
                    ),
                    "satisfied_percentage": (
                        round(satisfied * 100 / len(completed)) if completed else None
                    ),
                },
            },
        )

    def handle_feedback_invitation(self):
        user = self.authenticated_user()
        if not user:
            self.send_json(401, {"error": "Sign in required."})
            return
        data = self.read_json()
        complaint_id = data.get("complaint_id") if data else None
        if not isinstance(complaint_id, str) or not complaint_id.strip():
            self.send_json(400, {"error": "Choose a complaint to invite for feedback."})
            return

        with connect_db() as db:
            row = db.execute(
                "SELECT payload FROM user_data WHERE user_id = ?", (user["id"],)
            ).fetchone()
        try:
            state = json.loads(row["payload"]) if row else {}
        except (json.JSONDecodeError, TypeError):
            self.send_json(500, {"error": "The saved case register could not be read."})
            return
        case = next(
            (
                item
                for item in state.get("cases", [])
                if isinstance(item, dict) and item.get("id") == complaint_id
            ),
            None,
        )
        if not case or case.get("type") != "Complaint" or case.get("status") != "Resolved":
            self.send_json(
                409,
                {"error": "Feedback invitations are available only for resolved complaints."},
            )
            return
        client_name = str(case.get("client") or "").strip()
        client_email = str(case.get("email") or "").strip()
        if not EMAIL_PATTERN.fullmatch(client_email) or len(client_email) > 254:
            contact = str(case.get("contact") or "")
            client_email = next(
                (
                    address
                    for match in re.finditer(r"[^,\s;<>]+@[^,\s;<>]+", contact)
                    for address in (match.group(0).rstrip(".,;:!?"),)
                    if EMAIL_PATTERN.fullmatch(address) and len(address) <= 254
                ),
                "",
            )
        if not client_name or len(client_name) > 200:
            self.send_json(400, {"error": "Add the client's name to the complaint before inviting them."})
            return
        if not EMAIL_PATTERN.fullmatch(client_email) or len(client_email) > 254:
            self.send_json(
                400,
                {"error": "Add a valid client email address to the complaint before inviting them."},
            )
            return

        try:
            base_url = public_base_url()
        except RuntimeError as exc:
            self.send_json(503, {"error": str(exc)})
            return
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        now = int(time.time())
        expires_at = now + FEEDBACK_LIFETIME
        created_at = datetime.now(timezone.utc).isoformat()
        try:
            with connect_db() as db:
                existing = db.execute(
                    """SELECT id, invitation_status FROM client_feedback
                       WHERE user_id = ? AND complaint_id = ?""",
                    (user["id"], complaint_id),
                ).fetchone()
                if existing and existing["invitation_status"] == "Completed":
                    self.send_json(
                        409,
                        {"error": "Feedback has already been submitted for this complaint."},
                    )
                    return
                normalized_email = client_email.casefold()
                client = db.execute(
                    "SELECT id FROM clients WHERE user_id = ? AND email = ?",
                    (user["id"], normalized_email),
                ).fetchone()
                if client:
                    client_id = client["id"]
                    db.execute(
                        "UPDATE clients SET client_name = ? WHERE id = ? AND user_id = ?",
                        (client_name, client_id, user["id"]),
                    )
                else:
                    cursor = db.execute(
                        """INSERT INTO clients (user_id, client_name, email, created_at)
                           VALUES (?, ?, ?, ?)""",
                        (user["id"], client_name, normalized_email, created_at),
                    )
                    client_id = cursor.lastrowid
                if existing:
                    feedback_id = existing["id"]
                    db.execute(
                        """UPDATE client_feedback
                           SET client_id = ?, client_name = ?, client_email = ?, complaint_date = ?,
                               token_hash = ?, sent_at = NULL, expires_at = ?,
                               invitation_status = 'Pending', submission_status = 'Pending'
                           WHERE id = ? AND user_id = ?""",
                        (
                            client_id,
                            client_name,
                            client_email,
                            str(case.get("date") or ""),
                            token_hash,
                            expires_at,
                            feedback_id,
                            user["id"],
                        ),
                    )
                else:
                    cursor = db.execute(
                        """INSERT INTO client_feedback
                           (user_id, client_id, client_name, client_email, complaint_id,
                            complaint_date, token_hash, created_at, expires_at,
                            invitation_status)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending')""",
                        (
                            user["id"],
                            client_id,
                            client_name,
                            client_email,
                            complaint_id,
                            str(case.get("date") or ""),
                            token_hash,
                            created_at,
                            expires_at,
                        ),
                    )
                    feedback_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            self.send_json(409, {"error": "A feedback invitation already exists for this complaint."})
            return

        link = f"{base_url}/feedback/{token}"
        try:
            send_feedback_invitation(client_email, client_name, complaint_id, link)
        except (OSError, RuntimeError, ValueError, smtplib.SMTPException) as exc:
            print(
                f"Feedback email delivery failed for invitation {feedback_id}: "
                f"{type(exc).__name__}",
                file=sys.stderr,
            )
            self.send_json(
                502,
                {
                    "error": (
                        "The invitation is saved as Pending, but email delivery failed. "
                        "Check the SMTP settings and retry the invitation."
                    ),
                    "status": "Pending",
                },
            )
            return
        sent_at = datetime.now(timezone.utc).isoformat()
        with connect_db() as db:
            db.execute(
                """UPDATE client_feedback SET invitation_status = 'Sent', sent_at = ?
                   WHERE id = ? AND user_id = ?""",
                (sent_at, feedback_id, user["id"]),
            )
        self.send_json(201, {"sent": True, "status": "Sent"})

    def handle_public_feedback(self, token):
        if not FEEDBACK_TOKEN_PATTERN.fullmatch(token):
            self.send_json(404, {"error": "This feedback link is invalid."})
            return
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        now = int(time.time())
        with connect_db() as db:
            row = db.execute(
                """SELECT client_name, complaint_id, complaint_date, expires_at,
                          invitation_status, submission_status
                   FROM client_feedback WHERE token_hash = ?""",
                (token_hash,),
            ).fetchone()
            if row and row["invitation_status"] in ("Pending", "Sent") and row["expires_at"] <= now:
                db.execute(
                    "UPDATE client_feedback SET invitation_status = 'Expired' WHERE token_hash = ?",
                    (token_hash,),
                )
                row = dict(row)
                row["invitation_status"] = "Expired"
        if not row:
            self.send_json(404, {"error": "This feedback link is invalid."})
            return
        if row["submission_status"] == "Completed":
            self.send_json(409, {"error": "Feedback has already been submitted using this link."})
            return
        if row["invitation_status"] == "Expired":
            self.send_json(410, {"error": "This feedback link has expired. Please contact the Client Service Unit."})
            return
        if row["invitation_status"] != "Sent":
            self.send_json(409, {"error": "This feedback invitation is not available yet."})
            return
        self.send_json(
            200,
            {
                "client_name": row["client_name"],
                "complaint_id": row["complaint_id"],
                "complaint_date": row["complaint_date"],
                "expires_at": row["expires_at"],
            },
        )

    def handle_feedback_submission(self):
        data = self.read_json()
        if not data:
            self.send_json(400, {"error": "Complete the feedback form before submitting."})
            return
        token = data.get("token")
        if not isinstance(token, str) or not FEEDBACK_TOKEN_PATTERN.fullmatch(token):
            self.send_json(404, {"error": "This feedback link is invalid."})
            return
        valid_ratings = {
            "satisfaction_rating": {
                "Very Satisfied", "Satisfied", "Neutral", "Dissatisfied", "Very Dissatisfied"
            },
            "staff_behaviour_rating": {"Excellent", "Good", "Fair", "Poor"},
            "response_time_rating": {"Excellent", "Good", "Fair", "Poor"},
        }
        for field, choices in valid_ratings.items():
            if data.get(field) not in choices:
                self.send_json(400, {"error": "Choose a valid option for every rating."})
                return
        text_fields = {}
        for field in ("comments", "suggestions"):
            value = data.get(field, "")
            if not isinstance(value, str) or len(value) > 3000:
                self.send_json(400, {"error": "Comments and suggestions must be 3,000 characters or fewer."})
                return
            text_fields[field] = value.strip()

        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        now = int(time.time())
        submitted_at = datetime.now(timezone.utc).isoformat()
        with connect_db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """SELECT id, expires_at, invitation_status, submission_status
                   FROM client_feedback WHERE token_hash = ?""",
                (token_hash,),
            ).fetchone()
            if not row:
                self.send_json(404, {"error": "This feedback link is invalid."})
                return
            if row["submission_status"] == "Completed":
                self.send_json(409, {"error": "Feedback has already been submitted using this link."})
                return
            if row["expires_at"] <= now:
                db.execute(
                    "UPDATE client_feedback SET invitation_status = 'Expired' WHERE id = ?",
                    (row["id"],),
                )
                self.send_json(410, {"error": "This feedback link has expired. Please contact the Client Service Unit."})
                return
            if row["invitation_status"] != "Sent":
                self.send_json(409, {"error": "This feedback invitation is not available yet."})
                return
            db.execute(
                """UPDATE client_feedback
                   SET satisfaction_rating = ?, staff_behaviour_rating = ?,
                       response_time_rating = ?, comments = ?, suggestions = ?,
                       submitted_at = ?, invitation_status = 'Completed',
                       submission_status = 'Completed'
                   WHERE id = ? AND submission_status = 'Pending'""",
                (
                    data["satisfaction_rating"],
                    data["staff_behaviour_rating"],
                    data["response_time_rating"],
                    text_fields["comments"],
                    text_fields["suggestions"],
                    submitted_at,
                    row["id"],
                ),
            )
        self.send_json(200, {"submitted": True, "message": "Thank you for your feedback. Your response has been successfully submitted."})

    def handle_export_workbook(self):
        user = self.authenticated_user()
        if not user:
            self.send_json(401, {"error": "Sign in required."})
            return
        with connect_db() as db:
            row = db.execute(
                "SELECT payload FROM user_data WHERE user_id = ?",
                (user["id"],),
            ).fetchone()
        payload = json.loads(row["payload"]) if row else {}
        with connect_db() as db:
            db.execute(
                """UPDATE client_feedback SET invitation_status = 'Expired'
                   WHERE user_id = ? AND invitation_status IN ('Pending', 'Sent')
                     AND expires_at <= ?""",
                (user["id"], int(time.time())),
            )
            feedback_rows = db.execute(
                """SELECT id, client_id, client_name, complaint_id, sent_at,
                          invitation_status, submission_status, satisfaction_rating,
                          staff_behaviour_rating, response_time_rating, comments,
                          suggestions, submitted_at
                   FROM client_feedback WHERE user_id = ? ORDER BY created_at DESC""",
                (user["id"],),
            ).fetchall()
        payload["clientFeedback"] = [dict(item) for item in feedback_rows]
        try:
            content = create_export_workbook(payload)
        except (OSError, RuntimeError, ValueError) as exc:
            self.send_json(500, {"error": str(exc)})
            return
        filename = f"CSU-Client-Service-Management-{datetime.now().strftime('%Y-%m-%d')}.xlsx"
        self.send_response(200)
        self.send_security_headers()
        self.send_header(
            "Content-Type",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def handle_export_cases_workbook(self):
        user = self.authenticated_user()
        if not user:
            self.send_json(401, {"error": "Sign in required."})
            return

        data = None
        if self.headers.get("Content-Length", "0") != "0":
            data = self.read_json()
            if not data:
                self.send_json(400, {"error": "The case export request is invalid."})
                return
        case_id = data.get("case_id") if data else None
        if data and (
            not isinstance(case_id, str)
            or not case_id.strip()
        ):
            self.send_json(400, {"error": "Choose a case to export."})
            return

        with connect_db() as db:
            row = db.execute(
                "SELECT payload FROM user_data WHERE user_id = ?",
                (user["id"],),
            ).fetchone()
        try:
            payload = json.loads(row["payload"]) if row else {}
        except (json.JSONDecodeError, TypeError):
            self.send_json(500, {"error": "The saved case register could not be read."})
            return
        if not isinstance(payload, dict):
            self.send_json(500, {"error": "The saved case register is invalid."})
            return
        cases = payload.get("cases") or []
        if not isinstance(cases, list) or any(not isinstance(item, dict) for item in cases):
            self.send_json(500, {"error": "The saved case register is invalid."})
            return
        if case_id is not None:
            case = next((item for item in cases if item.get("id") == case_id), None)
            if not case:
                self.send_json(404, {"error": "That case could not be found in your register."})
                return
            cases = [case]

        try:
            content = create_case_workbook(cases)
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            self.send_json(500, {"error": str(exc)})
            return
        suffix = re.sub(r"[^A-Za-z0-9._-]", "_", case_id) if case_id else "Register"
        filename = f"CSU-Cases-{suffix}-{datetime.now().strftime('%Y-%m-%d')}.xlsx"
        self.send_response(200)
        self.send_security_headers()
        self.send_header(
            "Content-Type",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def handle_setup(self):
        data = self.read_json()
        if not data:
            self.send_json(400, {"error": "Enter DCD administrator account details."})
            return

        username = data.get("username")
        display_name = data.get("display_name")
        password = data.get("password")
        confirmation = data.get("confirmation")
        if not all(isinstance(value, str) for value in (username, display_name, password, confirmation)):
            self.send_json(400, {"error": "Complete all DCD administrator account fields."})
            return

        username = canonical_username(username)
        display_name = display_name.strip()
        if not USERNAME_PATTERN.fullmatch(username):
            self.send_json(
                400,
                {"error": "Username must be 3-64 characters using letters, numbers, ., _, -, or @."},
            )
            return
        if not display_name or len(display_name) > 100:
            self.send_json(400, {"error": "Enter a display name of at most 100 characters."})
            return
        if len(password) < 12 or len(password) > 1024:
            self.send_json(400, {"error": "Password must be between 12 and 1024 characters."})
            return
        if not hmac.compare_digest(password, confirmation):
            self.send_json(400, {"error": "The passwords do not match."})
            return

        now = int(time.time())
        token = secrets.token_urlsafe(32)
        try:
            with connect_db() as db:
                db.execute("BEGIN IMMEDIATE")
                if db.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
                    self.send_json(
                        409,
                        {"error": "The DCD administrator account has already been created. Please sign in."},
                    )
                    return
                cursor = db.execute(
                    """INSERT INTO users
                       (username, display_name, password_hash, created_at, role)
                       VALUES (?, ?, ?, ?, 'dcd')""",
                    (
                        username,
                        display_name,
                        password_digest(password),
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                db.execute(
                    """INSERT INTO sessions (token_hash, user_id, expires_at, created_at)
                       VALUES (?, ?, ?, ?)""",
                    (
                        hashlib.sha256(token.encode("ascii")).hexdigest(),
                        cursor.lastrowid,
                        now + SESSION_LIFETIME,
                        now,
                    ),
                )
        except sqlite3.IntegrityError:
            self.send_json(409,             {"error": "The DCD administrator account could not be created."})
            return
        self.send_json(
            201,
            {
                "authenticated": True,
                "user": {
                    "username": username,
                    "display_name": display_name,
                    "role": "dcd",
                },
            },
            {"Set-Cookie": self.session_cookie(token, SESSION_LIFETIME)},
        )

    def handle_signup(self):
        data = self.read_json()
        if not data:
            self.send_json(400, {"error": "Enter your account details."})
            return

        username = data.get("username")
        display_name = data.get("display_name")
        password = data.get("password")
        confirmation = data.get("confirmation")
        if not all(
            isinstance(value, str)
            for value in (username, display_name, password, confirmation)
        ):
            self.send_json(400, {"error": "Complete all account fields."})
            return

        username = canonical_username(username)
        display_name = display_name.strip()
        if not USERNAME_PATTERN.fullmatch(username):
            self.send_json(
                400,
                {"error": "Username must be 3-64 characters using letters, numbers, ., _, -, or @."},
            )
            return
        if not display_name or len(display_name) > 100:
            self.send_json(400, {"error": "Enter a display name of at most 100 characters."})
            return
        if len(password) < 12 or len(password) > 1024:
            self.send_json(400, {"error": "Password must be between 12 and 1024 characters."})
            return
        if not hmac.compare_digest(password, confirmation):
            self.send_json(400, {"error": "The passwords do not match."})
            return

        now = int(time.time())
        token = secrets.token_urlsafe(32)
        try:
            with connect_db() as db:
                db.execute("BEGIN IMMEDIATE")
                operator_exists = db.execute(
                    "SELECT EXISTS(SELECT 1 FROM users WHERE role = 'dcd' AND disabled = 0)"
                ).fetchone()[0]
                if not operator_exists:
                    self.send_json(
                        409,
                        {"error": "The DCD administrator must set up the first account before staff can sign up."},
                    )
                    return
                cursor = db.execute(
                    """INSERT INTO users
                       (username, display_name, password_hash, created_at, role)
                       VALUES (?, ?, ?, ?, 'staff')""",
                    (
                        username,
                        display_name,
                        password_digest(password),
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                db.execute(
                    """INSERT INTO sessions (token_hash, user_id, expires_at, created_at)
                       VALUES (?, ?, ?, ?)""",
                    (
                        hashlib.sha256(token.encode("ascii")).hexdigest(),
                        cursor.lastrowid,
                        now + SESSION_LIFETIME,
                        now,
                    ),
                )
        except sqlite3.IntegrityError:
            self.send_json(
                409,
                {"error": "That username is already in use. Choose another username."},
            )
            return
        self.send_json(
            201,
            {
                "authenticated": True,
                "user": {
                    "username": username,
                    "display_name": display_name,
                    "role": "staff",
                },
            },
            {"Set-Cookie": self.session_cookie(token, SESSION_LIFETIME)},
        )

    def handle_feedback_website(self):
        user = self.authenticated_user()
        if not user:
            self.send_json(401, {"error": "Sign in required."})
            return
        data = self.read_json()
        if not isinstance(data, dict) or not isinstance(data.get("ticket_id"), str):
            self.send_json(400, {"error": "A valid feedback Ticket ID is required."})
            return
        webhook = os.environ.get("BWDAS_FEEDBACK_WEBHOOK", "").strip()
        if not webhook:
            self.send_json(
                202,
                {
                    "queued": True,
                    "message": "Feedback was saved locally. Add BWDAS_FEEDBACK_WEBHOOK to send it to the official website automatically.",
                },
            )
            return
        try:
            body = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            request = urllib.request.Request(
                webhook,
                data=body,
                headers={"Content-Type": "application/json", "User-Agent": "BWDAS-CSM/1.0"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=12) as response:
                if response.status not in (200, 201, 202, 204):
                    raise RuntimeError(f"Official website returned HTTP {response.status}")
        except Exception as exc:
            self.send_json(
                502,
                {"queued": True, "error": f"The official website delivery failed: {exc}", "ticket_id": data["ticket_id"]},
            )
            return
        self.send_json(200, {"delivered": True, "ticket_id": data["ticket_id"]})

    def handle_data(self):
        user = self.authenticated_user()
        if not user:
            self.send_json(401, {"error": "Sign in required."})
            return

        data = self.read_json()
        if not data:
            self.send_json(400, {"error": "No CSU data supplied."})
            return
        payload = data.get("state") if isinstance(data, dict) and "state" in data else data
        if not isinstance(payload, dict):
            self.send_json(400, {"error": "The CSU data payload is invalid."})
            return

        allowed = {"cases", "visitors", "feedback", "schedules"}
        cleaned = {key: value for key, value in payload.items() if key in allowed}
        for key in allowed:
            cleaned.setdefault(key, [])
        try:
            encoded = json.dumps(cleaned, separators=(",", ":"), ensure_ascii=False)
        except (TypeError, ValueError):
            self.send_json(400, {"error": "The CSU data payload could not be saved."})
            return

        with connect_db() as db:
            db.execute(
                "INSERT INTO user_data (user_id, payload, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(user_id) DO UPDATE SET payload = excluded.payload, updated_at = excluded.updated_at",
                (user["id"], encoded, int(time.time())),
            )
        self.send_json(200, {"saved": True})

    def handle_login(self):
        address = self.client_address[0]
        now = time.time()
        data = self.read_json()
        if not data or not isinstance(data.get("username"), str) or not isinstance(
            data.get("password"), str
        ):
            self.send_json(400, {"error": "Enter a username and password."})
            return
        username = canonical_username(data["username"])
        password = data["password"]
        failure_key = (address, username)
        failure = LOGIN_FAILURES.get(failure_key)
        if failure and failure["blocked_until"] > now:
            wait = int(failure["blocked_until"] - now) + 1
            self.send_json(429, {"error": f"Too many attempts. Try again in {wait} seconds."})
            return

        if not USERNAME_PATTERN.fullmatch(username) or len(password) > 1024:
            self.record_login_failure(address, username, now)
            self.send_json(401, {"error": "Username or password is incorrect."})
            return

        with connect_db() as db:
            user = db.execute(
                """SELECT id, username, display_name, password_hash, role
                   FROM users WHERE username = ? AND disabled = 0""",
                (username,),
            ).fetchone()
            stored_hash = (
                user["password_hash"]
                if user
                else "pbkdf2_sha256$600000$00000000000000000000000000000000$"
                + ("00" * 32)
            )
            password_matches = verify_password(password, stored_hash)
            if not user or not password_matches:
                self.record_login_failure(address, username, now)
                self.send_json(401, {"error": "Username or password is incorrect."})
                return

            token = secrets.token_urlsafe(32)
            expires_at = int(now) + SESSION_LIFETIME
            db.execute(
                "INSERT INTO sessions (token_hash, user_id, expires_at, created_at) "
                "VALUES (?, ?, ?, ?)",
                (
                    hashlib.sha256(token.encode("ascii")).hexdigest(),
                    user["id"],
                    expires_at,
                    int(now),
                ),
            )
        LOGIN_FAILURES.pop(failure_key, None)
        self.send_json(
            200,
            {
                "authenticated": True,
                "user": {
                    "username": user["username"],
                    "display_name": user["display_name"],
                    "role": user["role"],
                },
            },
            {"Set-Cookie": self.session_cookie(token, SESSION_LIFETIME)},
        )

    @staticmethod
    def record_login_failure(address, username, now):
        key = (address, username)
        failure = LOGIN_FAILURES.get(key, {"count": 0, "started": now, "blocked_until": 0})
        if now - failure["started"] > 15 * 60:
            failure = {"count": 0, "started": now, "blocked_until": 0}
        failure["count"] += 1
        if failure["count"] >= 5:
            failure["blocked_until"] = now + 15 * 60
        LOGIN_FAILURES[key] = failure

    def handle_logout(self):
        user = self.authenticated_user()
        if user:
            cookie_header = self.headers.get("Cookie", "")
            token = next(
                (
                    item.strip().partition("=")[2]
                    for item in cookie_header.split(";")
                    if item.strip().partition("=")[0] == "csu_session"
                ),
                "",
            )
            digest = hashlib.sha256(token.encode("ascii", "ignore")).hexdigest()
            with connect_db() as db:
                db.execute("DELETE FROM sessions WHERE token_hash = ?", (digest,))
        self.send_json(
            200,
            {"authenticated": False},
            {"Set-Cookie": self.session_cookie("", 0)},
        )


def serve():
    if not APP_FILE.is_file() or not LOGIN_FILE.is_file() or not PUBLIC_FEEDBACK_FILE.is_file():
        raise FileNotFoundError("The application, sign-in, or client feedback page is missing.")
    with connect_db() as db:
        users_exist = db.execute("SELECT EXISTS(SELECT 1 FROM users)").fetchone()[0]
    if not users_exist:
        print("No DCD administrator account is set up. Create the first DCD account on the sign-in page.")
    server = ThreadingHTTPServer((HOST, PORT), CSURequestHandler)
    local_url = f"http://{HOST}:{PORT}/"
    try:
        url = public_base_url() + "/"
    except RuntimeError:
        url = local_url
    server.scheme = "https" if urlsplit(url).scheme == "https" else "http"
    print(f"CSU Client Service Management is available at {url}")
    if url != local_url:
        print(
            "The application server listens on 127.0.0.1; ensure the configured "
            "HTTPS reverse proxy routes to it."
        )
    else:
        print("This server is limited to this computer (127.0.0.1). Press Ctrl+C to stop.")
    try:
        webbrowser.open(url)
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping CSU server.")
    finally:
        server.server_close()


def main():
    parser = argparse.ArgumentParser(description="CSU Client Service Management server")
    parser.add_argument("command", choices=("serve", "create-user", "reset-password"))
    args = parser.parse_args()
    if args.command == "create-user":
        try:
            create_user()
        except (ValueError, EOFError) as exc:
            print(f"Could not create account: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
    elif args.command == "reset-password":
        try:
            reset_password()
        except (ValueError, EOFError) as exc:
            print(f"Could not reset password: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
    else:
        serve()


if __name__ == "__main__":
    main()
