import os
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory, session
from flask_cors import CORS
from dotenv import load_dotenv
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "student360_auth.db"
load_dotenv(BASE_DIR / ".env")

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32))
CORS(app, resources={r"/api/*": {"origins": "*"}})


CLASS_OPTIONS = ["CSE-A", "CSE-B", "CSE-C", "ECE-A", "IT-A", "IT-B"]
TEACHER_SUBJECTS = [
    "Mathematics",
    "Physics",
    "Chemistry",
    "English",
    "Computer Science",
    "Electronics",
    "Data Structures",
]


def get_db_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with get_db_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                full_name TEXT NOT NULL,
                password_hash TEXT,
                role TEXT NOT NULL,
                college TEXT NOT NULL,
                provider TEXT NOT NULL DEFAULT 'local',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.commit()


def normalize_role(role: str) -> str:
    role_value = (role or "").strip().lower()
    if role_value not in {"student", "teacher", "parent"}:
        return ""
    return role_value


def assign_profile(email: str, full_name: str) -> tuple[str, str]:
    seed_text = email or full_name or "student"
    hash_value = 0
    for char in seed_text:
        hash_value = (hash_value * 31 + ord(char)) & 0xFFFFFFFF

    assigned_class = CLASS_OPTIONS[hash_value % len(CLASS_OPTIONS)]
    teacher_subject = TEACHER_SUBJECTS[hash_value % len(TEACHER_SUBJECTS)]
    return assigned_class, teacher_subject


def build_user_payload(email: str, full_name: str, role: str, college: str) -> dict:
    assigned_class, teacher_subject = assign_profile(email, full_name)
    return {
        "email": email,
        "full_name": full_name,
        "role": role,
        "college": college,
        "assigned_class": assigned_class,
        "teacher_subject": teacher_subject,
    }


def validate_signup(data: dict) -> tuple[bool, str]:
    required_fields = ["fullName", "email", "password", "confirmPassword", "role", "college"]
    for field in required_fields:
        if not str(data.get(field, "")).strip():
            return False, f"{field} is required."

    if data["password"] != data["confirmPassword"]:
        return False, "Passwords do not match."

    if len(str(data["password"])) < 6:
        return False, "Password must be at least 6 characters long."

    role = normalize_role(str(data.get("role", "")))
    if not role:
        return False, "Please choose Student, Teacher, or Parent."

    return True, ""


def validate_login(data: dict) -> tuple[bool, str]:
    required_fields = ["email", "password", "role", "college"]
    for field in required_fields:
        if not str(data.get(field, "")).strip():
            return False, f"{field} is required."

    role = normalize_role(str(data.get("role", "")))
    if not role:
        return False, "Please choose Student, Teacher, or Parent."

    return True, ""


@app.post("/api/signup")
def api_signup():
    data = request.get_json(silent=True) or {}
    is_valid, error_message = validate_signup(data)
    if not is_valid:
        return jsonify({"error": error_message}), 400

    email = str(data["email"]).strip().lower()
    full_name = str(data["fullName"]).strip()
    role = normalize_role(str(data["role"]))
    college = str(data["college"]).strip()
    now = datetime.now(timezone.utc).isoformat()

    with get_db_connection() as connection:
        existing = connection.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if existing:
            return jsonify({"error": "Account already exists. Please Sign In instead."}), 409

        connection.execute(
            """
            INSERT INTO users (email, full_name, password_hash, role, college, provider, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 'local', ?, ?)
            """,
            (email, full_name, generate_password_hash(str(data["password"])), role, college, now, now),
        )
        connection.commit()

    session["student360_email"] = email
    user_payload = build_user_payload(email, full_name, role, college)
    return jsonify({"message": "Account created successfully.", "user": user_payload}), 201


@app.post("/api/login")
def api_login():
    data = request.get_json(silent=True) or {}
    is_valid, error_message = validate_login(data)
    if not is_valid:
        return jsonify({"error": error_message}), 400

    email = str(data["email"]).strip().lower()
    role = normalize_role(str(data["role"]))
    college = str(data["college"]).strip()

    with get_db_connection() as connection:
        row = connection.execute(
            "SELECT email, full_name, password_hash FROM users WHERE email = ?",
            (email,),
        ).fetchone()

    if not row:
        return jsonify({"error": "Account does not exist. Please Sign Up first."}), 404

    if not row["password_hash"]:
        return jsonify({"error": "This account has no password set. Please reset your password or sign up again."}), 400

    if not check_password_hash(row["password_hash"], str(data["password"])):
        return jsonify({"error": "Invalid email or password."}), 401

    session["student360_email"] = email

    with get_db_connection() as connection:
        connection.execute(
            "UPDATE users SET role = ?, college = ?, updated_at = ? WHERE email = ?",
            (role, college, datetime.now(timezone.utc).isoformat(), email),
        )
        connection.commit()

    user_payload = build_user_payload(email, row["full_name"], role, college)
    return jsonify({"message": "Login successful.", "user": user_payload})


@app.get("/health")
def health() -> tuple[dict, int]:
    return {"status": "ok"}, 200


@app.get("/")
def serve_index():
    return send_from_directory(BASE_DIR, "index.html")


@app.get("/<path:asset_path>")
def serve_assets(asset_path: str):
    return send_from_directory(BASE_DIR, asset_path)


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
