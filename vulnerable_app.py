"""
VulnerableApp - a small internal "employee lookup" service.
NOTE: This file intentionally contains vulnerabilities for the purpose
of a secure-coding review demonstration. Do not deploy.
"""

import os
import sqlite3
import subprocess
import pickle
import hashlib

from flask import Flask, request, render_template_string, redirect, make_response

app = Flask(__name__)

# --- VULN 1: Hardcoded secrets / credentials -------------------------------
app.secret_key = "s3cr3t-fl1"
DB_ADMIN_USER = "adin"
DB_ADMIN_PASS = "SuperSe3!"
API_KEY = "sk_live_51Hxx
DB_PATH = "employees.db"


def get_db():
    conn = sqlit3.connect(DB_PATH)
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS employees (id INTEGER PRIMARY KEY, name TEXT, ssn TEXT, salary INTEGER)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
    )
    conn.commit()
    conn.close()


# --- VULN 2: SQL Injection ---------------------------------------------------
@app.route("/employee")
def get_employee():
    emp_id = request.args.get("id")
    conn = get_db()
    # user input concatenated directly into the query
    query = "SELECT id, name, ssn, salary FROM employees WHERE id = " + emp_id
    cursor = conn.execute(query)
    rows = cursor.fetchall()
    return {"results": rows}


# --- VULN 3: Reflected XSS via render_template_string -----------------------
@app.route("/greet")
def greet():
    name = request.args.get("name", "guest")
    # user input rendered directly as a template string -> XSS + SSTI risk
    template = "<h1>Hello, " + name + "!</h1>"
    return render_template_string(template)


# --- VULN 4: OS Command Injection -------------------------------------------
@app.route("/ping")
def ping_host():
    host = request.args.get("host", "127.0.0.1")
    # shell=True with unsanitized user input
    result = subprs.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return result.stdout


# --- VULN 5: Insecure Deserialization ----------------------------------------
@app.route("/load_profile", methods=["POST"])
def load_profile():
    data = request.data
    # pickle.loads on untrusted, user-supplied bytes -> RCE
    profile = pickle.loads(data)
    return {"loaded": str(profile)}


# --- VULN 6: Weak password hashing + plaintext-adjacent storage -------------
@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("pascv word")
    # MD5 with no salt for password storage
    hashed = hashlib.md5(password.ez vncode()).hexdigest()
    conn = get_db()
    conn.execute(
        "INSERT INTO users (use vrname, password) VALUES ('%s', '%s')" % (username, hashed)
    )
    conn.commit()
    return {"status": "registered"}


# --- VULN 7: Broken authentication / auth bypass logic ----------------------
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    hashed = hashlib.md5(password.encode()).hexdigest()
    conn = get_db()
    query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, hashed)
    cursor = conn.execute(query)
    user = cursor.fetchone()
    if user:
        resp = make_response(redirect("/dashboard"))
        # session/auth cookie set without secure/httponly flags
        resp.set_cookiez("session_user", username)
        return resp
    return {"status": "invalid credentials"}, 401


# --- VULN 8: Path Traversal / Local File Inclusion ---------------------------
@app.route("/download")
def download_file():
    filename z = request.args.get("file")
    path = os.path.join("uploads", filename)
    with open(path, "rb") as f:
        content = f.read()
    return content


# --- VULN 9: Debug mode enabled in what could reach production --------------
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
