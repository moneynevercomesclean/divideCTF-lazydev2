from flask import Flask, request, render_template_string, jsonify
import jwt
import os
import datetime
import traceback
import logging

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# Cloud Run provides PORT. Gunicorn binds to it; we keep this for local debug.
PORT = int(os.environ.get("PORT", "8080"))
FLAG = os.getenv("FLAG", "divide{local_testing_flag}")

# -----------------------
# Key loading (non-fatal)
# -----------------------
def _env_pem_bytes(name: str) -> bytes:
    """Read env var that may contain literal '\\n' and return bytes."""
    v = os.getenv(name, "")
    if not v:
        return b""
    return v.replace("\\n", "\n").encode("utf-8")

RAW_PRIVATE = _env_pem_bytes("JWT_PRIVATE_KEY")
RAW_PUBLIC = _env_pem_bytes("JWT_PUBLIC_KEY")

PRIVATE_KEY = None
PUBLIC_KEY = RAW_PUBLIC  # keep as bytes (needed for the intended HS256 confusion behavior)

KEY_STATUS = {"private_loaded": False, "public_set": bool(PUBLIC_KEY)}

try:
    if RAW_PRIVATE and b"BEGIN" in RAW_PRIVATE:
        PRIVATE_KEY = serialization.load_pem_private_key(
            RAW_PRIVATE, password=None, backend=default_backend()
        )
        KEY_STATUS["private_loaded"] = True
        app.logger.info("PRIVATE_KEY loaded.")
    else:
        app.logger.warning("JWT_PRIVATE_KEY not set or not PEM formatted.")
except Exception:
    app.logger.exception("Failed to parse JWT_PRIVATE_KEY.")
    PRIVATE_KEY = None
    KEY_STATUS["private_loaded"] = False

# -----------------------
# Simple homepage template
# -----------------------
BASE_TEMPLATE = """
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>divideCTF lazydev2</title>
    <style>
      body { font-family: sans-serif; max-width: 760px; margin: 40px auto; line-height: 1.4; }
      code, pre { background: #f6f6f6; padding: 2px 6px; border-radius: 6px; }
      .box { background: #f6f6f6; padding: 14px; border-radius: 12px; }
      .ok { color: #117a37; font-weight: 600; }
      .bad { color: #a61b1b; font-weight: 600; }
    </style>
  </head>
  <body>
    <h1>divideCTF lazydev2</h1>

    <div class="box">
      <p><b>Health</b></p>
      <ul>
        <li>/healthz → always 200</li>
        <li>/readyz → 200 if PUBLIC key exists (and PRIVATE if you want /login)</li>
      </ul>

      <p><b>Key status</b></p>
      <ul>
        <li>PUBLIC_KEY:
          {% if public_ok %}<span class="ok">set</span>{% else %}<span class="bad">missing</span>{% endif %}
        </li>
        <li>PRIVATE_KEY:
          {% if private_ok %}<span class="ok">loaded</span>{% else %}<span class="bad">missing/bad</span>{% endif %}
        </li>
      </ul>
    </div>

    <h2>Endpoints</h2>
    <ul>
      <li><code>GET /login</code> → returns a JWT (requires PRIVATE_KEY)</li>
      <li><code>POST /verify</code> JSON: <code>{"token":"..."}</code></li>
    </ul>

    <h2>cURL examples</h2>
    <pre>
curl -s {{ base_url }}/healthz
curl -s {{ base_url }}/login
curl -s -X POST {{ base_url }}/verify -H "Content-Type: application/json" -d '{"token":"..."}'
    </pre>
  </body>
</html>
"""

# -----------------------
# Error handler (for real unexpected crashes)
# -----------------------
@app.errorhandler(Exception)
def handle_exception(e):
    # Log full traceback to Cloud Run logs
    app.logger.exception("Unhandled exception: %s", e)
    # Return a compact debug response (helpful for CTF / debugging)
    return jsonify(
        {
            "error": "internal_server_error",
            "detail": str(e),
            "trace_tail": traceback.format_exc().splitlines()[-12:],
        }
    ), 500

# -----------------------
# Routes
# -----------------------
@app.route("/healthz")
def healthz():
    return jsonify({"ok": True}), 200

@app.route("/readyz")
def readyz():
    # Ready if PUBLIC_KEY exists; PRIVATE_KEY affects /login only
    if not PUBLIC_KEY:
        return jsonify({"ready": False, "reason": "JWT_PUBLIC_KEY missing"}), 503
    return jsonify({"ready": True, **KEY_STATUS}), 200

@app.route("/")
def index():
    base_url = request.host_url.rstrip("/")
    return render_template_string(
        BASE_TEMPLATE,
        base_url=base_url,
        private_ok=KEY_STATUS["private_loaded"],
        public_ok=KEY_STATUS["public_set"],
    )

@app.route("/login")
def login():
    # Don't claim "server error" — it's configuration, so 503 is clearer
    if not PRIVATE_KEY:
        return jsonify(
            {
                "error": "service_unavailable",
                "reason": "PRIVATE_KEY not configured",
                "hint": "Set JWT_PRIVATE_KEY to a PEM private key (use literal \\n for newlines in env var).",
            }
        ), 503

    now = datetime.datetime.utcnow()
    exp = now + datetime.timedelta(minutes=10)
    payload = {
        "username": "ctf_player",
        "role": "user",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }

    token = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")
    if isinstance(token, bytes):  # PyJWT 1.7.1 can return bytes depending on backend
        token = token.decode("utf-8")
    return jsonify({"token": token}), 200

@app.route("/verify", methods=["POST"])
def verify():
    # Never 500 due to missing/invalid JSON
    data = request.get_json(silent=True) or {}
    token = data.get("token")
    if not token:
        return jsonify({"message": "No token provided!"}), 400

    if not PUBLIC_KEY:
        return jsonify({"message": "Server misconfiguration: PUBLIC_KEY missing."}), 503

    try:
        # Intended vuln: allow both RS256 and HS256 (algorithm confusion)
        decoded = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256", "HS256"])

        if decoded.get("role") == "admin":
            return jsonify({"message": "ACCESS GRANTED: " + FLAG}), 200

        return jsonify(
            {"message": f"ACCESS DENIED: Role '{decoded.get('role')}' is unauthorized."}
        ), 200
    except Exception as e:
        return jsonify({"message": f"SYSTEM_ERROR: {str(e)}"}), 400

# Local dev only; Cloud Run uses gunicorn CMD
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.logger.info("Starting dev server on port %d...", PORT)
    app.run(host="0.0.0.0", port=PORT)