from flask import Flask, request, render_template_string, jsonify
import jwt
import os
import datetime
import traceback

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# Cloud Run provides PORT; default to 8080 for local/dev
PORT = int(os.environ.get("PORT", "8080"))
FLAG = os.getenv("FLAG", "divide{local_testing_flag}")

# --- Key loading (never crash on boot) ---
raw_private = os.getenv("JWT_PRIVATE_KEY", "")
raw_public = os.getenv("JWT_PUBLIC_KEY", "")

# Allow env vars that store literal "\n" sequences (common in Cloud Run)
raw_private_bytes = raw_private.replace("\\n", "\n").encode("utf-8")
raw_public_bytes = raw_public.replace("\\n", "\n").encode("utf-8")

PRIVATE_KEY = None
PUBLIC_KEY = raw_public_bytes  # keep as bytes (HS256 confusion exploit behavior)

try:
    if raw_private_bytes and b"BEGIN" in raw_private_bytes:
        PRIVATE_KEY = serialization.load_pem_private_key(
            raw_private_bytes,
            password=None,
            backend=default_backend(),
        )
        app.logger.info("Successfully loaded PRIVATE_KEY.")
    else:
        app.logger.warning("JWT_PRIVATE_KEY missing or does not look like PEM.")
except Exception as e:
    app.logger.exception("Failed to load PRIVATE_KEY: %s", e)
    PRIVATE_KEY = None

# Provide a real template so "/" doesn't 500
BASE_TEMPLATE = """
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>divideCTF lazydev2</title>
    <style>
      body { font-family: sans-serif; max-width: 720px; margin: 40px auto; line-height: 1.4; }
      code, pre { background: #f6f6f6; padding: 2px 6px; border-radius: 6px; }
      .box { background: #f6f6f6; padding: 14px; border-radius: 12px; }
    </style>
  </head>
  <body>
    <h1>divideCTF lazydev2</h1>
    <div class="box">
      <p><b>Endpoints</b></p>
      <ul>
        <li><code>GET /login</code> → returns a JWT for <code>ctf_player</code> (requires PRIVATE_KEY)</li>
        <li><code>POST /verify</code> with JSON <code>{"token":"..."}</code></li>
        <li><code>GET /healthz</code> → basic health check</li>
      </ul>
      <p><b>Key status</b></p>
      <ul>
        <li>PRIVATE_KEY: {{ "loaded" if private_ok else "missing/bad" }}</li>
        <li>PUBLIC_KEY: {{ "set" if public_ok else "missing" }}</li>
      </ul>
    </div>

    <h2>Try verify</h2>
    <pre>
curl -s {{ base_url }}/login
curl -s -X POST {{ base_url }}/verify -H "Content-Type: application/json" -d '{"token":"..."}'
    </pre>
  </body>
</html>
"""

# --- Error handler to make Cloud Run 500s debuggable ---
@app.errorhandler(Exception)
def handle_exception(e):
    app.logger.exception("Unhandled exception: %s", e)
    # Keep response compact; Cloud Run logs will have the full trace.
    return jsonify(
        {
            "error": "internal_server_error",
            "detail": str(e),
            "trace_tail": traceback.format_exc().splitlines()[-12:],
        }
    ), 500


@app.route("/healthz")
def healthz():
    return jsonify({"ok": True}), 200


@app.route("/")
def index():
    # base_url is best-effort; may be empty behind some proxies
    base_url = request.host_url.rstrip("/")
    return render_template_string(
        BASE_TEMPLATE,
        private_ok=PRIVATE_KEY is not None,
        public_ok=bool(PUBLIC_KEY),
        base_url=base_url,
    )


@app.route("/login")
def login():
    if not PRIVATE_KEY:
        return (
            jsonify(
                {
                    "error": "Server misconfiguration: PRIVATE_KEY could not be parsed.",
                    "hint": "Set JWT_PRIVATE_KEY env var to a PEM private key, using literal \\n for newlines in Cloud Run.",
                }
            ),
            500,
        )

    now = datetime.datetime.utcnow()
    expiration_time = now + datetime.timedelta(minutes=10)

    payload = {
        "username": "ctf_player",
        "role": "user",
        "iat": int(now.timestamp()),
        "exp": int(expiration_time.timestamp()),
    }

    try:
        token = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")
        # PyJWT 1.6.4 may return bytes
        if isinstance(token, bytes):
            token = token.decode("utf-8")
        return jsonify({"token": token})
    except Exception as e:
        return jsonify({"error": f"Encoding error: {str(e)}"}), 500


@app.route("/verify", methods=["POST"])
def verify():
    # Avoid 500 when Content-Type isn't JSON or body is empty
    data = request.get_json(silent=True) or {}
    token = data.get("token")
    if not token:
        return jsonify({"message": "No token provided!"}), 400

    try:
        # The intended vulnerability: algorithm confusion (RS256 + HS256 allowed)
        decoded = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256", "HS256"])

        if decoded.get("role") == "admin":
            return jsonify({"message": "ACCESS GRANTED: " + FLAG})
        return jsonify(
            {"message": f"ACCESS DENIED: Role '{decoded.get('role')}' is unauthorized."}
        )
    except Exception as e:
        # Keep as 400 (bad token) but include error detail
        return jsonify({"message": f"SYSTEM_ERROR: {str(e)}"}), 400


if __name__ == "__main__":
    app.logger.info("Starting server on port %d...", PORT)
    app.run(host="0.0.0.0", port=PORT)