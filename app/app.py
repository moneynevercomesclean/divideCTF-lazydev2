from flask import Flask, request, render_template_string, jsonify
import jwt 
import os
import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
port = int(os.environ.get('PORT', 8080))
flag = os.getenv('FLAG', 'divide{local_testing_flag}')

# 1. Safely load raw strings
raw_private = os.getenv('JWT_PRIVATE_KEY', '').replace('\\n', '\n').encode('utf-8')
raw_public = os.getenv('JWT_PUBLIC_KEY', '').replace('\\n', '\n').encode('utf-8')

PRIVATE_KEY = None
PUBLIC_KEY = raw_public # Keep public key as raw bytes for the exploit to work

# 2. Attempt to parse, but DO NOT crash the app if it fails
try:
    if raw_private and b'BEGIN' in raw_private:
        PRIVATE_KEY = serialization.load_pem_private_key(
            raw_private,
            password=None,
            backend=default_backend()
        )
        print("Successfully loaded PRIVATE_KEY.")
    else:
        print("WARNING: JWT_PRIVATE_KEY env var is empty or missing headers.")
except Exception as e:
    print(f"CRITICAL ERROR loading private key: {e}")
    # The app will still start, but /login will fail gracefully

BASE_TEMPLATE = """...""" # (Keep your existing HTML template here)

@app.route('/')
def index():
    return render_template_string(BASE_TEMPLATE)

@app.route('/login')
def login():
    if not PRIVATE_KEY:
        # This will now tell you on the web page if the key is broken
        return jsonify({"error": "Server misconfiguration: PRIVATE_KEY could not be parsed."}), 500
    
    now = datetime.datetime.utcnow()
    expiration_time = now + datetime.timedelta(minutes=10) 

    payload = {
        "username": "ctf_player",
        "role": "user",
        "iat": int(now.timestamp()),
        "exp": int(expiration_time.timestamp())
    }

    try:
        token = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")
        if isinstance(token, bytes):
            token = token.decode('utf-8')
        return jsonify({"token": token})
    except Exception as e:
        return jsonify({"error": f"Encoding error: {str(e)}"}), 500

@app.route('/verify', methods=['POST'])
def verify():
    data = request.json
    token = data.get('token')
    if not token:
        return jsonify({"message": "No token provided!"}), 400

    try:
        # The vulnerability!
        decoded = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256", "HS256"])

        if decoded.get('role') == 'admin':
            return jsonify({"message": "ACCESS GRANTED: " + flag})
        return jsonify({"message": f"ACCESS DENIED: Role '{decoded.get('role')}' is unauthorized."})
    except Exception as e:
        return jsonify({"message": f"SYSTEM_ERROR: {str(e)}"}), 400

if __name__ == '__main__':
    print(f"Starting server on port {port}...")
    app.run(host='0.0.0.0', port=port)