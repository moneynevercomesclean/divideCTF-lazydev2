from flask import Flask, request, render_template_string, jsonify
import jwt 
import os
import datetime
# Import the serialization modules from cryptography
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
port = int(os.environ.get('PORT', 8080))
flag = os.getenv('FLAG', 'divide{local_testing_flag}')

# 1. Load the raw strings from the environment
raw_private = os.getenv('JWT_PRIVATE_KEY', '').replace('\\n', '\n').encode('utf-8')
raw_public = os.getenv('JWT_PUBLIC_KEY', '').replace('\\n', '\n').encode('utf-8')

# 2. Parse the Private Key properly for PyJWT 1.7.1 RS256 signing
try:
    if raw_private:
        PRIVATE_KEY = serialization.load_pem_private_key(
            raw_private,
            password=None,
            backend=default_backend()
        )
    else:
        PRIVATE_KEY = None
except Exception as e:
    print(f"WARNING: Failed to load PRIVATE_KEY. {e}")
    PRIVATE_KEY = None

# We keep the PUBLIC_KEY as raw bytes. 
# Why? Because the vulnerability requires the server to use this exact byte string 
# as the HMAC secret when we pass alg="HS256". If we parse it into an RSA object, 
# the HMAC math will fail!
PUBLIC_KEY = raw_public

BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>AuthPortal v2.0</title>
    <style>
        body { background: #0d0208; color: #00ff41; font-family: 'Courier New', Courier, monospace; display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        .container { border: 1px solid #00ff41; padding: 20px; box-shadow: 0 0 15px #00ff41; max-width: 600px; width: 90%; }
        h1 { border-bottom: 1px solid #00ff41; padding-bottom: 10px; }
        input, button { background: #000; border: 1px solid #00ff41; color: #00ff41; padding: 10px; margin-top: 10px; width: 100%; box-sizing: border-box; }
        button:hover { background: #00ff41; color: #000; cursor: pointer; }
        .status { margin-top: 20px; padding: 10px; background: #1a1a1a; min-height: 50px; word-wrap: break-word; border: 1px dashed #00ff41; }
    </style>
</head>
<body>
    <div class="container">
        <h1>> AUTH_PORTAL_V2.0</h1>
        <p>Current Identity: <span id="user-role">Guest</span></p>
        <button onclick="getToken()">Initialize Session (Get Token)</button>
        <div style="margin-top: 30px;">
            <p>Submit Authorized Token:</p>
            <input type="text" id="jwt-input" placeholder="eyJhbGciOiJIUzI1NiI...">
            <button onclick="submitToken()">Access Restricted Files</button>
        </div>
        <div class="status" id="output">System Ready...</div>
    </div>
    <script>
        async function getToken() {
            try {
                const res = await fetch('/login');
                const data = await res.json();
                if (data.token) {
                    document.getElementById('output').innerText = "Token Received: " + data.token;
                    document.getElementById('user-role').innerText = "User";
                } else {
                    document.getElementById('output').innerText = "Error: " + data.error;
                }
            } catch (e) {
                document.getElementById('output').innerText = "Connection Failed.";
            }
        }
        async function submitToken() {
            const token = document.getElementById('jwt-input').value;
            const res = await fetch('/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: token })
            });
            const data = await res.json();
            document.getElementById('output').innerText = data.message;
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(BASE_TEMPLATE)

@app.route('/login')
def login():
    if not PRIVATE_KEY:
        return jsonify({"error": "PRIVATE_KEY not loaded or invalid"}), 500
    
    now = datetime.datetime.utcnow()
    # Ensure token lives long enough for testing
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
        # The vulnerability remains here. 
        # PUBLIC_KEY is raw bytes. If alg=HS256, PyJWT 1.7.1 uses it as the HMAC secret.
        decoded = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256", "HS256"])

        if decoded.get('role') == 'admin':
            return jsonify({"message": "ACCESS GRANTED: " + flag})
        return jsonify({"message": f"ACCESS DENIED: Role '{decoded.get('role')}' is unauthorized."})
    except Exception as e:
        return jsonify({"message": f"SYSTEM_ERROR: {str(e)}"}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=port)