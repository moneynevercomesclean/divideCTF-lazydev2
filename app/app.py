from flask import Flask, request, render_template_string, jsonify
import jwt 
import random
import os

app = Flask(__name__)
port = int(os.environ.get('PORT', 8080))
flag = os.getenv('FLAG', 'divide{local_testing_flag}')
PRIVATE_KEY = os.getenv("JWT_PRIVATE_KEY", "").replace('\\n', '\n').encode()
PUBLIC_KEY = os.getenv("JWT_PUBLIC_KEY", "").replace('\\n', '\n').encode()

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

import datetime
import jwt

@app.route('/login')
def login():
    # 1. Set the expiration (e.g., 30 minutes from now)
    now = datetime.datetime.utcnow()
    expiration_time = now + datetime.timedelta(seconds=1)  # Token valid for 30 minutes

    payload = {
        "username": "ctf_player",
        "role": "user",
        "iat": int(now.timestamp()),          # Issued At
        "exp": int(expiration_time.timestamp()) # Expiration
    }

    # 2. Encode as usual
    token = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")
    
    # Handle bytes/string conversion for older PyJWT versions
    if isinstance(token, bytes):
        token = token.decode('utf-8')

    return jsonify({"token": token})

@app.route('/verify', methods=['POST'])
def verify():
    data = request.json
    token = data.get('token')
    if not token:
        return jsonify({"message": "No token provided!"}), 400

    try:
        decoded = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256", "HS256"])

        if decoded.get('role') == 'admin':
            return jsonify({"message": "ACCESS GRANTED: " + flag})
        return jsonify({"message": f"ACCESS DENIED: Role '{decoded.get('role')}' is unauthorized."})
    except Exception as e:
        return jsonify({"message": f"SYSTEM_ERROR: {str(e)}"}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=port)