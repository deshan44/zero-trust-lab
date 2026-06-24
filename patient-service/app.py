from flask import Flask, jsonify, request
import jwt
import os
import urllib.request
import json

app = Flask(__name__)

SECRET_KEY = os.environ.get('JWT_SECRET', 'fallback-secret-key')

def verify_token(req):
    auth_header = req.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return None, "No token provided"
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload, None
    except jwt.ExpiredSignatureError:
        return None, "Token has expired"
    except jwt.InvalidTokenError:
        return None, "Invalid token"

def check_opa(service, action):
    # Ask OPA: is this service allowed to do this action?
    opa_input = {
        "input": {
            "service": service,
            "action": action
        }
    }

    data = json.dumps(opa_input).encode('utf-8')

    try:
        req = urllib.request.Request(
            'http://opa:8181/v1/data/authz/allow',
            data=data,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=3) as response:
            result = json.loads(response.read())
            return result.get('result', False)
    except Exception as e:
        print(f"OPA error: {e}")
        return False

@app.route('/health')
def health():
    return jsonify({"service": "patient-service", "status": "running"})

@app.route('/patients')
def get_patients():
    # Door 2: Check JWT token
    payload, error = verify_token(request)
    if error:
        return jsonify({
            "error": error,
            "blocked": True,
            "door": "Door 2 - JWT"
        }), 401

    # Door 3: Check OPA policy
    allowed = check_opa(payload.get('sub'), 'read:patients')
    if not allowed:
        return jsonify({
            "error": "OPA policy denied this request",
            "blocked": True,
            "door": "Door 3 - OPA Policy",
            "service": payload.get('sub')
        }), 403

    return jsonify({
        "service": "patient-service",
        "accessed_by": payload.get("sub"),
        "opa_checked": True,
        "patients": [
            {"id": 1, "name": "Ashan Silva", "age": 34},
            {"id": 2, "name": "Nimali Perera", "age": 28}
        ]
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)