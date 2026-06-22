from flask import Flask, jsonify, request
import jwt
import os

app = Flask(__name__)

SECRET_KEY = os.environ.get('JWT_SECRET', 'fallback-secret-key')

def verify_token(req):
    # Get token from the request header
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

@app.route('/health')
def health():
    return jsonify({"service": "patient-service", "status": "running"})

@app.route('/patients')
def get_patients():
    # Check token first
    payload, error = verify_token(request)

    if error:
        return jsonify({"error": error, "blocked": True}), 401

    # Check if token has the right scope
    if "read:patients" not in payload.get("scope", []):
        return jsonify({
            "error": "You don't have permission to read patients",
            "blocked": True,
            "your_scope": payload.get("scope")
        }), 403

    # If we reach here, token is valid and has correct scope
    return jsonify({
        "service": "patient-service",
        "accessed_by": payload.get("sub"),
        "patients": [
            {"id": 1, "name": "Ashan Silva", "age": 34},
            {"id": 2, "name": "Nimali Perera", "age": 28}
        ]
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)