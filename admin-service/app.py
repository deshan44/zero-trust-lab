from flask import Flask, jsonify, request
import jwt
import os

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

@app.route('/health')
def health():
    return jsonify({"service": "admin-service", "status": "running"})

@app.route('/admin')
def get_admin():
    payload, error = verify_token(request)

    if error:
        return jsonify({"error": error, "blocked": True}), 401

    # Admin requires a special scope
    if "read:admin" not in payload.get("scope", []):
        return jsonify({
            "error": "Admin access denied - insufficient scope",
            "blocked": True,
            "your_scope": payload.get("scope")
        }), 403

    return jsonify({
        "service": "admin-service",
        "accessed_by": payload.get("sub"),
        "admin_data": {
            "total_patients": 2,
            "total_staff": 10,
            "system_status": "all green"
        }
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)