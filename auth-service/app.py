from flask import Flask, jsonify, request
import jwt
import datetime
import os

app = Flask(__name__)

SECRET_KEY = os.environ.get('JWT_SECRET', 'fallback-secret-key')

# This is our fake list of known services that can request tokens
KNOWN_SERVICES = {
    "patient-service": "patient-pass",
    "admin-service": "admin-pass",
    "dashboard": "dashboard-pass"
}

@app.route('/health')
def health():
    return jsonify({"service": "auth-service", "status": "running"})

@app.route('/token', methods=['POST'])
def get_token():
    data = request.get_json()

    service_name = data.get('service_name')
    service_pass = data.get('service_pass')

    # Check if the service is known and password is correct
    if not service_name or not service_pass:
        return jsonify({"error": "Missing credentials"}), 400

    if KNOWN_SERVICES.get(service_name) != service_pass:
        return jsonify({"error": "Invalid credentials"}), 401

    # Create the JWT token
    payload = {
        "sub": service_name,
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15),
        "scope": get_scope(service_name)
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

    return jsonify({
        "token": token,
        "expires_in": "15 minutes",
        "service": service_name,
        "scope": get_scope(service_name)
    })

def get_scope(service_name):
    # Each service only gets permissions it needs
    scopes = {
        "patient-service": ["read:patients"],
        "admin-service": ["read:patients", "write:patients", "read:admin"],
        "dashboard": ["read:logs"]
    }
    return scopes.get(service_name, [])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)