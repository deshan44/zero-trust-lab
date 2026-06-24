# Zero Trust Network Simulator

A fully working Zero Trust security lab built with Docker, Python, JWT, OPA, and NGINX.

## What it does
- Micro-segmented Docker network — services cannot see each other directly
- JWT authentication — every request carries a 15-minute token
- OPA policy engine — rulebook blocks unauthorized access automatically
- Live dashboard — real-time visualization of all allowed and blocked requests

## Tech Stack
Docker, Python (Flask), JWT (PyJWT), OPA (Open Policy Agent), NGINX

## How to run
```bash
docker compose up --build
```
Then open http://localhost:5005 for the live dashboard.

## Architecture
- api-gateway — front door, all requests enter here
- auth-service — issues JWT tokens to known services
- patient-service — protected service, requires valid token + OPA approval
- admin-service — restricted service, requires admin scope + OPA approval
- dashboard — real-time monitoring of all access events

## Security layers
1. Network isolation — micro-segmented Docker networks
2. JWT tokens — short-lived, scope-based, RS256 signed
3. OPA policies — policy-as-code rulebook, default deny

