# IHFA Mock API Server

Serve your JSON as working HTTP endpoints so the mobile app can call them now, and later you only change the base URL to the real API.

## Quick Start

```bash
cd mock_api_server
npm install
npm run start
```

Server starts at: **http://localhost:4000/mock**

## Test from your app
- Base URL: `http://localhost:4000/mock`
- Every request should include headers:
  ```json
  {
    "Authorization": "Bearer {{token}}",
    "Content-Type": "application/json"
  }
  ```

## Endpoints
Routes are loaded from `IHFA_Mock_API_Secure.json`. Examples:
- POST `/mock/auth/login`
- POST `/mock/registration/create-account`
- POST `/mock/auth/refresh`
- GET  `/mock/__health`

## Modify Endpoints
Edit `IHFA_Mock_API_Secure.json` under `"endpoints"`:
```json
{
  "method": "POST",
  "headers": {"Authorization": "Bearer {{token}}","Content-Type": "application/json"},
  "request": {...},
  "response": {...}
}
```

## Simulate Latency
```bash
npm run start:delay    # default 500ms; adjust MOCK_DELAY_MS env var
```
