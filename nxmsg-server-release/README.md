# NXMSG Server Release

Backend release bundle for:

- NXMSG website
- native Android client
- Railway deployment

## Included

- `server.js`
- `package.json`
- `railway.json`
- `.env.example`
- `public/index.html`

## Features

- register / login / session restore
- contact list and message history
- WebSocket live messaging
- call signaling
- avatar upload and persistence
- device push token storage
- FCM push for incoming messages and calls
- `/health` endpoint for Railway health checks

## Railway setup

1. Push this folder to a GitHub repository.
2. Create a new Railway project from that repository.
3. Add a PostgreSQL plugin or connect an existing database.
4. Set environment variables from `.env.example`.
5. Railway will run `npm start` automatically.

## Environment variables

- `PORT`
- `DATABASE_URL`
- `FIREBASE_SERVICE_ACCOUNT_JSON`
- `FIREBASE_SERVICE_ACCOUNT_JSON_BASE64`

Use either raw Firebase service account JSON or its base64 version.

## Notes

- The server is ready for `https` + `wss` deployment behind Railway.
- Push notifications require valid Firebase credentials.
- Native Android client should point to the Railway public URL in its build config.
