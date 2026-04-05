# Railway Setup

## 1. Upload this folder

Use this folder as the repository root:

- [nxmsg-server-release](C:\Users\egorm\OneDrive\Документы\New%20project\nxmsg-server-release)

## 2. Create a Railway project

1. Create a new project from your GitHub repository.
2. Add a PostgreSQL database.
3. Railway will inject `DATABASE_URL` automatically.

## 3. Set environment variables

Required:

- `DATABASE_URL`
- `FIREBASE_SERVICE_ACCOUNT_JSON`

or:

- `FIREBASE_SERVICE_ACCOUNT_JSON_BASE64`

Optional:

- `PORT`

## 4. Health check

Railway can use:

- `/health`

## 5. Android client values

After Railway gives you the public domain, put it into Android config:

```properties
NXMSG_API_BASE=https://your-app.up.railway.app
NXMSG_WS_BASE=wss://your-app.up.railway.app
NXMSG_FIREBASE_APP_ID=1:1234567890:android:your_app_id
NXMSG_FIREBASE_API_KEY=AIza...
NXMSG_FIREBASE_PROJECT_ID=your-firebase-project-id
NXMSG_FIREBASE_STORAGE_BUCKET=your-firebase-project.appspot.com
NXMSG_FIREBASE_GCM_SENDER_ID=1234567890
```

These values match:

- [firebase.properties.example](C:\Users\egorm\OneDrive\Документы\New%20project\nxmsg-android\firebase.properties.example)

## 6. What should work after deploy

- register / login
- live messages over WebSocket
- username lookup
- avatar persistence
- push token registration
- FCM message notifications
- FCM incoming call notifications
- call signaling between Android clients
