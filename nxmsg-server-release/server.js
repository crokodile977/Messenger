const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const admin = require('firebase-admin');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(express.json({ limit: '35mb' }));

// PWA icons (generated SVG rendered as PNG via browser)
// We serve SVG with correct MIME so browsers accept it as icon
const ICON_SVG = (size) => `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
  <rect width="${size}" height="${size}" rx="${size*0.18}" fill="#0a0a0a"/>
  <rect width="${size}" height="${size}" rx="${size*0.18}" fill="url(#g)"/>
  <defs><radialGradient id="g" cx="50%" cy="40%" r="60%"><stop offset="0%" stop-color="#FF5C00" stop-opacity="0.15"/><stop offset="100%" stop-color="#0a0a0a" stop-opacity="0"/></radialGradient></defs>
  <text x="${size/2}" y="${size*0.62}" text-anchor="middle" font-family="monospace" font-weight="bold" font-size="${size*0.38}" fill="#f0f0f0">NX</text>
  <text x="${size/2}" y="${size*0.88}" text-anchor="middle" font-family="monospace" font-weight="bold" font-size="${size*0.28}" fill="#FF5C00">MSG</text>
</svg>`;

app.get('/icon-192.png', (req, res) => {
  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Cache-Control', 'public, max-age=86400');
  res.send(ICON_SVG(192));
});
app.get('/icon-512.png', (req, res) => {
  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Cache-Control', 'public, max-age=86400');
  res.send(ICON_SVG(512));
});
// apple touch icon
app.get('/apple-touch-icon.png', (req, res) => {
  res.setHeader('Content-Type', 'image/svg+xml');
  res.send(ICON_SVG(180));
});

app.use(express.static(path.join(__dirname, 'public')));

app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self' ws: wss:");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

app.get('/health', (req, res) => {
  res.json({
    ok: true,
    uptime: process.uptime(),
    users: users.size,
    conversations: messages.size,
    push: admin.apps.length > 0
  });
});

// ─── DATABASE (PostgreSQL) ──────────────────────────────
const { Pool } = require('pg');

// DATABASE_URL is set automatically by Railway when you attach a PostgreSQL database.
// For local dev, set it in .env or environment: DATABASE_URL=postgresql://user:pass@host/db
const pool = process.env.DATABASE_URL ? new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: /localhost|127\.0\.0\.1/i.test(process.env.DATABASE_URL)
    ? false
    : { rejectUnauthorized: false }
}) : null;

// In-memory cache (populated from DB on startup, kept in sync on writes)
// users    : userId  -> { id, passwordHash, displayName, bio, avatar, registeredAt, publicCode, username }
// pubcodes : publicCode -> userId
// messages : convKey -> [{ id, from, to, encrypted, timestamp, kind, fileName, fileSize, fileType, fileData }]
const users    = new Map();
const pubcodes = new Map();
const messages = new Map();
const wsClients = new Map();
const sessions = new Map();
const deviceTokens = new Map();

function upsertDeviceToken(userId, token) {
  if (!deviceTokens.has(userId)) deviceTokens.set(userId, new Set());
  deviceTokens.get(userId).add(token);
}

function removeDeviceToken(userId, token) {
  const tokens = deviceTokens.get(userId);
  if (!tokens) return;
  tokens.delete(token);
  if (!tokens.size) deviceTokens.delete(userId);
}

// ── Schema init ──────────────────────────────────────────
async function initDB() {
  if (!pool) { console.log('⚠️  No DATABASE_URL — running with in-memory storage only'); return; }
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id            TEXT PRIMARY KEY,
      public_code   TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      display_name  TEXT NOT NULL DEFAULT '',
      username      TEXT UNIQUE,
      bio           TEXT NOT NULL DEFAULT '',
      avatar        TEXT,
      registered_at BIGINT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS messages (
      id        TEXT PRIMARY KEY,
      conv_key  TEXT NOT NULL,
      from_id   TEXT NOT NULL,
      to_id     TEXT NOT NULL,
      encrypted TEXT NOT NULL,
      ts        BIGINT NOT NULL,
      kind      TEXT NOT NULL DEFAULT 'text',
      file_name TEXT,
      file_size BIGINT,
      file_type TEXT,
      file_data TEXT
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      expires_at BIGINT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS device_tokens (
      token TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      platform TEXT NOT NULL DEFAULT 'android',
      updated_at BIGINT NOT NULL
    );
    ALTER TABLE messages ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'text';
    ALTER TABLE messages ADD COLUMN IF NOT EXISTS file_name TEXT;
    ALTER TABLE messages ADD COLUMN IF NOT EXISTS file_size BIGINT;
    ALTER TABLE messages ADD COLUMN IF NOT EXISTS file_type TEXT;
    ALTER TABLE messages ADD COLUMN IF NOT EXISTS file_data TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS username TEXT;
    CREATE UNIQUE INDEX IF NOT EXISTS users_username_unique ON users (username) WHERE username IS NOT NULL;
    CREATE INDEX IF NOT EXISTS messages_conv_key ON messages(conv_key, ts);
    CREATE INDEX IF NOT EXISTS sessions_user_id ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS device_tokens_user_id ON device_tokens(user_id);
  `);
}

// ── Load all data into memory on startup ─────────────────
async function loadFromDB() {
  if (!pool) return;
  const { rows: uRows } = await pool.query('SELECT * FROM users');
  for (const r of uRows) {
    const u = { id: r.id, publicCode: r.public_code, passwordHash: r.password_hash,
      displayName: r.display_name, username: r.username || '',
      bio: r.bio || '', avatar: r.avatar || null,
      registeredAt: Number(r.registered_at) };
    if (!u.username) {
      u.username = ensureUniqueUsername('', u.displayName, u.publicCode, u.id);
      if (pool) {
        await pool.query('UPDATE users SET username=$1 WHERE id=$2', [u.username, u.id]);
      }
    }
    users.set(r.id, u);
    pubcodes.set(r.public_code, r.id);
  }
  const { rows: sRows } = await pool.query('SELECT token, user_id, expires_at FROM sessions WHERE expires_at > $1', [Date.now()]);
  for (const r of sRows) {
    sessions.set(r.token, { userId: r.user_id, expiresAt: Number(r.expires_at) });
  }
  const { rows: dRows } = await pool.query('SELECT token, user_id FROM device_tokens');
  for (const r of dRows) {
    upsertDeviceToken(r.user_id, r.token);
  }
  const { rows: mRows } = await pool.query(`
    SELECT id, conv_key, from_id, to_id, encrypted, ts, kind, file_name, file_size, file_type, file_data
    FROM messages
    ORDER BY ts ASC
  `);
  for (const r of mRows) {
    const key = r.conv_key;
    if (!messages.has(key)) messages.set(key, []);
    messages.get(key).push({
      id: r.id,
      from: r.from_id,
      to: r.to_id,
      encrypted: r.encrypted,
      timestamp: Number(r.ts),
      kind: r.kind || 'text',
      fileName: r.file_name || '',
      fileSize: Number(r.file_size || 0),
      fileType: r.file_type || '',
      fileData: r.file_data || ''
    });
  }
  console.log(`✅ Loaded ${users.size} users, ${messages.size} conversations, ${sessions.size} sessions and ${dRows.length} push tokens from DB`);
}

// ── Persist helpers (write-through: update cache then DB) ─

async function saveUser(u) {
  users.set(u.id, u);
  pubcodes.set(u.publicCode, u.id);
  if (!pool) return; // no DB configured — in-memory only
  try {
    await pool.query(`
      INSERT INTO users (id, public_code, password_hash, display_name, username, bio, avatar, registered_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
      ON CONFLICT (id) DO UPDATE SET
        display_name = EXCLUDED.display_name,
        username     = EXCLUDED.username,
        bio          = EXCLUDED.bio,
        avatar       = EXCLUDED.avatar,
        password_hash= EXCLUDED.password_hash
    `, [u.id, u.publicCode, u.passwordHash, u.displayName || '', u.username || null, u.bio || '', u.avatar || null, u.registeredAt]);
  } catch (e) { console.error('saveUser DB error:', e.message); }
}

// Debounce avatar saves (avatars are big base64 strings)
const _avatarTimers = {};
function saveUserAvatar(u) {
  users.set(u.id, u);
  clearTimeout(_avatarTimers[u.id]);
  _avatarTimers[u.id] = setTimeout(() => {
    if (!pool) return;
    pool.query('UPDATE users SET avatar=$1 WHERE id=$2', [u.avatar || null, u.id])
      .catch(e => console.error('avatar save error:', e.message));
  }, 500);
}

async function saveMessage(convKey, msgObj) {
  if (!messages.has(convKey)) messages.set(convKey, []);
  messages.get(convKey).push(msgObj);
  if (!pool) return;
  try {
    await pool.query(`
      INSERT INTO messages (id, conv_key, from_id, to_id, encrypted, ts, kind, file_name, file_size, file_type, file_data)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT DO NOTHING
    `, [
      msgObj.id,
      convKey,
      msgObj.from,
      msgObj.to,
      msgObj.encrypted,
      msgObj.timestamp,
      msgObj.kind || 'text',
      msgObj.fileName || null,
      msgObj.fileSize || 0,
      msgObj.fileType || null,
      msgObj.fileData || null
    ]);
  } catch (e) { console.error('saveMessage DB error:', e.message); }
}

async function saveSession(token, userId, expiresAt) {
  sessions.set(token, { userId, expiresAt });
  if (!pool) return;
  try {
    await pool.query(`
      INSERT INTO sessions (token, user_id, expires_at)
      VALUES ($1, $2, $3)
      ON CONFLICT (token) DO UPDATE SET
        user_id = EXCLUDED.user_id,
        expires_at = EXCLUDED.expires_at
    `, [token, userId, expiresAt]);
  } catch (e) {
    console.error('saveSession DB error:', e.message);
  }
}

async function deleteSession(token) {
  sessions.delete(token);
  if (!pool) return;
  try {
    await pool.query('DELETE FROM sessions WHERE token=$1', [token]);
  } catch (e) {
    console.error('deleteSession DB error:', e.message);
  }
}

async function saveDeviceToken(userId, token, platform = 'android') {
  if (!token) return;
  upsertDeviceToken(userId, token);
  if (!pool) return;
  try {
    await pool.query(`
      INSERT INTO device_tokens (token, user_id, platform, updated_at)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (token) DO UPDATE SET
        user_id = EXCLUDED.user_id,
        platform = EXCLUDED.platform,
        updated_at = EXCLUDED.updated_at
    `, [token, userId, platform, Date.now()]);
  } catch (e) {
    console.error('saveDeviceToken DB error:', e.message);
  }
}

async function deleteDeviceToken(token) {
  if (!token) return;
  for (const [userId, tokens] of deviceTokens.entries()) {
    if (tokens.has(token)) {
      removeDeviceToken(userId, token);
      break;
    }
  }
  if (!pool) return;
  try {
    await pool.query('DELETE FROM device_tokens WHERE token=$1', [token]);
  } catch (e) {
    console.error('deleteDeviceToken DB error:', e.message);
  }
}

// Legacy no-ops (code still calls these in some places — safe to ignore)
const saveUsers    = () => {};
const saveMessages = () => {};
const savePubcodes = () => {};

// ─── HELPERS ────────────────────────────────────────────

// Internal ID: ~20 chars, mixed case + specials — never shown to other users
function generateUserId() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_+=~';
  const bytes = crypto.randomBytes(24);
  let id = '';
  for (let i = 0; i < 20; i++) id += chars[bytes[i] % chars.length];
  return id;
}

// Public code: 12 alphanumeric chars — safe to share, shown in QR
function generatePublicCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no ambiguous chars
  const bytes = crypto.randomBytes(16);
  let code = '';
  for (let i = 0; i < 12; i++) code += chars[bytes[i] % chars.length];
  return code;
}

// Session token: 32 random hex bytes
function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

function getConvKey(a, b)             { return [a, b].sort().join('::'); }
function getConversationSecret(a, b)  {
  return crypto.createHmac('sha256', 'nxmsg-secret-2024').update([a, b].sort().join('|')).digest('hex');
}

function encryptMessage(text, secret) {
  const key = crypto.createHash('sha256').update(secret).digest();
  const iv  = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return iv.toString('hex') + ':' + tag.toString('hex') + ':' + enc.toString('hex');
}

function decryptMessage(data, secret) {
  try {
    const [ivH, tagH, dataH] = data.split(':');
    const key = crypto.createHash('sha256').update(secret).digest();
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivH, 'hex'));
    decipher.setAuthTag(Buffer.from(tagH, 'hex'));
    return decipher.update(Buffer.from(dataH, 'hex')) + decipher.final('utf8');
  } catch { return null; }
}

function sanitizeText(input) {
  if (typeof input !== 'string') return '';
  return input
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#x27;').replace(/\//g, '&#x2F;')
    .replace(/`/g, '&#x60;').replace(/=/g, '&#x3D;')
    .slice(0, 4000);
}

function sanitizeDisplayName(input) {
  if (typeof input !== 'string') return '';
  return input.replace(/[<>&"'`\/=]/g, '').trim().slice(0, 32);
}

function sanitizeBio(input, fallback = '') {
  if (typeof input !== 'string') return fallback;
  return input.replace(/[<>&"'`\/=]/g, '').trim().slice(0, 80);
}

function sanitizeUsername(input, fallback = '') {
  if (typeof input !== 'string') return fallback;
  return input
    .trim()
    .replace(/^@+/, '')
    .toLowerCase()
    .replace(/[^a-z0-9_]/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 24);
}

function defaultUsername(displayName, publicCode = '') {
  const base = sanitizeUsername(displayName);
  if (base) return base;
  const suffix = String(publicCode || '').slice(-4).toLowerCase();
  return sanitizeUsername(`nxmsg_${suffix}`) || `nxmsg_${crypto.randomBytes(3).toString('hex')}`;
}

function isUsernameTaken(username, exceptUserId = null) {
  if (!username) return false;
  for (const [id, user] of users.entries()) {
    if (id === exceptUserId) continue;
    if ((user.username || '').toLowerCase() === username.toLowerCase()) return true;
  }
  return false;
}

function ensureUniqueUsername(preferred, displayName, publicCode, exceptUserId = null) {
  const seed = sanitizeUsername(preferred) || defaultUsername(displayName, publicCode);
  let candidate = seed || `nxmsg_${String(publicCode || '').slice(-4).toLowerCase()}`;
  let attempt = 1;
  while (isUsernameTaken(candidate, exceptUserId)) {
    const suffix = attempt < 10 ? attempt : crypto.randomBytes(2).toString('hex');
    candidate = sanitizeUsername(`${seed}_${suffix}`) || `nxmsg_${crypto.randomBytes(3).toString('hex')}`;
    attempt += 1;
  }
  return candidate;
}

function buildFilePreview(fileName) {
  return `📎 ${fileName || 'Файл'}`;
}

function serializeMessageForClient(message, viewerUserId, secret) {
  const text = decryptMessage(message.encrypted, secret) || (message.kind === 'file' ? buildFilePreview(message.fileName) : '[decryption failed]');
  return {
    id: message.id,
    mine: message.from === viewerUserId,
    text,
    timestamp: message.timestamp,
    fileData: message.fileData || '',
    fileName: message.fileName || '',
    fileSize: message.fileSize || 0,
    fileType: message.fileType || ''
  };
}

function buildChatStartedPayload(senderUser) {
  return {
    type: 'chat_started',
    fromCode: senderUser.publicCode,
    fromName: senderUser.displayName || '',
    publicCode: senderUser.publicCode,
    displayName: senderUser.displayName || '',
    username: senderUser.username || '',
    bio: senderUser.bio || '',
    avatar: senderUser.avatar || null,
    online: true
  };
}

function isValidUserId(id) {
  if (typeof id !== 'string' || id.length < 18 || id.length > 24) return false;
  return /^[A-Za-z0-9!@#$%^&*\-_+=~]+$/.test(id);
}

function isValidPublicCode(code) {
  if (typeof code !== 'string') return false;
  return /^[A-Z0-9]{12}$/.test(code);
}

// Resolve a token to userId, return null if invalid/expired
function resolveSession(token) {
  if (typeof token !== 'string') return null;
  const s = sessions.get(token);
  if (!s) return null;
  if (s.expiresAt < Date.now()) { deleteSession(token); return null; }
  return s.userId;
}

function getFirebaseServiceAccount() {
  const rawJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  const base64Json = process.env.FIREBASE_SERVICE_ACCOUNT_JSON_BASE64;
  try {
    if (rawJson) {
      return JSON.parse(rawJson);
    }
    if (base64Json) {
      return JSON.parse(Buffer.from(base64Json, 'base64').toString('utf8'));
    }
  } catch (e) {
    console.error('Firebase service account parse error:', e.message);
    return null;
  }
  return null;
}

function initFirebaseAdmin() {
  const serviceAccount = getFirebaseServiceAccount();
  if (!serviceAccount) {
    console.warn('⚠️ Firebase service account is not configured. Push notifications are disabled.');
    return false;
  }
  if (!admin.apps.length) {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
  }
  return true;
}

async function sendPushToUser(userId, message) {
  const tokens = Array.from(deviceTokens.get(userId) || []);
  if (!tokens.length || !admin.apps.length) return;
  try {
    const response = await admin.messaging().sendEachForMulticast({
      tokens,
      ...message
    });
    const invalidTokens = [];
    response.responses.forEach((result, index) => {
      if (result.success) return;
      const code = result.error?.code || '';
      if (
        code.includes('registration-token-not-registered') ||
        code.includes('invalid-registration-token') ||
        code.includes('invalid-argument')
      ) {
        invalidTokens.push(tokens[index]);
      }
    });
    await Promise.all(invalidTokens.map(deleteDeviceToken));
  } catch (e) {
    console.error('sendPushToUser error:', e.message);
  }
}

// Rate-limit store: ip -> { count, resetAt }
const loginAttempts = new Map();
function checkRateLimit(ip) {
  const now = Date.now();
  const entry = loginAttempts.get(ip) || { count: 0, resetAt: now + 60000 };
  if (now > entry.resetAt) { entry.count = 0; entry.resetAt = now + 60000; }
  entry.count++;
  loginAttempts.set(ip, entry);
  return entry.count <= 10; // max 10 attempts per minute per IP
}

// ─── AUTH ENDPOINTS ─────────────────────────────────────

// Register: { password, displayName? } -> { publicCode, token }
app.post('/api/register', async (req, res) => {
  const { password, displayName } = req.body;
  if (typeof password !== 'string' || password.length < 6 || password.length > 128) {
    return res.status(400).json({ error: 'Пароль должен быть от 6 до 128 символов' });
  }

  const passwordHash = await bcrypt.hash(password, 12);
  const userId = generateUserId();

  // Ensure public code is unique
  let publicCode;
  do { publicCode = generatePublicCode(); } while (pubcodes.has(publicCode));

  const safeName = sanitizeDisplayName(displayName);
  const username = ensureUniqueUsername('', safeName, publicCode);

  await saveUser({ id: userId, passwordHash, displayName: safeName, username, bio: '', avatar: null, registeredAt: Date.now(), publicCode });

  const token = generateSessionToken();
  const expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000;
  await saveSession(token, userId, expiresAt);

  res.json({ publicCode, token, displayName: safeName, username, bio: '', avatar: null });
});

// Login: { publicCode, password } -> { token, displayName }
app.post('/api/login', async (req, res) => {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  if (!checkRateLimit(ip)) {
    return res.status(429).json({ error: 'Слишком много попыток входа. Подождите минуту.' });
  }

  const { publicCode, password } = req.body;
  if (!isValidPublicCode(publicCode)) {
    return res.status(400).json({ error: 'Неверный формат кода' });
  }
  if (typeof password !== 'string') {
    return res.status(400).json({ error: 'Пароль не указан' });
  }

  const userId = pubcodes.get(publicCode);
  if (!userId || !users.has(userId)) {
    // Constant-time response to prevent user enumeration
    await bcrypt.compare('dummy-password', '$2a$12$C6UzMDM.H6dfI/f/IKcEeOeW8b7mBfCJoM/gA1r5MMEZe7qVD/3G.');
    return res.status(401).json({ error: 'Неверный код или пароль' });
  }

  const user = users.get(userId);
  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) {
    return res.status(401).json({ error: 'Неверный код или пароль' });
  }

  const token = generateSessionToken();
  const expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000;
  await saveSession(token, userId, expiresAt);

  res.json({ token, displayName: user.displayName || '', publicCode, username: user.username || '', bio: user.bio || '', avatar: user.avatar || null });
});

// Validate existing session token -> { valid, displayName, publicCode }
app.post('/api/session', (req, res) => {
  const { token } = req.body;
  const userId = resolveSession(token);
  if (!userId || !users.has(userId)) return res.json({ valid: false });
  const u = users.get(userId);
  res.json({ valid: true, token, displayName: u.displayName || '', username: u.username || '', bio: u.bio || '', avatar: u.avatar || null, publicCode: u.publicCode });
});

// Lookup user by public code (for starting a chat) — returns exists + displayName only
app.get('/api/user/bycode/:code', (req, res) => {
  const code = req.params.code.toUpperCase();
  if (!isValidPublicCode(code)) return res.status(400).json({ error: 'Invalid code' });
  const userId = pubcodes.get(code);
  if (!userId || !users.has(userId)) return res.json({ exists: false });
  const u = users.get(userId);
  res.json({ exists: true, online: wsClients.has(userId), displayName: u.displayName || '', username: u.username || '', bio: u.bio || '', avatar: u.avatar || null, publicCode: code });
});

app.get('/api/user/byusername/:username', (req, res) => {
  const username = sanitizeUsername(req.params.username);
  if (!username) return res.status(400).json({ error: 'Invalid username' });
  const user = Array.from(users.values()).find(entry => (entry.username || '').toLowerCase() === username);
  if (!user) return res.json({ exists: false });
  res.json({
    exists: true,
    online: wsClients.has(user.id),
    displayName: user.displayName || '',
    username: user.username || '',
    bio: user.bio || '',
    avatar: user.avatar || null,
    publicCode: user.publicCode
  });
});

// Update display name (authenticated)
app.patch('/api/user/name', async (req, res) => {
  const userId = resolveSession(req.body.token);
  if (!userId || !users.has(userId)) return res.status(401).json({ error: 'Unauthorized' });
  const requestedName = typeof req.body.displayName === 'string' ? req.body.displayName : req.body.name;
  if (typeof requestedName !== 'string') return res.status(400).json({ error: 'Invalid name' });
  const safeName = sanitizeDisplayName(requestedName);
  const safeBio = sanitizeBio(req.body.bio, users.get(userId).bio || '');
  const requestedUsername = sanitizeUsername(req.body.username, users.get(userId).username || '');
  const safeUsername = ensureUniqueUsername(requestedUsername, safeName, users.get(userId).publicCode, userId);
  if (requestedUsername && safeUsername !== requestedUsername) {
    return res.status(409).json({ error: 'Username already taken' });
  }
  const updatedUser = { ...users.get(userId), displayName: safeName, username: safeUsername, bio: safeBio };
  await saveUser(updatedUser);
  // Broadcast name change
  for (const [key] of messages) {
    const [a, b] = key.split('::');
    const other = a === userId ? b : b === userId ? a : null;
    if (!other) continue;
    const ows = wsClients.get(other);
    if (ows && ows.readyState === WebSocket.OPEN) {
      ows.send(JSON.stringify({
        type: 'name_changed',
        publicCode: users.get(userId).publicCode,
        displayName: safeName,
        username: safeUsername,
        bio: safeBio
      }));
    }
  }
  res.json({ ok: true, displayName: safeName, username: safeUsername, bio: safeBio });
});

// Upload / update avatar
app.post('/api/user/avatar', async (req, res) => {
  const userId = resolveSession(req.body.token);
  if (!userId || !users.has(userId)) return res.status(401).json({ error: 'Unauthorized' });
  const { avatar } = req.body;
  if (typeof avatar !== 'string') return res.status(400).json({ error: 'Invalid avatar' });
  // Accept only data URLs with image MIME type — basic validation
  if (!avatar.startsWith('data:image/')) return res.status(400).json({ error: 'Must be an image' });
  // ~2 MB limit on base64 string (~2.7 MB raw) 
  if (avatar.length > 3 * 1024 * 1024) return res.status(400).json({ error: 'Image too large (max 2 MB)' });
  const userWithAvatar = { ...users.get(userId), avatar };
  saveUserAvatar(userWithAvatar);
  // Notify contacts of avatar update
  for (const [key] of messages) {
    const [a, b] = key.split('::');
    const other = a === userId ? b : b === userId ? a : null;
    if (!other) continue;
    const ows = wsClients.get(other);
    if (ows?.readyState === WebSocket.OPEN) {
      ows.send(JSON.stringify({ type: 'avatar_changed', publicCode: users.get(userId).publicCode }));
    }
  }
  res.json({ ok: true });
});

// Delete avatar
app.delete('/api/user/avatar', async (req, res) => {
  const userId = resolveSession(req.body.token);
  if (!userId || !users.has(userId)) return res.status(401).json({ error: 'Unauthorized' });
  const userNoAvatar = { ...users.get(userId), avatar: null };
  saveUserAvatar(userNoAvatar);
  res.json({ ok: true });
});

// Get avatar by public code (public endpoint)
app.get('/api/avatar/:code', (req, res) => {
  const code = req.params.code.toUpperCase();
  if (!isValidPublicCode(code)) return res.status(400).json({ error: 'Invalid code' });
  const userId = pubcodes.get(code);
  if (!userId || !users.has(userId)) return res.json({ avatar: null });
  const u = users.get(userId);
  res.json({ avatar: u.avatar || null });
});

app.post('/api/push/register', async (req, res) => {
  const userId = resolveSession(req.body.token);
  if (!userId || !users.has(userId)) return res.status(401).json({ error: 'Unauthorized' });
  const pushToken = typeof req.body.pushToken === 'string' ? req.body.pushToken.trim() : '';
  const platform = typeof req.body.platform === 'string' ? req.body.platform.trim().slice(0, 32) : 'android';
  if (!pushToken) return res.status(400).json({ error: 'Invalid push token' });
  await saveDeviceToken(userId, pushToken, platform || 'android');
  res.json({ ok: true });
});

app.post('/api/push/unregister', async (req, res) => {
  const userId = resolveSession(req.body.token);
  if (!userId || !users.has(userId)) return res.status(401).json({ error: 'Unauthorized' });
  const pushToken = typeof req.body.pushToken === 'string' ? req.body.pushToken.trim() : '';
  if (!pushToken) return res.status(400).json({ error: 'Invalid push token' });
  await deleteDeviceToken(pushToken);
  res.json({ ok: true });
});

// Get contacts for current user
app.post('/api/contacts', (req, res) => {
  const userId = resolveSession(req.body.token);
  if (!userId || !users.has(userId)) return res.status(401).json({ error: 'Unauthorized' });

  const contacts = [];
  for (const [key, msgs] of messages) {
    const [a, b] = key.split('::');
    if (a !== userId && b !== userId) continue;
    const contactId = a === userId ? b : a;
    if (!users.has(contactId)) continue;
    const cu = users.get(contactId);
    const lastMsg = msgs.length ? msgs[msgs.length - 1] : null;
    const secret = getConversationSecret(userId, contactId);
    const lastText = !lastMsg
      ? ''
      : lastMsg.kind === 'file'
        ? buildFilePreview(lastMsg.fileName)
        : (decryptMessage(lastMsg.encrypted, secret) || '');
    contacts.push({
      publicCode: cu.publicCode,
      displayName: cu.displayName || '',
      username: cu.username || '',
      bio: cu.bio || '',
      avatar: cu.avatar || null,
      online: wsClients.has(contactId),
      lastTimestamp: lastMsg ? lastMsg.timestamp : 0,
      lastText,
      lastFrom: lastMsg ? (lastMsg.from === userId ? 'me' : 'them') : null,
      messageCount: msgs.length
    });
  }
  contacts.sort((a, b) => b.lastTimestamp - a.lastTimestamp);
  res.json(contacts);
});

// Get message history (authenticated, by public code)
app.post('/api/messages', (req, res) => {
  const userId = resolveSession(req.body.token);
  if (!userId || !users.has(userId)) return res.status(401).json({ error: 'Unauthorized' });

  const { contactCode } = req.body;
  if (!isValidPublicCode(contactCode)) return res.status(400).json({ error: 'Invalid code' });
  const contactId = pubcodes.get(contactCode);
  if (!contactId || !users.has(contactId)) return res.status(404).json({ error: 'Contact not found' });

  const key = getConvKey(userId, contactId);
  const secret = getConversationSecret(userId, contactId);
  const raw = messages.get(key) || [];
  const decrypted = raw.map(m => serializeMessageForClient(m, userId, secret));
  res.json(decrypted);
});

// ─── WEBSOCKET ──────────────────────────────────────────
wss.on('connection', (ws) => {
  let userId = null; // internal ID — resolved from session token

  ws.on('message', async (rawData) => {
    let msg;
    try { msg = JSON.parse(rawData.toString()); }
    catch { ws.send(JSON.stringify({ type: 'error', error: 'Invalid format' })); return; }
    if (typeof msg.type !== 'string') return;

    switch (msg.type) {
      case 'auth': {
        const uid = resolveSession(msg.token);
        if (!uid || !users.has(uid)) {
          ws.send(JSON.stringify({ type: 'error', error: 'Auth failed' }));
          return;
        }
        userId = uid;
        wsClients.set(userId, ws);
        ws.send(JSON.stringify({ type: 'auth_ok' }));
        broadcastOnlineStatus(userId, true);
        break;
      }

      case 'send_message': {
        if (!userId) { ws.send(JSON.stringify({ type: 'error', error: 'Not authenticated' })); return; }
        const { to: toCode, text } = msg; // 'to' is recipient's PUBLIC CODE

        if (!isValidPublicCode(toCode)) { ws.send(JSON.stringify({ type: 'error', error: 'Invalid recipient' })); return; }
        const toId = pubcodes.get(toCode);
        if (!toId || !users.has(toId)) { ws.send(JSON.stringify({ type: 'error', error: 'User not found' })); return; }
        if (typeof text !== 'string' || !text.trim()) { ws.send(JSON.stringify({ type: 'error', error: 'Empty message' })); return; }

        const safeText = sanitizeText(text.trim());
        const secret = getConversationSecret(userId, toId);
        const encrypted = encryptMessage(safeText, secret);

        const msgObj = {
          id: crypto.randomUUID(),
          from: userId,
          to: toId,
          encrypted,
          timestamp: Date.now(),
          kind: 'text',
          fileName: '',
          fileSize: 0,
          fileType: '',
          fileData: ''
        };
        const convKey = getConvKey(userId, toId);
        const isFirst = !messages.has(convKey) || !messages.get(convKey).length;
        await saveMessage(convKey, msgObj);

        const senderUser = users.get(userId);
        const recipientWs = wsClients.get(toId);

        if (isFirst && recipientWs?.readyState === WebSocket.OPEN) {
          recipientWs.send(JSON.stringify(buildChatStartedPayload(senderUser)));
        }

        if (recipientWs?.readyState === WebSocket.OPEN) {
          recipientWs.send(JSON.stringify({
            type: 'new_message',
            id: msgObj.id,
            from: senderUser.publicCode,
            fromName: senderUser.displayName || '',
            username: senderUser.username || '',
            avatar: senderUser.avatar || null,
            text: safeText,
            timestamp: msgObj.timestamp
          }));
        }

        await sendPushToUser(toId, {
          data: {
            type: 'incoming_message',
            publicCode: senderUser.publicCode,
            displayName: senderUser.displayName || '',
            fromName: senderUser.displayName || '',
            username: senderUser.username || '',
            avatar: senderUser.avatar || '',
            text: safeText,
            timestamp: String(msgObj.timestamp)
          },
          android: {
            priority: 'high',
            ttl: 60 * 60 * 1000,
            notification: {
              channelId: 'nxmsg_messages',
              sound: 'default'
            }
          }
        });

        ws.send(JSON.stringify({
          type: 'message_sent',
          id: msgObj.id,
          to: toCode,
          text: safeText,
          timestamp: msgObj.timestamp
        }));
        break;
      }

      case 'start_chat': {
        if (!userId) return;
        const toCode = msg.to;
        if (!isValidPublicCode(toCode)) return;
        const toId = pubcodes.get(toCode);
        if (!toId || !users.has(toId)) return;
        const convKey = getConvKey(userId, toId);
        if (messages.has(convKey) && messages.get(convKey).length) return;
        const rws = wsClients.get(toId);
        if (rws?.readyState === WebSocket.OPEN) {
          const su = users.get(userId);
          rws.send(JSON.stringify(buildChatStartedPayload(su)));
        }
        break;
      }

      case 'send_file': {
        if (!userId) { ws.send(JSON.stringify({ type:'error', error:'Not authenticated' })); return; }
        const { to: toCode, fileName, fileSize, fileType, data } = msg;
        if (!isValidPublicCode(toCode)) return;
        const toId = pubcodes.get(toCode);
        if (!toId || !users.has(toId)) { ws.send(JSON.stringify({ type:'error', error:'User not found' })); return; }
        // Validate file data
        if (typeof data !== 'string' || !data.startsWith('data:')) { ws.send(JSON.stringify({ type:'error', error:'Invalid file data' })); return; }
        if (data.length > 28 * 1024 * 1024) { ws.send(JSON.stringify({ type:'error', error:'File too large (max 20 MB)' })); return; }
        const safeName = typeof fileName === 'string' ? fileName.replace(/[<>&"']/g,'').slice(0,255) : 'file';
        const safeSize = typeof fileSize === 'number' ? fileSize : 0;
        const safeType = typeof fileType === 'string' ? fileType.slice(0,100) : 'application/octet-stream';
        const fileSender = users.get(userId);
        const fileId = crypto.randomUUID();
        const ts = Date.now();
        const secret = getConversationSecret(userId, toId);
        const encrypted = encryptMessage(buildFilePreview(safeName), secret);
        const msgObj = {
          id: fileId,
          from: userId,
          to: toId,
          encrypted,
          timestamp: ts,
          kind: 'file',
          fileName: safeName,
          fileSize: safeSize,
          fileType: safeType,
          fileData: data
        };
        const convKey = getConvKey(userId, toId);
        const isFirst = !messages.has(convKey) || !messages.get(convKey).length;
        await saveMessage(convKey, msgObj);
        const recipientWs = wsClients.get(toId);
        if (isFirst && recipientWs?.readyState === WebSocket.OPEN) {
          recipientWs.send(JSON.stringify(buildChatStartedPayload(fileSender)));
        }
        if (recipientWs?.readyState === WebSocket.OPEN) {
          recipientWs.send(JSON.stringify({
            type:'new_file',
            id:fileId,
            from:fileSender.publicCode,
            fromName:fileSender.displayName||'',
            username:fileSender.username||'',
            avatar:fileSender.avatar||null,
            publicCode:fileSender.publicCode,
            displayName:fileSender.displayName||'',
            fileName:safeName,
            fileSize:safeSize,
            fileType:safeType,
            fileData:data,
            data,
            timestamp:ts
          }));
        }
        await sendPushToUser(toId, {
          data: {
            type: 'incoming_message',
            publicCode: fileSender.publicCode,
            displayName: fileSender.displayName || '',
            fromName: fileSender.displayName || '',
            username: fileSender.username || '',
            avatar: fileSender.avatar || '',
            fileName: safeName,
            text: buildFilePreview(safeName),
            timestamp: String(ts)
          },
          android: {
            priority: 'high',
            ttl: 60 * 60 * 1000,
            notification: {
              channelId: 'nxmsg_messages',
              sound: 'default'
            }
          }
        });
        ws.send(JSON.stringify({
          type:'file_sent',
          id:fileId,
          to:toCode,
          fileName:safeName,
          fileSize:safeSize,
          fileType:safeType,
          fileData:data,
          data,
          timestamp:ts
        }));
        break;
      }

      case 'call_offer': {
        if (!userId) { ws.send(JSON.stringify({ type: 'error', error: 'Not authenticated' })); return; }
        const toCode = String(msg.to || '').toUpperCase();
        if (!isValidPublicCode(toCode)) { ws.send(JSON.stringify({ type: 'error', error: 'Invalid recipient' })); return; }
        const toId = pubcodes.get(toCode);
        if (!toId || !users.has(toId)) { ws.send(JSON.stringify({ type: 'error', error: 'User not found' })); return; }
        const recipientWs = wsClients.get(toId);
        const hasPushTarget = (deviceTokens.get(toId)?.size || 0) > 0;
        if ((!recipientWs || recipientWs.readyState !== WebSocket.OPEN) && !hasPushTarget) {
          ws.send(JSON.stringify({ type: 'error', error: 'Recipient is unavailable' }));
          return;
        }
        const senderUser = users.get(userId);
        if (recipientWs?.readyState === WebSocket.OPEN) {
          recipientWs.send(JSON.stringify({
            type: 'incoming_call',
            from: senderUser.publicCode,
            publicCode: senderUser.publicCode,
            fromName: senderUser.displayName || '',
            displayName: senderUser.displayName || '',
            username: senderUser.username || '',
            avatar: senderUser.avatar || null,
            video: !!msg.video,
            timestamp: Date.now()
          }));
        }
        await sendPushToUser(toId, {
          data: {
            type: 'incoming_call',
            publicCode: senderUser.publicCode,
            displayName: senderUser.displayName || '',
            fromName: senderUser.displayName || '',
            username: senderUser.username || '',
            avatar: senderUser.avatar || '',
            video: String(!!msg.video),
            timestamp: String(Date.now())
          },
          android: {
            priority: 'high',
            ttl: 30000,
            notification: {
              channelId: 'nxmsg_calls',
              sound: 'default'
            }
          }
        });
        ws.send(JSON.stringify({
          type: 'call_ringing',
          to: toCode,
          video: !!msg.video,
          timestamp: Date.now()
        }));
        break;
      }

      case 'call_answer': {
        if (!userId) return;
        const toCode = String(msg.to || '').toUpperCase();
        if (!isValidPublicCode(toCode)) return;
        const toId = pubcodes.get(toCode);
        const recipientWs = toId ? wsClients.get(toId) : null;
        if (recipientWs?.readyState === WebSocket.OPEN) {
          recipientWs.send(JSON.stringify({
            type: 'call_answer',
            from: users.get(userId)?.publicCode || '',
            publicCode: users.get(userId)?.publicCode || '',
            video: !!msg.video,
            timestamp: Date.now()
          }));
        }
        break;
      }

      case 'call_end': {
        if (!userId) return;
        const toCode = String(msg.to || '').toUpperCase();
        if (!isValidPublicCode(toCode)) return;
        const toId = pubcodes.get(toCode);
        const recipientWs = toId ? wsClients.get(toId) : null;
        if (recipientWs?.readyState === WebSocket.OPEN) {
          recipientWs.send(JSON.stringify({
            type: 'call_end',
            from: users.get(userId)?.publicCode || '',
            publicCode: users.get(userId)?.publicCode || '',
            video: !!msg.video,
            timestamp: Date.now()
          }));
        }
        break;
      }

      case 'ping':
        ws.send(JSON.stringify({ type: 'pong' }));
        break;
    }
  });

  ws.on('close', () => {
    if (userId) { wsClients.delete(userId); broadcastOnlineStatus(userId, false); }
  });
  ws.on('error', () => {
    if (userId) wsClients.delete(userId);
  });
});

function broadcastOnlineStatus(userId, online) {
  const u = users.get(userId);
  for (const [key] of messages) {
    const [a, b] = key.split('::');
    const other = a === userId ? b : b === userId ? a : null;
    if (!other) continue;
    const ows = wsClients.get(other);
    if (ows?.readyState === WebSocket.OPEN) {
      ows.send(JSON.stringify({ type: 'status_change', publicCode: u?.publicCode, online }));
    }
  }
}

const PORT = process.env.PORT || 3000;
(async () => {
  try {
    await initDB();
    await loadFromDB();
    initFirebaseAdmin();
  } catch (e) {
    console.error('DB init failed:', e.message);
    console.error('Running without persistent DB (data will be lost on restart)');
  }
  server.listen(PORT, () => console.log(`🔒 NXMSG server listening on port ${PORT}`));
})();
