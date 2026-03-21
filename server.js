const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self' ws: wss:");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// ─── PERSISTENCE ────────────────────────────────────────
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE    = path.join(DATA_DIR, 'users.json');
const MESSAGES_FILE = path.join(DATA_DIR, 'messages.json');
const PUBCODES_FILE = path.join(DATA_DIR, 'pubcodes.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function loadJSON(file) {
  try {
    if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) { console.error('Load error', file, e.message); }
  return {};
}

function debounceWrite(file, getData, timers) {
  clearTimeout(timers[file]);
  timers[file] = setTimeout(() => {
    try { fs.writeFileSync(file, JSON.stringify(getData()), 'utf8'); }
    catch (e) { console.error('Write error', file, e.message); }
  }, 300);
}

const _timers = {};
const saveUsers    = () => debounceWrite(USERS_FILE,    () => Object.fromEntries(users),    _timers);
const saveMessages = () => debounceWrite(MESSAGES_FILE, () => Object.fromEntries(messages), _timers);
const savePubcodes = () => debounceWrite(PUBCODES_FILE, () => Object.fromEntries(pubcodes), _timers);

// In-memory stores
// users    : userId  -> { id, passwordHash, displayName, registeredAt, publicCode }
// pubcodes : publicCode -> userId   (reverse lookup)
// messages : convKey -> [{ id, from, to, encrypted, timestamp }]
const users    = new Map(Object.entries(loadJSON(USERS_FILE)));
const pubcodes = new Map(Object.entries(loadJSON(PUBCODES_FILE)));
const messages = new Map(Object.entries(loadJSON(MESSAGES_FILE)));
const wsClients = new Map();   // userId -> ws  (runtime only)
// Session tokens: token -> { userId, expiresAt }
const sessions = new Map();

console.log(`📂 Loaded ${users.size} users, ${messages.size} conversations`);

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
  if (s.expiresAt < Date.now()) { sessions.delete(token); return null; }
  return s.userId;
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

  const safeName = typeof displayName === 'string'
    ? displayName.replace(/[<>&"'`\/=]/g, '').trim().slice(0, 32)
    : '';

  users.set(userId, { id: userId, passwordHash, displayName: safeName, registeredAt: Date.now(), publicCode });
  pubcodes.set(publicCode, userId);
  saveUsers();
  savePubcodes();

  const token = generateSessionToken();
  sessions.set(token, { userId, expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000 }); // 30 days

  res.json({ publicCode, token, displayName: safeName });
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
    await bcrypt.compare('dummy', '$2b$12$invalidhashpaddingtostoptimingatk');
    return res.status(401).json({ error: 'Неверный код или пароль' });
  }

  const user = users.get(userId);
  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) {
    return res.status(401).json({ error: 'Неверный код или пароль' });
  }

  const token = generateSessionToken();
  sessions.set(token, { userId, expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000 });

  res.json({ token, displayName: user.displayName || '', publicCode });
});

// Validate existing session token -> { valid, displayName, publicCode }
app.post('/api/session', (req, res) => {
  const { token } = req.body;
  const userId = resolveSession(token);
  if (!userId || !users.has(userId)) return res.json({ valid: false });
  const u = users.get(userId);
  res.json({ valid: true, displayName: u.displayName || '', bio: u.bio || '', publicCode: u.publicCode });
});

// Lookup user by public code (for starting a chat) — returns exists + displayName only
app.get('/api/user/bycode/:code', (req, res) => {
  const code = req.params.code.toUpperCase();
  if (!isValidPublicCode(code)) return res.status(400).json({ error: 'Invalid code' });
  const userId = pubcodes.get(code);
  if (!userId || !users.has(userId)) return res.json({ exists: false });
  const u = users.get(userId);
  res.json({ exists: true, online: wsClients.has(userId), displayName: u.displayName || '', bio: u.bio || '', publicCode: code });
});

// Update display name (authenticated)
app.patch('/api/user/name', (req, res) => {
  const userId = resolveSession(req.body.token);
  if (!userId || !users.has(userId)) return res.status(401).json({ error: 'Unauthorized' });
  const { name } = req.body;
  if (typeof name !== 'string') return res.status(400).json({ error: 'Invalid name' });
  const safeName = name.replace(/[<>&"'`\/=]/g, '').trim().slice(0, 32);
  const { bio } = req.body;
  const safeBio = typeof bio === 'string' ? bio.replace(/[<>&"']/g, '').trim().slice(0, 80) : users.get(userId).bio || '';
  users.get(userId).displayName = safeName;
  users.get(userId).bio = safeBio;
  saveUsers();
  // Broadcast name change
  for (const [key] of messages) {
    const [a, b] = key.split('::');
    const other = a === userId ? b : b === userId ? a : null;
    if (!other) continue;
    const ows = wsClients.get(other);
    if (ows && ows.readyState === WebSocket.OPEN) {
      ows.send(JSON.stringify({ type: 'name_changed', publicCode: users.get(userId).publicCode, displayName: safeName }));
    }
  }
  res.json({ ok: true, displayName: safeName, bio: safeBio });
});

// Upload / update avatar
app.post('/api/user/avatar', (req, res) => {
  const userId = resolveSession(req.body.token);
  if (!userId || !users.has(userId)) return res.status(401).json({ error: 'Unauthorized' });
  const { avatar } = req.body;
  if (typeof avatar !== 'string') return res.status(400).json({ error: 'Invalid avatar' });
  // Accept only data URLs with image MIME type — basic validation
  if (!avatar.startsWith('data:image/')) return res.status(400).json({ error: 'Must be an image' });
  // ~2 MB limit on base64 string (~2.7 MB raw) 
  if (avatar.length > 3 * 1024 * 1024) return res.status(400).json({ error: 'Image too large (max 2 MB)' });
  users.get(userId).avatar = avatar;
  saveUsers();
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
app.delete('/api/user/avatar', (req, res) => {
  const userId = resolveSession(req.body.token);
  if (!userId || !users.has(userId)) return res.status(401).json({ error: 'Unauthorized' });
  delete users.get(userId).avatar;
  saveUsers();
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
    const lastText = lastMsg ? (decryptMessage(lastMsg.encrypted, secret) || '') : '';
    contacts.push({
      publicCode: cu.publicCode,
      displayName: cu.displayName || '',
      bio: cu.bio || '',
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
  const decrypted = raw.map(m => ({
    id: m.id,
    mine: m.from === userId,
    text: decryptMessage(m.encrypted, secret) || '[decryption failed]',
    timestamp: m.timestamp
  }));
  res.json(decrypted);
});

// ─── WEBSOCKET ──────────────────────────────────────────
wss.on('connection', (ws) => {
  let userId = null; // internal ID — resolved from session token

  ws.on('message', (rawData) => {
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

        const msgObj = { id: crypto.randomUUID(), from: userId, to: toId, encrypted, timestamp: Date.now() };
        const convKey = getConvKey(userId, toId);
        const isFirst = !messages.has(convKey) || !messages.get(convKey).length;
        if (!messages.has(convKey)) messages.set(convKey, []);
        messages.get(convKey).push(msgObj);
        saveMessages();

        const senderUser = users.get(userId);
        const recipientWs = wsClients.get(toId);

        if (isFirst && recipientWs?.readyState === WebSocket.OPEN) {
          recipientWs.send(JSON.stringify({
            type: 'chat_started',
            fromCode: senderUser.publicCode,
            fromName: senderUser.displayName || '',
            online: true
          }));
        }

        if (recipientWs?.readyState === WebSocket.OPEN) {
          recipientWs.send(JSON.stringify({
            type: 'new_message',
            id: msgObj.id,
            from: senderUser.publicCode,
            fromName: senderUser.displayName || '',
            text: safeText,
            timestamp: msgObj.timestamp
          }));
        }

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
          rws.send(JSON.stringify({ type: 'chat_started', fromCode: su.publicCode, fromName: su.displayName || '', online: true }));
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
        const senderUser2 = users.get(userId);
        const fileId = crypto.randomUUID();
        const ts = Date.now();
        const recipientWs = wsClients.get(toId);
        if (recipientWs?.readyState === WebSocket.OPEN) {
          recipientWs.send(JSON.stringify({ type:'new_file', id:fileId, from:senderUser.publicCode, fromName:senderUser.displayName||'', fileName:safeName, fileSize:safeSize, fileType:safeType, data, timestamp:ts }));
        }
        ws.send(JSON.stringify({ type:'file_sent', id:fileId, to:toCode, fileName:safeName, fileSize:safeSize, fileType:safeType, data, timestamp:ts }));
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
server.listen(PORT, () => console.log(`🔒 NXMSG running on http://localhost:${PORT}`));
