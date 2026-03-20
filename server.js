const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Security headers
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self' ws: wss:");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// ─── PERSISTENCE ────────────────────────────────────────
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const MESSAGES_FILE = path.join(DATA_DIR, 'messages.json');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// Load users from disk
function loadUsers() {
  try {
    if (fs.existsSync(USERS_FILE)) {
      const raw = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
      return new Map(Object.entries(raw));
    }
  } catch (e) { console.error('Failed to load users:', e.message); }
  return new Map();
}

// Load messages from disk
function loadMessages() {
  try {
    if (fs.existsSync(MESSAGES_FILE)) {
      const raw = JSON.parse(fs.readFileSync(MESSAGES_FILE, 'utf8'));
      return new Map(Object.entries(raw));
    }
  } catch (e) { console.error('Failed to load messages:', e.message); }
  return new Map();
}

// Debounced save — coalesces rapid writes into one
let saveUsersTimer = null;
let saveMessagesTimer = null;

function saveUsers() {
  clearTimeout(saveUsersTimer);
  saveUsersTimer = setTimeout(() => {
    try {
      const obj = Object.fromEntries(users);
      fs.writeFileSync(USERS_FILE, JSON.stringify(obj), 'utf8');
    } catch (e) { console.error('Failed to save users:', e.message); }
  }, 300);
}

function saveMessages() {
  clearTimeout(saveMessagesTimer);
  saveMessagesTimer = setTimeout(() => {
    try {
      const obj = Object.fromEntries(messages);
      fs.writeFileSync(MESSAGES_FILE, JSON.stringify(obj), 'utf8');
    } catch (e) { console.error('Failed to save messages:', e.message); }
  }, 300);
}

// In-memory stores — pre-loaded from disk
const users = loadUsers();
const messages = loadMessages();
const wsClients = new Map();   // userId -> ws  (never persisted — runtime only)

console.log(`📂 Loaded ${users.size} users, ${messages.size} conversations from disk`);

// ─── CRYPTO HELPERS ────────────────────────────────────

function generateUserId() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_+=~';
  let id = '';
  const bytes = crypto.randomBytes(24);
  for (let i = 0; i < 20; i++) {
    id += chars[bytes[i] % chars.length];
  }
  return id;
}

function encryptMessage(text, sharedSecret) {
  const key = crypto.createHash('sha256').update(sharedSecret).digest();
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return iv.toString('hex') + ':' + tag.toString('hex') + ':' + encrypted.toString('hex');
}

function decryptMessage(encryptedData, sharedSecret) {
  try {
    const parts = encryptedData.split(':');
    if (parts.length !== 3) return null;
    const [ivHex, tagHex, dataHex] = parts;
    const key = crypto.createHash('sha256').update(sharedSecret).digest();
    const iv = Buffer.from(ivHex, 'hex');
    const tag = Buffer.from(tagHex, 'hex');
    const data = Buffer.from(dataHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    return decipher.update(data) + decipher.final('utf8');
  } catch {
    return null;
  }
}

function getConversationSecret(id1, id2) {
  const sorted = [id1, id2].sort().join('|');
  return crypto.createHmac('sha256', 'messenger-secret-key-2024').update(sorted).digest('hex');
}

function getConvKey(id1, id2) {
  return [id1, id2].sort().join('::');
}

function sanitizeText(input) {
  if (typeof input !== 'string') return '';
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;')
    .replace(/`/g, '&#x60;')
    .replace(/=/g, '&#x3D;')
    .slice(0, 4000);
}

function isValidUserId(id) {
  if (typeof id !== 'string') return false;
  if (id.length < 18 || id.length > 24) return false;
  return /^[A-Za-z0-9!@#$%^&*\-_+=~]+$/.test(id);
}

// ─── REST API ───────────────────────────────────────────

// Register new user
app.post('/api/register', (req, res) => {
  const userId = generateUserId();
  users.set(userId, { id: userId, registeredAt: Date.now(), displayName: '' });
  saveUsers();
  res.json({ userId });
});

// Check if user exists
app.get('/api/user/:id', (req, res) => {
  const id = req.params.id;
  if (!isValidUserId(id)) return res.status(400).json({ error: 'Invalid ID format' });
  if (users.has(id)) {
    const u = users.get(id);
    res.json({ exists: true, online: wsClients.has(id), displayName: u.displayName || '' });
  } else {
    res.json({ exists: false });
  }
});

// Update display name
app.patch('/api/user/:id/name', (req, res) => {
  const id = req.params.id;
  if (!isValidUserId(id)) return res.status(400).json({ error: 'Invalid ID format' });
  if (!users.has(id)) return res.status(404).json({ error: 'User not found' });
  const { name } = req.body;
  if (typeof name !== 'string') return res.status(400).json({ error: 'Invalid name' });
  const safeName = name.replace(/[<>&"'`\/=]/g, '').trim().slice(0, 32);
  users.get(id).displayName = safeName;
  saveUsers();
  // Broadcast name change to online contacts
  for (const [key] of messages) {
    const [a, b] = key.split('::');
    const otherId = a === id ? b : b === id ? a : null;
    if (!otherId) continue;
    const otherWs = wsClients.get(otherId);
    if (otherWs && otherWs.readyState === WebSocket.OPEN) {
      otherWs.send(JSON.stringify({ type: 'name_changed', userId: id, displayName: safeName }));
    }
  }
  res.json({ ok: true, displayName: safeName });
});

// Get all contacts for a user (everyone they've had a conversation with)
app.get('/api/contacts/:userId', (req, res) => {
  const userId = req.params.userId;
  if (!isValidUserId(userId)) return res.status(400).json({ error: 'Invalid ID format' });
  if (!users.has(userId)) return res.status(404).json({ error: 'User not found' });

  const contacts = [];
  for (const [key, msgs] of messages) {
    const [a, b] = key.split('::');
    if (a !== userId && b !== userId) continue;
    const contactId = a === userId ? b : a;
    if (!users.has(contactId)) continue;

    const contactUser = users.get(contactId);
    const lastMsg = msgs.length > 0 ? msgs[msgs.length - 1] : null;
    const secret = getConversationSecret(userId, contactId);
    const lastText = lastMsg
      ? (decryptMessage(lastMsg.encrypted, secret) || '')
      : '';

    contacts.push({
      contactId,
      displayName: contactUser.displayName || '',
      online: wsClients.has(contactId),
      lastTimestamp: lastMsg ? lastMsg.timestamp : 0,
      lastText,
      lastFrom: lastMsg ? lastMsg.from : null,
      messageCount: msgs.length
    });
  }

  // Sort by last message time descending
  contacts.sort((a, b) => b.lastTimestamp - a.lastTimestamp);
  res.json(contacts);
});

// Get message history for a conversation
app.get('/api/messages/:myId/:theirId', (req, res) => {
  const { myId, theirId } = req.params;
  if (!isValidUserId(myId) || !isValidUserId(theirId)) {
    return res.status(400).json({ error: 'Invalid ID format' });
  }
  if (!users.has(myId) || !users.has(theirId)) {
    return res.status(404).json({ error: 'User not found' });
  }
  const key = getConvKey(myId, theirId);
  const secret = getConversationSecret(myId, theirId);
  const raw = messages.get(key) || [];
  const decrypted = raw.map(m => ({
    ...m,
    text: decryptMessage(m.encrypted, secret) || '[decryption failed]',
    encrypted: undefined
  }));
  res.json(decrypted);
});

// ─── WEBSOCKET ──────────────────────────────────────────
wss.on('connection', (ws) => {
  let authenticatedUserId = null;

  ws.on('message', (rawData) => {
    let msg;
    try {
      msg = JSON.parse(rawData.toString());
    } catch {
      ws.send(JSON.stringify({ type: 'error', error: 'Invalid message format' }));
      return;
    }

    if (typeof msg.type !== 'string') {
      ws.send(JSON.stringify({ type: 'error', error: 'Invalid type' }));
      return;
    }

    switch (msg.type) {
      case 'auth': {
        const userId = msg.userId;
        if (!isValidUserId(userId) || !users.has(userId)) {
          ws.send(JSON.stringify({ type: 'error', error: 'Authentication failed' }));
          return;
        }
        authenticatedUserId = userId;
        wsClients.set(userId, ws);
        ws.send(JSON.stringify({ type: 'auth_ok', userId }));
        broadcastOnlineStatus(userId, true);
        break;
      }

      case 'send_message': {
        if (!authenticatedUserId) {
          ws.send(JSON.stringify({ type: 'error', error: 'Not authenticated' }));
          return;
        }
        const toId = msg.to;
        const text = msg.text;

        if (!isValidUserId(toId)) {
          ws.send(JSON.stringify({ type: 'error', error: 'Invalid recipient ID' }));
          return;
        }
        if (!users.has(toId)) {
          ws.send(JSON.stringify({ type: 'error', error: 'User not found' }));
          return;
        }
        if (typeof text !== 'string' || text.trim().length === 0) {
          ws.send(JSON.stringify({ type: 'error', error: 'Empty message' }));
          return;
        }

        const safeText = sanitizeText(text.trim());
        const secret = getConversationSecret(authenticatedUserId, toId);
        const encrypted = encryptMessage(safeText, secret);

        const msgObj = {
          id: crypto.randomUUID(),
          from: authenticatedUserId,
          to: toId,
          encrypted,
          timestamp: Date.now()
        };

        const convKey = getConvKey(authenticatedUserId, toId);
        const isFirstMessage = !messages.has(convKey) || messages.get(convKey).length === 0;
        if (!messages.has(convKey)) messages.set(convKey, []);
        messages.get(convKey).push(msgObj);
        saveMessages(); // persist immediately

        const recipientWs = wsClients.get(toId);

        if (isFirstMessage && recipientWs && recipientWs.readyState === WebSocket.OPEN) {
          recipientWs.send(JSON.stringify({
            type: 'chat_started',
            fromId: authenticatedUserId,
            fromName: users.get(authenticatedUserId)?.displayName || '',
            online: true
          }));
        }

        const senderName = users.get(authenticatedUserId)?.displayName || '';
        const deliveryPayload = {
          type: 'new_message',
          id: msgObj.id,
          from: authenticatedUserId,
          fromName: senderName,
          text: safeText,
          timestamp: msgObj.timestamp
        };

        if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
          recipientWs.send(JSON.stringify(deliveryPayload));
        }

        ws.send(JSON.stringify({
          type: 'message_sent',
          id: msgObj.id,
          to: toId,
          text: safeText,
          timestamp: msgObj.timestamp
        }));
        break;
      }

      case 'start_chat': {
        if (!authenticatedUserId) return;
        const toId = msg.to;
        if (!isValidUserId(toId) || !users.has(toId)) return;

        const convKey = getConvKey(authenticatedUserId, toId);
        const alreadyHasMessages = messages.has(convKey) && messages.get(convKey).length > 0;

        if (!alreadyHasMessages) {
          const recipientWs = wsClients.get(toId);
          if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
            recipientWs.send(JSON.stringify({
              type: 'chat_started',
              fromId: authenticatedUserId,
              fromName: users.get(authenticatedUserId)?.displayName || '',
              online: true
            }));
          }
        }
        break;
      }

      case 'ping':
        ws.send(JSON.stringify({ type: 'pong' }));
        break;

      default:
        ws.send(JSON.stringify({ type: 'error', error: 'Unknown message type' }));
    }
  });

  ws.on('close', () => {
    if (authenticatedUserId) {
      wsClients.delete(authenticatedUserId);
      broadcastOnlineStatus(authenticatedUserId, false);
    }
  });

  ws.on('error', () => {
    if (authenticatedUserId) wsClients.delete(authenticatedUserId);
  });
});

function broadcastOnlineStatus(userId, online) {
  for (const [key] of messages) {
    const [a, b] = key.split('::');
    const otherId = a === userId ? b : b === userId ? a : null;
    if (!otherId) continue;
    const otherWs = wsClients.get(otherId);
    if (otherWs && otherWs.readyState === WebSocket.OPEN) {
      otherWs.send(JSON.stringify({ type: 'status_change', userId, online }));
    }
  }
}

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🔒 Secure Messenger running on http://localhost:${PORT}`);
});
