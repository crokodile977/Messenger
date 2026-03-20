const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const crypto = require('crypto');
const path = require('path');

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

// In-memory stores
const users = new Map();       // userId -> { id, publicKey, connectedAt }
const messages = new Map();    // conversationKey -> [messages]
const wsClients = new Map();   // userId -> ws

// Generate a cryptographically secure unique ID (~20 chars, letters + special chars)
function generateUserId() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_+=~';
  let id = '';
  const bytes = crypto.randomBytes(24);
  for (let i = 0; i < 20; i++) {
    id += chars[bytes[i] % chars.length];
  }
  return id;
}

// Encrypt message content server-side (AES-256-GCM)
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

// Derive shared secret for a conversation
function getConversationSecret(id1, id2) {
  const sorted = [id1, id2].sort().join('|');
  return crypto.createHmac('sha256', 'messenger-secret-key-2024').update(sorted).digest('hex');
}

// Conversation key (sorted so A->B and B->A use same key)
function getConvKey(id1, id2) {
  return [id1, id2].sort().join('::');
}

// Sanitize text — strip all HTML tags and dangerous chars to prevent XSS/injection
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
    .slice(0, 4000); // max message length
}

// Validate user ID format
function isValidUserId(id) {
  if (typeof id !== 'string') return false;
  if (id.length < 18 || id.length > 24) return false;
  const allowed = /^[A-Za-z0-9!@#$%^&*\-_+=~]+$/;
  return allowed.test(id);
}

// REST: Register new user
app.post('/api/register', (req, res) => {
  const userId = generateUserId();
  users.set(userId, {
    id: userId,
    registeredAt: Date.now()
  });
  res.json({ userId });
});

// REST: Check if user exists
app.get('/api/user/:id', (req, res) => {
  const id = req.params.id;
  if (!isValidUserId(id)) return res.status(400).json({ error: 'Invalid ID format' });
  if (users.has(id)) {
    res.json({ exists: true, online: wsClients.has(id) });
  } else {
    res.json({ exists: false });
  }
});

// REST: Get message history for a conversation
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

// WebSocket handling
wss.on('connection', (ws) => {
  let authenticatedUserId = null;

  ws.on('message', (rawData) => {
    let msg;
    try {
      // Strict JSON parse only — no eval, no dynamic execution
      msg = JSON.parse(rawData.toString());
    } catch {
      ws.send(JSON.stringify({ type: 'error', error: 'Invalid message format' }));
      return;
    }

    // Validate message type is a plain string
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

        // Notify contacts that this user came online
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

        // Sanitize text BEFORE encryption — strip HTML/JS injection vectors
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
        if (!messages.has(convKey)) messages.set(convKey, []);
        messages.get(convKey).push(msgObj);

        // Deliver to recipient if online
        const recipientWs = wsClients.get(toId);
        const deliveryPayload = {
          type: 'new_message',
          id: msgObj.id,
          from: authenticatedUserId,
          text: safeText, // already sanitized plain text
          timestamp: msgObj.timestamp
        };

        if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
          recipientWs.send(JSON.stringify(deliveryPayload));
        }

        // Confirm delivery to sender
        ws.send(JSON.stringify({
          type: 'message_sent',
          id: msgObj.id,
          to: toId,
          text: safeText,
          timestamp: msgObj.timestamp
        }));
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
  // Notify all conversations this user is part of
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
