// exit-node.js – Express version of the Deno exit node handler
// Run with Node.js 18+ (supports global fetch) or install node-fetch.
//
// Usage:
//   1. Set environment variable EXIT_NODE_PSK to a strong secret.
//   2. node exit-node.js
//   3. The server listens on port 3000 (change via PORT env).
//
// Endpoint: POST /  (any path works, but root is fine)
// Body: JSON with fields k (PSK), u (destination URL), m (method),
//       h (headers object), b (base64 body, optional).
//
// Returns JSON: { s: status, h: headers, b: base64 body } or { e: error }

import express from 'express';

const app = express();

// Increase JSON payload limit if needed; 10MB is reasonable.
app.use(express.json({ limit: '10mb' }));

// Headers that are stripped before forwarding (hop‑by‑hop or internal).
const STRIP_HEADERS = new Set([
  'host',
  'connection',
  'content-length',
  'transfer-encoding',
  'proxy-connection',
  'proxy-authorization',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-proto',
  'x-forwarded-port',
  'x-real-ip',
  'forwarded',
  'via',
]);

// Helper: base64 string → Uint8Array (Node.js Buffer)
function decodeBase64ToBytes(base64) {
  return new Uint8Array(Buffer.from(base64, 'base64'));
}

// Helper: Uint8Array → base64 string
function encodeBytesToBase64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

// Filter incoming headers: keep only safe ones
function sanitizeHeaders(headers) {
  const out = {};
  if (!headers || typeof headers !== 'object') return out;
  for (const [key, value] of Object.entries(headers)) {
    if (!key) continue;
    if (STRIP_HEADERS.has(key.toLowerCase())) continue;
    out[key] = String(value ?? '');
  }
  return out;
}

// Main request handler
app.all('*', async (req, res) => {
  // Read PSK from environment; fallback to a placeholder (safe by default)
  const PSK = process.env.EXIT_NODE_PSK || 'CHANGE_ME_TO_A_STRONG_SECRET';

  // Fail closed if still using the placeholder
  if (PSK === 'CHANGE_ME_TO_A_STRONG_SECRET') {
    return res.status(503).json({
      e: 'exit_node misconfigured: EXIT_NODE_PSK environment variable is not set or still the placeholder. Set a strong secret before deploying.',
    });
  }

  // Only POST is allowed
  if (req.method !== 'POST') {
    return res.status(405).json({ e: 'method_not_allowed' });
  }

  try {
    const body = req.body;
    if (!body || typeof body !== 'object') {
      return res.status(400).json({ e: 'bad_json' });
    }

    const k = String(body.k ?? '');
    const u = String(body.u ?? '');
    const m = String(body.m ?? 'GET').toUpperCase();
    const h = sanitizeHeaders(body.h);
    const b64 = body.b;

    // Authentication
    if (k !== PSK) {
      return res.status(401).json({ e: 'unauthorized' });
    }

    // Basic URL validation
    if (!/^https?:\/\//i.test(u)) {
      return res.status(400).json({ e: 'bad url' });
    }

    // Loop guard: prevent forwarding to this same exit node instance
    try {
      const reqUrl = new URL(`${req.protocol}://${req.get('host')}${req.originalUrl}`);
      const dstUrl = new URL(u);
      if (reqUrl.host === dstUrl.host && reqUrl.protocol === dstUrl.protocol) {
        return res.status(400).json({ e: 'exit-node loop refused' });
      }
    } catch {
      // Malformed URL – will be caught by fetch below
    }

    // Decode body if provided
    let payload;
    if (typeof b64 === 'string' && b64.length > 0) {
      payload = decodeBase64ToBytes(b64);
    }

    // Forward the request (Node 18+ global fetch)
    const resp = await fetch(u, {
      method: m,
      headers: h,
      body: payload,
      redirect: 'manual',
    });

    const data = new Uint8Array(await resp.arrayBuffer());

    // Convert headers to plain object
    const respHeaders = {};
    resp.headers.forEach((value, key) => {
      respHeaders[key] = value;
    });

    // Respond with status, headers, and base64 body
    return res.json({
      s: resp.status,
      h: respHeaders,
      b: encodeBytesToBase64(data),
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ e: message });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Exit node listening on port ${PORT}`);
});