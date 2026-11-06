// ============================================================
// OSSMO AI — Cloudflare Worker Backend
// Single-file API: auth + chat (Claude Haiku 5.5 streaming) + expenses + R2 upload
// Uses: Hono framework, Web Crypto for JWT + password hashing,
//       Supabase REST API for database, R2 binding for file storage,
//       meshapi.ai (OpenAI-compatible) for Claude.
// ============================================================/

import { Hono } from 'hono';
import { cors } from 'hono/cors';

const app = new Hono();

// ---------- Bindings & env (defined in wrangler.toml) ----------
// env.SUPABASE_URL, env.SUPABASE_SERVICE_KEY
// env.MESH_API_KEY, env.MESH_API_BASE_URL, env.ANTHROPIC_MODEL
// env.JWT_SECRET
// env.OSSMO_BUCKET (R2 binding)

// ---------- CORS ----------
app.use('*', cors({
  origin: (origin) => origin || '*',
  allowHeaders: ['Content-Type', 'Authorization'],
  allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  credentials: true,
  maxAge: 86400,
}));

// ---------- Rate limiting (in-memory per-isolate) ----------
const rateMap = new Map();
function rateLimit(ip, max = 5, windowMs = 60000) {
  const now = Date.now();
  const rec = rateMap.get(ip);
  if (!rec || rec.until < now) {
    rateMap.set(ip, { count: 1, until: now + windowMs });
    return true;
  }
  if (rec.count >= max) return false;
  rec.count++;
  return true;
}

function getClientIP(c) {
  return c.req.header('x-forwarded-for')?.split(',')[0]?.trim() || c.req.header('cf-connecting-ip') || 'unknown';
}

// ============================================================
// AUTH HELPERS (Web Crypto API)
// ============================================================

// PBKDF2 password hashing (works in Workers free tier, no CPU limit issues like bcrypt)
async function hashPassword(plain) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(plain), 'PBKDF2', false, ['deriveBits']);
  const hash = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
  const hashHex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
  return `pbkdf2$100000$${saltHex}$${hashHex}`;
}

async function verifyPassword(plain, stored) {
  const parts = stored.split('$');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2') return false;
  const iterations = parseInt(parts[1]);
  const salt = new Uint8Array(parts[2].match(/.{2}/g).map(b => parseInt(b, 16)));
  const storedHash = parts[3];
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(plain), 'PBKDF2', false, ['deriveBits']);
  const hash = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  const hashHex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex === storedHash;
}

// JWT using HMAC-SHA256 (Web Crypto)
async function signToken(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const enc = new TextEncoder();
  const headerB64 = btoa(JSON.stringify(header)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const payloadB64 = btoa(JSON.stringify({ ...payload, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 7 * 86400 }))
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const data = `${headerB64}.${payloadB64}`;
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${data}.${sigB64}`;
}

async function verifyToken(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [headerB64, payloadB64, sigB64] = parts;
    const data = `${headerB64}.${payloadB64}`;
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const sig = Uint8Array.from(atob(sigB64.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sig, enc.encode(data));
    if (!valid) return null;
    const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}

const COOKIE_NAME = 'ossmo_session';

async function setSessionCookie(c, payload, secret) {
  const token = await signToken(payload, secret);
  // SameSite=None required for cross-origin (frontend on different domain than worker)
  c.header('Set-Cookie', `${COOKIE_NAME}=${token}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=604800`);
  return token;
}

function clearSessionCookie(c) {
  c.header('Set-Cookie', `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0`);
}

function getCookie(c, name) {
  const cookie = c.req.header('cookie') || '';
  const match = cookie.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return match ? match[1] : null;
}

async function getSession(c, env) {
  const token = getCookie(c, COOKIE_NAME);
  if (!token) return null;
  return verifyToken(token, env.JWT_SECRET);
}

async function requireAuth(c, env) {
  const session = await getSession(c, env);
  if (!session) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
  c.set('userId', session.uid);
  c.set('email', session.email);
  return null;
}

// ============================================================
// SUPABASE REST API HELPERS
// ============================================================

async function supabase(env, path, opts = {}) {
  const url = `${env.SUPABASE_URL}/rest/v1${path}`;
  const res = await fetch(url, {
    ...opts,
    headers: {
      'apikey': env.SUPABASE_SERVICE_KEY,
      'Authorization': `Bearer ${env.SUPABASE_SERVICE_KEY}`,
      'Content-Type': 'application/json',
      'Prefer': opts.method === 'POST' ? 'return=representation' : 'return=representation',
      ...(opts.headers || {}),
    },
  });
  return res;
}

async function getUserById(env, userId) {
  const res = await supabase(env, `/users?id=eq.${userId}&select=*`, { method: 'GET' });
  const arr = await res.json();
  return arr && arr.length > 0 ? arr[0] : null;
}

// ============================================================
// ROUTES: AUTH
// ============================================================

app.post('/api/auth/signup', async (c) => {
  const env = c.env;
  const ip = getClientIP(c);
  if (!rateLimit(ip, 5)) return c.json({ error: 'Too many attempts. Try again in a minute.' }, 429);

  let body;
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid JSON' }, 400); }
  const email = String(body.email || '').toLowerCase().trim();
  const password = String(body.password || '');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 6) {
    return c.json({ error: 'Invalid email or password (min 6 chars)' }, 400);
  }

  // Check if exists
  const existRes = await supabase(env, `/users?email=eq.${encodeURIComponent(email)}&select=id`, { method: 'GET' });
  const existArr = await existRes.json();
  if (existArr && existArr.length > 0) {
    return c.json({ error: 'Account already exists. Please sign in.' }, 409);
  }

  const passwordHash = await hashPassword(password);
  const insertRes = await supabase(env, '/users', {
    method: 'POST',
    body: JSON.stringify({ email, password_hash: passwordHash, is_onboarded: false }),
  });
  const inserted = await insertRes.json();
  if (!inserted || !inserted[0]) {
    return c.json({ error: 'Failed to create user' }, 500);
  }
  const user = inserted[0];
  await setSessionCookie(c, { uid: user.id, email: user.email }, env.JWT_SECRET);
  return c.json({ user: { id: user.id, email: user.email, isOnboarded: false } });
});

app.post('/api/auth/signin', async (c) => {
  const env = c.env;
  const ip = getClientIP(c);
  if (!rateLimit(ip, 5)) return c.json({ error: 'Too many attempts. Try again in a minute.' }, 429);

  let body;
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid JSON' }, 400); }
  const email = String(body.email || '').toLowerCase().trim();
  const password = String(body.password || '');
  if (!email || !password) return c.json({ error: 'Invalid email or password' }, 400);

  const res = await supabase(env, `/users?email=eq.${encodeURIComponent(email)}&select=*`, { method: 'GET' });
  const arr = await res.json();
  if (!arr || arr.length === 0) return c.json({ error: 'Invalid email or password' }, 401);
  const user = arr[0];
  if (!user.password_hash) return c.json({ error: 'Invalid email or password' }, 401);
  const ok = await verifyPassword(password, user.password_hash);
  if (!ok) return c.json({ error: 'Invalid email or password' }, 401);

  await setSessionCookie(c, { uid: user.id, email: user.email }, env.JWT_SECRET);
  return c.json({
    user: {
      id: user.id, email: user.email, name: user.name,
      isOnboarded: !!user.is_onboarded,
    },
  });
});

app.post('/api/auth/signout', (c) => {
  clearSessionCookie(c);
  return c.json({ ok: true });
});

app.get('/api/auth/me', async (c) => {
  const env = c.env;
  const session = await getSession(c, env);
  if (!session) return c.json({ user: null });
  const user = await getUserById(env, session.uid);
  if (!user) return c.json({ user: null });
  return c.json({
    user: {
      id: user.id, email: user.email, name: user.name,
      age: user.age, profession: user.profession,
      monthlyIncome: user.monthly_income || 0,
      isOnboarded: !!user.is_onboarded,
    },
  });
});

app.post('/api/auth/onboarding', async (c) => {
  const env = c.env;
  const authErr = await requireAuth(c, env);
  if (authErr) return authErr;
  const userId = c.get('userId');

  let body;
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid JSON' }, 400); }
  const name = String(body.name || '').trim();
  const age = String(body.age || '');
  const profession = String(body.profession || '');
  const monthlyIncome = Number(body.monthlyIncome) || 0;
  if (name.length < 2) return c.json({ error: 'Name too short' }, 400);

  const res = await supabase(env, `/users?id=eq.${userId}`, {
    method: 'PATCH',
    body: JSON.stringify({
      name, age, profession, monthly_income: monthlyIncome, is_onboarded: true,
    }),
  });
  const updated = await res.json();
  if (!updated || !updated[0]) return c.json({ error: 'Failed to update' }, 500);
  const u = updated[0];
  return c.json({
    user: {
      id: u.id, email: u.email, name: u.name, age: u.age,
      profession: u.profession, monthlyIncome: u.monthly_income,
      isOnboarded: !!u.is_onboarded,
    },
  });
});

// ============================================================
// ROUTES: EXPENSES
// ============================================================

app.get('/api/expenses', async (c) => {
  const env = c.env;
  const authErr = await requireAuth(c, env);
  if (authErr) return authErr;
  const userId = c.get('userId');
  const res = await supabase(env, `/expenses?user_id=eq.${userId}&order=date.desc,created_at.desc&select=*`, { method: 'GET' });
  const arr = await res.json();
  return c.json({ expenses: (arr || []).map(e => ({
    id: e.id, date: e.date, item: e.item, category: e.category,
    mode: e.mode, amount: Number(e.amount), source: e.source || 'manual',
  }))});
});

app.post('/api/expenses', async (c) => {
  const env = c.env;
  const authErr = await requireAuth(c, env);
  if (authErr) return authErr;
  const userId = c.get('userId');
  let body;
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid JSON' }, 400); }
  const item = String(body.item || '').trim();
  const amount = Number(body.amount);
  const date = String(body.date || '');
  const category = String(body.category || 'Other');
  const mode = String(body.mode || 'UPI');
  const source = String(body.source || 'manual');
  if (!item || !amount || amount <= 0 || !/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    return c.json({ error: 'Invalid expense data' }, 400);
  }
  const res = await supabase(env, '/expenses', {
    method: 'POST',
    body: JSON.stringify({
      user_id: userId, item: item.slice(0, 200), amount, date,
      category: category.slice(0, 60), mode: mode.slice(0, 30), source,
    }),
  });
  const arr = await res.json();
  if (!arr || !arr[0]) return c.json({ error: 'Failed to create' }, 500);
  const e = arr[0];
  return c.json({ expense: { id: e.id, date: e.date, item: e.item, category: e.category, mode: e.mode, amount: Number(e.amount), source: e.source } });
});

app.put('/api/expenses/:id', async (c) => {
  const env = c.env;
  const authErr = await requireAuth(c, env);
  if (authErr) return authErr;
  const userId = c.get('userId');
  const id = c.req.param('id');
  let body;
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid JSON' }, 400); }
  const patch = {};
  if (body.item != null) patch.item = String(body.item).slice(0, 200);
  if (body.amount != null) patch.amount = Number(body.amount);
  if (body.date != null && /^\d{4}-\d{2}-\d{2}$/.test(String(body.date))) patch.date = String(body.date);
  if (body.category != null) patch.category = String(body.category).slice(0, 60);
  if (body.mode != null) patch.mode = String(body.mode).slice(0, 30);
  const res = await supabase(env, `/expenses?id=eq.${id}&user_id=eq.${userId}`, {
    method: 'PATCH',
    body: JSON.stringify(patch),
  });
  const arr = await res.json();
  if (!arr || arr.length === 0) return c.json({ error: 'Not found' }, 404);
  return c.json({ expense: arr[0] });
});

app.delete('/api/expenses/:id', async (c) => {
  const env = c.env;
  const authErr = await requireAuth(c, env);
  if (authErr) return authErr;
  const userId = c.get('userId');
  const id = c.req.param('id');
  await supabase(env, `/expenses?id=eq.${id}&user_id=eq.${userId}`, { method: 'DELETE' });
  return c.json({ ok: true });
});

// ============================================================
// ROUTES: CHAT SESSIONS
// ============================================================

app.get('/api/chat/sessions', async (c) => {
  const env = c.env;
  const authErr = await requireAuth(c, env);
  if (authErr) return authErr;
  const userId = c.get('userId');
  const res = await supabase(env, `/chat_sessions?user_id=eq.${userId}&order=updated_at.desc&select=id,title,created_at,updated_at`, { method: 'GET' });
  const arr = await res.json();
  return c.json({ sessions: arr || [] });
});

app.post('/api/chat/sessions', async (c) => {
  const env = c.env;
  const authErr = await requireAuth(c, env);
  if (authErr) return authErr;
  const userId = c.get('userId');
  let body = {};
  try { body = await c.req.json(); } catch {}
  const title = (body.title || 'New Chat').slice(0, 80);
  const res = await supabase(env, '/chat_sessions', {
    method: 'POST',
    body: JSON.stringify({ user_id: userId, title }),
  });
  const arr = await res.json();
  return c.json({ session: arr[0] });
});

app.get('/api/chat/sessions/:id', async (c) => {
  const env = c.env;
  const authErr = await requireAuth(c, env);
  if (authErr) return authErr;
  const userId = c.get('userId');
  const id = c.req.param('id');
  const sessRes = await supabase(env, `/chat_sessions?id=eq.${id}&user_id=eq.${userId}&select=*`, { method: 'GET' });
  const sessArr = await sessRes.json();
  if (!sessArr || sessArr.length === 0) return c.json({ error: 'Not found' }, 404);
  const session = sessArr[0];
  const msgRes = await supabase(env, `/chat_messages?session_id=eq.${id}&order=created_at.asc&select=*`, { method: 'GET' });
  const msgs = await msgRes.json();
  // Get attachments for each message
  const msgIds = (msgs || []).map(m => m.id);
  let attachments = [];
  if (msgIds.length > 0) {
    const attRes = await supabase(env, `/attachments?message_id=in.(${msgIds.join(',')})&select=*`, { method: 'GET' });
    attachments = await attRes.json() || [];
  }
  return c.json({
    session: {
      ...session,
      messages: (msgs || []).map(m => ({
        ...m,
        attachments: attachments.filter(a => a.message_id === m.id).map(a => ({
          id: a.id, fileName: a.file_name, mimeType: a.mime_type,
        })),
      })),
    },
  });
});

app.patch('/api/chat/sessions/:id', async (c) => {
  const env = c.env;
  const authErr = await requireAuth(c, env);
  if (authErr) return authErr;
  const userId = c.get('userId');
  const id = c.req.param('id');
  let body = {};
  try { body = await c.req.json(); } catch {}
  const res = await supabase(env, `/chat_sessions?id=eq.${id}&user_id=eq.${userId}`, {
    method: 'PATCH',
    body: JSON.stringify({ title: (body.title || 'New Chat').slice(0, 80) }),
  });
  const arr = await res.json();
  return c.json({ session: arr[0] });
});

app.delete('/api/chat/sessions/:id', async (c) => {
  const env = c.env;
  const authErr = await requireAuth(c, env);
  if (authErr) return authErr;
  const userId = c.get('userId');
  const id = c.req.param('id');
  await supabase(env, `/chat_sessions?id=eq.${id}&user_id=eq.${userId}`, { method: 'DELETE' });
  return c.json({ ok: true });
});

// ============================================================
// ROUTES: FILE UPLOAD (R2)
// ============================================================

app.post('/api/chat/upload', async (c) => {
  const env = c.env;
  const authErr = await requireAuth(c, env);
  if (authErr) return authErr;
  const userId = c.get('userId');

  if (!env.OSSMO_BUCKET) {
    return c.json({ error: 'R2 bucket not configured. Set OSSMO_BUCKET binding in wrangler.toml' }, 503);
  }

  const formData = await c.req.formData();
  const file = formData.get('file');
  if (!(file instanceof File)) {
    return c.json({ error: 'No file provided' }, 400);
  }
  if (file.size > 8 * 1024 * 1024) {
    return c.json({ error: 'File too large (max 8MB)' }, 413);
  }
  const allowedMimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'application/pdf', 'text/plain', 'text/csv'];
  const mimeType = file.type || 'application/octet-stream';
  if (!allowedMimes.includes(mimeType)) {
    return c.json({ error: `Unsupported file type: ${mimeType}` }, 415);
  }

  const buffer = await file.arrayBuffer();
  const safeName = file.name.replace(/[^a-zA-Z0-9.\-_]/g, '_');
  const r2Key = `attachments/${userId}/${Date.now()}-${safeName}`;

  await env.OSSMO_BUCKET.put(r2Key, buffer, {
    httpMetadata: { contentType: mimeType },
  });

  const insertRes = await supabase(env, '/attachments', {
    method: 'POST',
    body: JSON.stringify({
      user_id: userId, r2_key: r2Key, file_name: file.name,
      mime_type: mimeType, size: file.size,
    }),
  });
  const arr = await insertRes.json();
  if (!arr || !arr[0]) return c.json({ error: 'Failed to save attachment record' }, 500);
  const att = arr[0];

  // Generate a short-lived signed URL for Claude vision
  const signedUrl = await getR2SignedUrl(env, r2Key, 900);
  return c.json({ attachment: { id: att.id, fileName: att.file_name, mimeType: att.mime_type }, signedUrl });
});

app.get('/api/attachments/:id', async (c) => {
  const env = c.env;
  const authErr = await requireAuth(c, env);
  if (authErr) return authErr;
  const userId = c.get('userId');
  const id = c.req.param('id');
  const res = await supabase(env, `/attachments?id=eq.${id}&user_id=eq.${userId}&select=*`, { method: 'GET' });
  const arr = await res.json();
  if (!arr || arr.length === 0) return c.json({ error: 'Not found' }, 404);
  const att = arr[0];
  const url = await getR2SignedUrl(env, att.r2_key, 600);
  return c.json({ url, attachment: { id: att.id, fileName: att.file_name, mimeType: att.mime_type } });
});

// R2 signed URL via direct get() — Workers R2 doesn't have presigned URLs natively,
// so we serve through the worker itself.
async function getR2SignedUrl(env, key, ttl) {
  // We'll serve via /api/r2/:key endpoint, but for Claude vision we need a real URL.
  // Use R2 public URL if configured, else return a worker-served URL.
  if (env.R2_PUBLIC_URL) {
    return `${env.R2_PUBLIC_URL}/${key}`;
  }
  // Fallback: return the worker-served URL (only works if worker is publicly accessible)
  return `${env.WORKER_PUBLIC_URL || ''}/api/r2/${encodeURIComponent(key)}`;
}

// R2 file serving endpoint (for Claude to fetch + for user preview)
app.get('/api/r2/:key', async (c) => {
  const env = c.env;
  const authErr = await requireAuth(c, env);
  if (authErr) return authErr;
  const key = decodeURIComponent(c.req.param('key'));
  if (!env.OSSMO_BUCKET) return c.text('R2 not configured', 503);
  const obj = await env.OSSMO_BUCKET.get(key);
  if (!obj) return c.text('Not found', 404);
  const headers = new Headers();
  obj.writeHttpMetadata(headers);
  headers.set('Content-Type', obj.httpMetadata?.contentType || 'application/octet-stream');
  headers.set('Cache-Control', 'private, max-age=600');
  return new Response(obj.body, { headers });
});

// ============================================================
// ROUTES: CHAT (streaming via SSE + Claude Haiku 5.5)
// ============================================================

const ACCOUNTANT_SYSTEM_PROMPT = `You are Ossmo, the user's personal AI accountant and financial co-pilot. You talk like a sharp, friendly CA (chartered accountant) who actually cares — not a generic chatbot.

# YOUR PERSONA
- Name: Ossmo
- Role: Personal finance accountant for an Indian user (₹ currency, Indian context, Hinglish-friendly)
- Tone: Professional, warm, specific. Never robotic. Never generic. Always actionable.
- Language: Reply in the same language the user wrote in. If they write Hinglish, reply in Hinglish. If pure English, reply in English. If pure Hindi, reply in Hindi.

# WHAT YOU DO
1. **Logging expenses** — When they mention spending money, USE THE log_expense tool to save it automatically.
2. **Budgeting** — Give 50/30/20 advice tailored to their actual income and spending.
3. **Analysis** — When asked, give real breakdown with their actual numbers from the context block.
4. **Receipt parsing** — If they attach a receipt image, extract merchant, total, date, items. Then auto-log via log_expense.
5. **Planning** — Help with savings goals, SIP suggestions, emergency fund planning.

# HOW YOU FORMAT RESPONSES (like ChatGPT/Claude/Z.ai)

## Checklists (very important)
When giving steps or advice, ALWAYS use markdown checkboxes:
- [ ] Step 1 — what to do
- [ ] Step 2 — what to do

## Tables
For breakdowns, use markdown tables:
| Category | Spent | Budget | Status |
|---|---|---|---|
| Food | ₹2,400 | ₹3,000 | ✅ On track |

## Number formatting
Always use ₹ with Indian comma format: ₹12,500.

# RULES — NEVER BREAK
1. Always use the log_expense tool when the user mentions a spend.
2. Never invent numbers — only from user's message or context block below.
3. Never give investment advice beyond common-sense SIP/index fund suggestions.
4. Be concise — under 200 words unless they asked for detailed plan.
5. Always end with a next-step suggestion when relevant.
6. If user asks something unrelated to finance, politely redirect.

# CONTEXT (live, updated every message)
{{USER_CONTEXT}}`;

const LOG_EXPENSE_TOOL = {
  type: 'function',
  function: {
    name: 'log_expense',
    description: 'Log a new expense for the user. Call this whenever the user mentions spending money or attaching a receipt. You can call multiple times.',
    parameters: {
      type: 'object',
      properties: {
        item: { type: 'string', description: 'Short description of what was bought.' },
        amount: { type: 'number', description: 'Amount in INR. Just the number.' },
        category: { type: 'string', enum: ['Food & Dining','Groceries','Transport & Fuel','Bills & Recharge','Shopping','Rent & Housing','Entertainment','Investments','Other'] },
        date: { type: 'string', description: 'Date in YYYY-MM-DD format. Use today if "aaj/today".' },
        mode: { type: 'string', enum: ['UPI','Card','Cash','Bank Transfer','Wallet'], description: 'Payment method. Default UPI.' },
      },
      required: ['item', 'amount', 'category', 'date'],
    },
  },
};

const EXPENSE_CATEGORIES = ['Food & Dining','Groceries','Transport & Fuel','Bills & Recharge','Shopping','Rent & Housing','Entertainment','Investments','Other'];
const PAYMENT_MODES = ['UPI','Card','Cash','Bank Transfer','Wallet'];

async function buildUserContext(env, userId) {
  const user = await getUserById(env, userId);
  if (!user) return '';
  const now = new Date();
  const monthStart = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-01`;
  const expRes = await supabase(env, `/expenses?user_id=eq.${userId}&date=gte.${monthStart}&order=date.desc&select=*`, { method: 'GET' });
  const expenses = await expRes.json() || [];
  const totalSpent = expenses.reduce((s, e) => s + Number(e.amount || 0), 0);
  const byCat = {};
  expenses.forEach(e => { byCat[e.category] = (byCat[e.category] || 0) + Number(e.amount || 0); });
  const lines = Object.entries(byCat).sort((a, b) => b[1] - a[1]).map(([c, a]) => `  - ${c}: ₹${Math.round(a).toLocaleString('en-IN')}`).join('\n');
  return `USER PROFILE:
- Name: ${user.name || 'Unknown'}
- Age: ${user.age || 'unknown'}
- Profession: ${user.profession || 'unknown'}
- Monthly income: ₹${(user.monthly_income || 0).toLocaleString('en-IN')}

CURRENT MONTH (${monthStart} onwards):
- Total spent so far: ₹${Math.round(totalSpent).toLocaleString('en-IN')}
- Remaining budget: ₹${Math.max(0, (user.monthly_income || 0) - totalSpent).toLocaleString('en-IN')}
- Number of transactions: ${expenses.length}

CATEGORY BREAKDOWN:
${lines || '  (no expenses logged yet)'}

TOP 5 RECENT TRANSACTIONS:
${expenses.slice(0, 5).map(e => `  - ${e.date} | ${e.item} | ${e.category} | ₹${Number(e.amount).toLocaleString('en-IN')}`).join('\n') || '  (none)'}`;
}

async function* streamClaude(env, messages, systemPrompt, tools) {
  const model = env.ANTHROPIC_MODEL || 'claude-haiku-5-5';
  const baseURL = env.MESH_API_BASE_URL || 'https://api.meshapi.ai/v1';

  const body = {
    model,
    messages,
    temperature: 0.7,
    stream: true,
  };
  if (systemPrompt) body.messages = [{ role: 'system', content: systemPrompt }, ...messages];
  if (tools && tools.length > 0) {
    body.tools = tools;
    body.tool_choice = 'auto';
  }

  const res = await fetch(`${baseURL}/chat/completions`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.MESH_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });

  if (!res.ok || !res.body) {
    const text = await res.text();
    throw new Error(`Claude API error ${res.status}: ${text}`);
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  const toolBuffers = new Map();
  let finishReason = 'stop';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop() || '';
    for (const line of lines) {
      if (!line.startsWith('data: ')) continue;
      const dataStr = line.slice(6).trim();
      if (dataStr === '[DONE]') continue;
      try {
        const chunk = JSON.parse(dataStr);
        const choice = chunk.choices?.[0];
        if (!choice) continue;
        const delta = choice.delta;
        if (delta?.content) yield { type: 'token', text: delta.content };
        if (delta?.tool_calls) {
          for (const tc of delta.tool_calls) {
            const idx = tc.index ?? 0;
            if (!toolBuffers.has(idx)) toolBuffers.set(idx, { id: tc.id || '', name: '', args: '' });
            const buf = toolBuffers.get(idx);
            if (tc.function?.name) buf.name = tc.function.name;
            if (tc.function?.arguments) buf.args += tc.function.arguments;
          }
        }
        if (choice.finish_reason) finishReason = choice.finish_reason;
      } catch { /* skip malformed */ }
    }
  }

  for (const buf of toolBuffers.values()) {
    if (buf.name) {
      try {
        const args = buf.args ? JSON.parse(buf.args) : {};
        yield { type: 'tool_call', tool: { name: buf.name, arguments: args } };
      } catch { /* ignore */ }
    }
  }
  yield { type: 'done', finishReason };
}

async function completeOnce(env, messages, systemPrompt) {
  const model = env.ANTHROPIC_MODEL || 'claude-haiku-5-5';
  const baseURL = env.MESH_API_BASE_URL || 'https://api.meshapi.ai/v1';
  const body = {
    model,
    messages: systemPrompt ? [{ role: 'system', content: systemPrompt }, ...messages] : messages,
    temperature: 0.6,
  };
  const res = await fetch(`${baseURL}/chat/completions`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${env.MESH_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  return data.choices?.[0]?.message?.content || '';
}

app.post('/api/chat', async (c) => {
  const env = c.env;
  const authErr = await requireAuth(c, env);
  if (authErr) return authErr;
  const userId = c.get('userId');

  let body;
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid JSON' }, 400); }
  const messageText = String(body.message || '').trim();
  const attachmentIds = Array.isArray(body.attachmentIds) ? body.attachmentIds : [];
  if (!messageText && attachmentIds.length === 0) return c.json({ error: 'Empty message' }, 400);

  // Get or create session
  let sessionId = body.sessionId;
  if (sessionId) {
    const sRes = await supabase(env, `/chat_sessions?id=eq.${sessionId}&user_id=eq.${userId}&select=*`, { method: 'GET' });
    const sArr = await sRes.json();
    if (!sArr || sArr.length === 0) sessionId = null;
  }
  if (!sessionId) {
    const title = messageText ? messageText.slice(0, 60) : 'New Chat';
    const sRes = await supabase(env, '/chat_sessions', {
      method: 'POST',
      body: JSON.stringify({ user_id: userId, title }),
    });
    const sArr = await sRes.json();
    sessionId = sArr[0]?.id;
  } else {
    // Update title if it was "New Chat"
    const sRes = await supabase(env, `/chat_sessions?id=eq.${sessionId}&select=title`, { method: 'GET' });
    const sArr = await sRes.json();
    if (sArr && sArr[0] && sArr[0].title === 'New Chat' && messageText) {
      await supabase(env, `/chat_sessions?id=eq.${sessionId}`, {
        method: 'PATCH',
        body: JSON.stringify({ title: messageText.slice(0, 60) }),
      });
    }
  }

  // Resolve attachments
  let attachments = [];
  if (attachmentIds.length > 0) {
    const attRes = await supabase(env, `/attachments?id=in.(${attachmentIds.join(',')})&user_id=eq.${userId}&select=*`, { method: 'GET' });
    attachments = await attRes.json() || [];
  }

  // Save user message
  const userMsgRes = await supabase(env, '/chat_messages', {
    method: 'POST',
    body: JSON.stringify({ session_id: sessionId, role: 'user', content: messageText || '(attachment only)' }),
  });
  const userMsgArr = await userMsgRes.json();
  const userMsgId = userMsgArr[0]?.id;
  if (userMsgId && attachments.length > 0) {
    for (const att of attachments) {
      await supabase(env, `/attachments?id=eq.${att.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ message_id: userMsgId }),
      });
    }
  }

  // Build attachment content for Claude (image_url / file)
  const userContent = [];
  if (messageText) userContent.push({ type: 'text', text: messageText });
  else userContent.push({ type: 'text', text: 'Please analyze the attached file.' });
  for (const att of attachments) {
    const url = await getR2SignedUrl(env, att.r2_key, 900);
    if (att.mime_type.startsWith('image/')) {
      userContent.push({ type: 'image_url', image_url: { url } });
    } else if (att.mime_type === 'application/pdf') {
      userContent.push({ type: 'file', file_url: { url } });
    } else {
      userContent.push({ type: 'text', text: `[Attached file: ${att.file_name}]` });
    }
  }

  // Load recent history
  const histRes = await supabase(env, `/chat_messages?session_id=eq.${sessionId}&order=created_at.asc&select=role,content&limit=20`, { method: 'GET' });
  const history = await histRes.json() || [];
  const historyMessages = history.map(m => ({ role: m.role === 'assistant' ? 'assistant' : 'user', content: m.content }));
  // Replace last user message with one that has attachments
  if (historyMessages.length > 0 && historyMessages[historyMessages.length - 1].role === 'user') {
    historyMessages[historyMessages.length - 1] = { role: 'user', content: userContent };
  } else {
    historyMessages.push({ role: 'user', content: userContent });
  }

  // Build system prompt
  const userContext = await buildUserContext(env, userId);
  const systemPrompt = ACCOUNTANT_SYSTEM_PROMPT.replace('{{USER_CONTEXT}}', userContext);

  // SSE stream
  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      const send = (event, data) => {
        controller.enqueue(encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`));
      };
      send('session', { sessionId });

      let assistantText = '';
      const toolCalls = [];

      try {
        for await (const ev of streamClaude(env, historyMessages, systemPrompt, [LOG_EXPENSE_TOOL])) {
          if (ev.type === 'token') {
            assistantText += ev.text;
            send('token', { text: ev.text });
          } else if (ev.type === 'tool_call') {
            toolCalls.push(ev.tool);
            send('tool_call', { tool: ev.tool });
          } else if (ev.type === 'done') {
            send('done', { finishReason: ev.finishReason });
          }
        }

        // Execute tool calls
        const toolResults = [];
        for (const tc of toolCalls) {
          if (tc.name === 'log_expense') {
            const args = tc.arguments;
            if (args.item && args.amount && args.category && EXPENSE_CATEGORIES.includes(args.category) && /^\d{4}-\d{2}-\d{2}$/.test(args.date)) {
              const mode = PAYMENT_MODES.includes(args.mode) ? args.mode : 'UPI';
              const expRes = await supabase(env, '/expenses', {
                method: 'POST',
                body: JSON.stringify({
                  user_id: userId,
                  item: String(args.item).slice(0, 200),
                  amount: Number(args.amount),
                  category: args.category,
                  date: args.date,
                  mode,
                  source: 'ai',
                }),
              });
              const expArr = await expRes.json();
              if (expArr && expArr[0]) {
                const e = expArr[0];
                toolResults.push(`Logged: ${e.item} ₹${e.amount} on ${e.date} (${e.category})`);
                send('tool_result', {
                  tool: 'log_expense',
                  expense: { id: e.id, item: e.item, amount: Number(e.amount), category: e.category, date: e.date },
                });
              }
            } else {
              send('tool_result', { tool: 'log_expense', error: 'invalid args' });
            }
          }
        }

        // If only tool calls and no text, do a follow-up
        if (toolCalls.length > 0 && !assistantText.trim()) {
          const followUpMessages = [
            ...historyMessages,
            { role: 'assistant', content: `[Tool calls executed: ${toolResults.join('; ')}]` },
            { role: 'user', content: 'Now reply to me with a friendly confirmation. Be brief — 1-2 sentences in my language. Mention the logged expense(s) clearly with ₹ amounts.' },
          ];
          const followUpText = await completeOnce(env, followUpMessages, systemPrompt);
          assistantText = followUpText;
          send('token', { text: followUpText });
        }

        // Save assistant message
        await supabase(env, '/chat_messages', {
          method: 'POST',
          body: JSON.stringify({
            session_id: sessionId,
            role: 'assistant',
            content: assistantText || '(no response)',
            tool_calls: toolCalls.length > 0 ? JSON.stringify(toolCalls) : null,
          }),
        });
        // Update session timestamp
        await supabase(env, `/chat_sessions?id=eq.${sessionId}`, {
          method: 'PATCH',
          body: JSON.stringify({ updated_at: new Date().toISOString() }),
        });

        send('end', { ok: true });
      } catch (err) {
        send('error', { error: err.message || 'Unknown error' });
      } finally {
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',
    },
  });
});

// ============================================================
// ROOT
// ============================================================

app.get('/', (c) => c.json({ name: 'Ossmo AI API', status: 'running', version: '1.0.0' }));
app.get('/health', (c) => c.json({ ok: true }));

export default app;
