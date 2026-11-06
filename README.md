# Ossmo AI — Personal Finance Accountant

Hinglish AI accountant that logs your expenses, parses receipts, and builds your budget — powered by Claude Haiku 5.5 via meshapi.ai. Built on a free-tier-friendly stack: Supabase + Cloudflare R2 + Cloudflare Workers + plain HTML/CSS/JS.

## 📁 Folder Structure

```
Ossmo-AI/
├── public/                    # Frontend — static HTML/CSS/JS (host on Cloudflare Pages, Vercel, Netlify, etc.)
│   ├── index.html             # Auth + Onboarding page
│   ├── dashboard.html         # Main app (chat + expense table)
│   ├── config.js              # ← EDIT THIS: set your Worker URL
│   └── logo.svg
├── worker/                    # Backend — Cloudflare Worker
│   ├── index.js               # All API routes (auth, chat, expenses, upload, AI proxy)
│   ├── wrangler.toml          # Worker config (R2 binding + env vars)
│   ├── package.json
│   └── .dev.vars.example      # Local dev secrets template
├── supabase/
│   └── schema.sql             # Run this in Supabase SQL Editor to create tables
└── README.md                  # This file
```

## ✨ Features

- **AI Accountant Chat** — Talk to Ossmo in Hinglish. It logs expenses, gives budget advice (50/30/20 rule), analyzes spending, and acts like a real CA.
- **Receipt Image Upload** — Attach a receipt photo in chat. Claude Haiku 5.5 vision extracts merchant, amount, date, items and auto-logs it.
- **PDF Support** — Upload PDFs (e.g. bank statements) for analysis.
- **Live Expense Table** — Inline editable, with categories, payment modes, AI-logged badges.
- **Secure by Design** — JWT auth with PBKDF2-hashed passwords, HTTP-only cookies, API keys never exposed to frontend, rate limiting.
- **Streaming Responses** — Word-by-word reveal like ChatGPT/Claude.
- **Function Calling** — AI uses tools to log expenses (no manual steps).
- **Markdown Rendering** — AI responses show checklists, tables, bold text, code blocks (just like Z.ai/Claude UI).
- **Dark / Light Mode** — Auto-saved.
- **Chat History** — Multiple sessions, rename, delete.

## 🏗️ Architecture

```
Browser (static HTML/CSS/JS)
   ↓
Cloudflare Worker (single API endpoint)
   ↓                          ↓                    ↓
Supabase Postgres          Cloudflare R2       meshapi.ai → Claude Haiku 5.5
(users, expenses,          (receipt images,    (streaming chat + vision +
 chats, attachments)        PDFs)               function calling)
```

## 🚀 Setup Guide (3 parts)

### PART 1: Database (Supabase) — 5 minutes

1. Create a free account at https://supabase.com
2. Create a new project (free tier is fine)
3. Go to **SQL Editor → New Query**
4. Paste the entire contents of `supabase/schema.sql` and click **Run**
5. Go to **Project Settings → API**:
   - Copy **Project URL** (looks like `https://xxxxxxxx.supabase.co`)
   - Copy **service_role** secret key (NOT the anon key — the service_role bypasses RLS)

### PART 2: Storage (Cloudflare R2) — 5 minutes

1. Create a free Cloudflare account at https://cloudflare.com
2. Go to **R2 → Overview → Create bucket**
   - Name it `ossmo` (or anything, but match it in `wrangler.toml`)
3. You don't need an API token — the Worker uses the R2 binding natively

### PART 3: AI (meshapi.ai) — 2 minutes

1. Create an account at https://app.meshapi.ai
2. Go to **API Keys → Create API Key**
3. Copy the key

---

## 🔧 Deploy the Backend (Cloudflare Worker)

```bash
cd worker/

# 1. Install dependencies
npm install

# 2. Login to Cloudflare (one-time)
npx wrangler login

# 3. Create the R2 bucket (one-time, skip if already created)
npx wrangler r2 bucket create ossmo

# 4. Set secrets (run each command, paste value when prompted)
npx wrangler secret put SUPABASE_URL
npx wrangler secret put SUPABASE_SERVICE_KEY
npx wrangler secret put MESH_API_KEY
npx wrangler secret put MESH_API_BASE_URL
npx wrangler secret put ANTHROPIC_MODEL
npx wrangler secret put JWT_SECRET

# 5. Deploy
npx wrangler deploy
```

After deploy, you'll get a URL like `https://ossmo-api.your-subdomain.workers.dev`. Note this down.

**For local dev** instead of deploy:
```bash
cp .dev.vars.example .dev.vars
# Edit .dev.vars with your real values
npx wrangler dev
# Worker runs on http://localhost:8787
```

---

## 🌐 Deploy the Frontend (Static Hosting)

The `public/` folder is just static files. Host it anywhere:

### Option A: Cloudflare Pages (recommended — same Cloudflare account)
1. Go to **Pages → Create project → Connect to Git** (or upload `public/` directly)
2. Build command: (none)
3. Output directory: `public`
4. Done — you'll get a URL like `https://ossmo.pages.dev`

### Option B: Vercel
1. Drag the `public/` folder to https://vercel.com/new

### Option C: Netlify
1. Drag the `public/` folder to https://app.netlify.com/drop

### Option D: Any web server (nginx, Apache, etc.)
Just serve the `public/` folder.

---

## ⚙️ Connect Frontend to Backend

Edit `public/config.js`:

```js
const API_BASE = 'https://ossmo-api.your-subdomain.workers.dev';
```

That's it! Open your frontend URL, sign up, complete onboarding, and start chatting with Ossmo.

---

## 🔒 Security Notes

- ✅ **API keys never reach the browser** — all AI/R2/DB calls happen in the Worker
- ✅ **JWT in HTTP-only cookies** — not accessible via JavaScript
- ✅ **PBKDF2 password hashing** — Web Crypto, works in Workers free tier (10ms CPU limit)
- ✅ **Rate limiting** on auth endpoints (5 attempts/min/IP)
- ✅ **Per-user data isolation** — every query checks `user_id`
- ✅ **File upload validation** — type + size limits (8MB max)
- ✅ **R2 files served through Worker** — authenticated, no public access
- ✅ **Supabase RLS enabled** — defense-in-depth, anon key denied

## 💰 Free Tier Capacity

| Component | Free limit | ~User capacity |
|---|---|---|
| Cloudflare Workers | 100K req/day | ~3,000 active users |
| Cloudflare R2 | 10GB storage, free egress | ~12K users w/ receipts |
| Supabase | 50K MAU, 500MB DB, 5GB egress | ~5K active users |
| Mesh API (Claude Haiku 5.5) | $0.09/$0.45 per M tokens | Pay per use |

**Realistic free-tier**: ~5,000 signups, ~1,500 daily active users.

## 🛠️ Tech Stack

- **Frontend**: Plain HTML/CSS/JS (no framework, no build step)
- **Backend**: Cloudflare Worker (Hono framework, single file)
- **Database**: Supabase Postgres (via REST API)
- **Storage**: Cloudflare R2 (S3-compatible, native Worker binding)
- **AI**: Claude Haiku 5.5 via meshapi.ai (OpenAI-compatible)
- **Auth**: Custom JWT + PBKDF2 (Web Crypto, no external libs)

## 📝 Development Notes

- The frontend uses `marked.js` from a CDN for markdown rendering (checklists, tables, code blocks in AI responses)
- The Worker uses Web Crypto API for all crypto operations (no Node.js deps needed)
- Supabase is accessed via REST API (PostgREST) — no TCP socket library needed in the Worker
- R2 files are served through the Worker at `/api/r2/:key` (authenticated, not public)

## 🎯 Troubleshooting

**"Network error. Check API URL in config.js"** → Your `config.js` API_BASE is wrong, or the Worker isn't deployed yet.

**"401 Invalid or missing API key"** in chat → Your `MESH_API_KEY` secret isn't set on the Worker. Run `npx wrangler secret put MESH_API_KEY`.

**Upload returns "R2 bucket not configured"** → The R2 binding isn't set up. Make sure you ran `npx wrangler r2 bucket create ossmo` and the binding in `wrangler.toml` matches.

**Database errors** → Make sure you ran `supabase/schema.sql` in the Supabase SQL Editor, and your `SUPABASE_URL` + `SUPABASE_SERVICE_KEY` secrets are correct.

---

Built with ❤️ for the Indian user who wants a real AI accountant, not a generic chatbot.
