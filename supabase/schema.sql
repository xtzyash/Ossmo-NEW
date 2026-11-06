-- ============================================================
-- OSSMO AI — Supabase Database Schema
-- ============================================================
-- Run this in: Supabase Dashboard → SQL Editor → New Query
-- ============================================================

-- ---------- USERS ----------
-- Note: We use our own users table (not Supabase Auth) for full control.
-- Passwords are hashed with PBKDF2 (Web Crypto) in the Worker.

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name TEXT,
  age TEXT,
  profession TEXT,
  monthly_income INTEGER DEFAULT 0,
  is_onboarded BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ---------- EXPENSES ----------
CREATE TABLE IF NOT EXISTS expenses (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  date TEXT NOT NULL,
  item TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'Other',
  mode TEXT NOT NULL DEFAULT 'UPI',
  amount NUMERIC(12,2) NOT NULL,
  source TEXT NOT NULL DEFAULT 'manual',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_expenses_user_id ON expenses(user_id);
CREATE INDEX IF NOT EXISTS idx_expenses_user_date ON expenses(user_id, date DESC);

-- ---------- CHAT SESSIONS ----------
CREATE TABLE IF NOT EXISTS chat_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL DEFAULT 'New Chat',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_chat_sessions_user_id ON chat_sessions(user_id);

-- ---------- CHAT MESSAGES ----------
CREATE TABLE IF NOT EXISTS chat_messages (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id UUID NOT NULL REFERENCES chat_sessions(id) ON DELETE CASCADE,
  role TEXT NOT NULL,
  content TEXT NOT NULL,
  tool_calls TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_chat_messages_session_id ON chat_messages(session_id);

-- ---------- ATTACHMENTS ----------
CREATE TABLE IF NOT EXISTS attachments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  message_id UUID REFERENCES chat_messages(id) ON DELETE CASCADE,
  expense_id UUID REFERENCES expenses(id) ON DELETE CASCADE,
  r2_key TEXT NOT NULL,
  file_name TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  size INTEGER NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_attachments_user_id ON attachments(user_id);
CREATE INDEX IF NOT EXISTS idx_attachments_message_id ON attachments(message_id);

-- ---------- UPDATED_AT TRIGGERS ----------
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS users_updated_at ON users;
CREATE TRIGGER users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at();

DROP TRIGGER IF EXISTS expenses_updated_at ON expenses;
CREATE TRIGGER expenses_updated_at BEFORE UPDATE ON expenses FOR EACH ROW EXECUTE FUNCTION update_updated_at();

DROP TRIGGER IF EXISTS chat_sessions_updated_at ON chat_sessions;
CREATE TRIGGER chat_sessions_updated_at BEFORE UPDATE ON chat_sessions FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ---------- ROW LEVEL SECURITY ----------
-- Enable RLS (the service_role key bypasses RLS, so the Worker can read/write everything).
-- This is defense-in-depth in case the anon key ever leaks.

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE expenses ENABLE ROW LEVEL SECURITY;
ALTER TABLE chat_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE chat_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE attachments ENABLE ROW LEVEL SECURITY;

-- Deny all access via anon key (service_role bypasses these policies)
CREATE POLICY "deny_anon_users" ON users FOR ALL USING (false) WITH CHECK (false);
CREATE POLICY "deny_anon_expenses" ON expenses FOR ALL USING (false) WITH CHECK (false);
CREATE POLICY "deny_anon_sessions" ON chat_sessions FOR ALL USING (false) WITH CHECK (false);
CREATE POLICY "deny_anon_messages" ON chat_messages FOR ALL USING (false) WITH CHECK (false);
CREATE POLICY "deny_anon_attachments" ON attachments FOR ALL USING (false) WITH CHECK (false);

-- Done! Now create an API key in Supabase Dashboard → Project Settings → API:
-- - Use "service_role" key as SUPABASE_SERVICE_KEY in your Worker secrets
-- - SUPABASE_URL is "https://yourproject.supabase.co"
