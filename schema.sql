-- Cloudflare D1 (SQLite) Schema
-- 运行：wrangler d1 execute purplestar-db --file=./schema.sql

CREATE TABLE IF NOT EXISTS charts (
  id TEXT PRIMARY KEY,
  input_json TEXT NOT NULL,
  chart_json TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  expires_at INTEGER  -- NULL = 永不过期
);

CREATE INDEX IF NOT EXISTS idx_charts_created ON charts(created_at);

-- payments 表：webhook 写入，用于对账
-- 不依赖订单表（订单状态用 Stripe API 实时查）
CREATE TABLE IF NOT EXISTS payments (
  session_id TEXT PRIMARY KEY,           -- stripe checkout session id (cs_...)
  amount_total INTEGER NOT NULL,
  currency TEXT NOT NULL DEFAULT 'usd',
  customer_email TEXT,
  status TEXT NOT NULL,                  -- paid / refunded / failed
  paid_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status);
CREATE INDEX IF NOT EXISTS idx_payments_paid_at ON payments(paid_at);

CREATE TABLE IF NOT EXISTS readings (
  id TEXT PRIMARY KEY,
  chart_id TEXT NOT NULL,
  order_id TEXT NOT NULL,                -- 这里存的是 stripe session id，不再 FK 到 orders
  tier TEXT NOT NULL,
  content TEXT NOT NULL,
  tokens_used INTEGER,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_readings_chart ON readings(chart_id);
CREATE INDEX IF NOT EXISTS idx_readings_order ON readings(order_id);

CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT PRIMARY KEY,
  count INTEGER NOT NULL DEFAULT 1,
  expires_at INTEGER
);
