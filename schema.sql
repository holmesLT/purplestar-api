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

CREATE TABLE IF NOT EXISTS orders (
  id TEXT PRIMARY KEY,                   -- stripe session id
  chart_id TEXT NOT NULL,
  tier TEXT NOT NULL CHECK(tier IN ('basic', 'premium')),
  amount INTEGER NOT NULL,                -- 美分
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'paid', 'failed', 'refunded')),
  customer_email TEXT,
  paid_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_orders_chart ON orders(chart_id);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);

CREATE TABLE IF NOT EXISTS readings (
  id TEXT PRIMARY KEY,
  chart_id TEXT NOT NULL,
  order_id TEXT NOT NULL,
  tier TEXT NOT NULL,
  content TEXT NOT NULL,
  tokens_used INTEGER,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  FOREIGN KEY (order_id) REFERENCES orders(id)
);

CREATE INDEX IF NOT EXISTS idx_readings_chart ON readings(chart_id);
