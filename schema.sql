-- Cloudflare D1 (SQLite) Schema
-- 运行:wrangler d1 execute purplestar-db --file=./schema.sql

CREATE TABLE IF NOT EXISTS charts (
  id TEXT PRIMARY KEY,
  input_json TEXT NOT NULL,
  chart_json TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  expires_at INTEGER  -- NULL = 永不过期
);

CREATE INDEX IF NOT EXISTS idx_charts_created ON charts(created_at);

-- payments 表:webhook 写入,用于对账
-- 不依赖订单表(订单状态用 Stripe API 实时查)
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
  order_id TEXT NOT NULL,                -- 通用支付 ID:Stripe session_id 或 NOWPayments payment_id
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

-- NOWPayments 订单记录(IPN webhook 写入,/api/interpret 校验读)
CREATE TABLE IF NOT EXISTS nowpayments_payments (
  payment_id INTEGER PRIMARY KEY,         -- NOWPayments 返回的 payment_id(数字)
  order_id TEXT UNIQUE NOT NULL,          -- 我生成的 UUID,前端 jump 时带回
  tier TEXT NOT NULL,                     -- basic / premium
  chart_id TEXT,                          -- 关联 chart(可选)
  amount_usd REAL NOT NULL,               -- 锁定时的美元价(防止汇率波动)
  pay_currency TEXT,                      -- 用户实际付的币 (usdttrc20 / btc / eth ...)
  status TEXT NOT NULL DEFAULT 'waiting', -- waiting / confirming / confirmed / sending / finished / failed / refunded
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  finished_at INTEGER                     -- finished/failed 时填时间戳
);

CREATE INDEX IF NOT EXISTS idx_nowpayments_order ON nowpayments_payments(order_id);
CREATE INDEX IF NOT EXISTS idx_nowpayments_status ON nowpayments_payments(status);

-- 自托管加密货币支付订单(派生地址,链上 watcher 写入)
CREATE TABLE IF NOT EXISTS crypto_payments (
  order_id TEXT PRIMARY KEY,             -- 我生成的 UUID,前端 jump 时带回
  address TEXT UNIQUE NOT NULL,          -- 派生的 XRP 收款地址
  derivation_index INTEGER NOT NULL,     -- HD wallet 派生路径 m/44'/144'/0'/0/<index>
  tier TEXT NOT NULL,                    -- basic / premium
  chart_id TEXT,
  amount_xrp REAL NOT NULL,              -- 锁定 XRP 数量(防汇率波动)
  amount_usd REAL NOT NULL,              -- 锁定时 USD 价
  xrp_usd_rate REAL NOT NULL,            -- 锁定时汇率
  status TEXT NOT NULL DEFAULT 'waiting',-- waiting / confirming / confirmed / finished / failed / expired
  tx_hash TEXT,                          -- 链上交易 hash
  paid_at INTEGER,                       -- 链上确认时间
  expires_at INTEGER NOT NULL,           -- 过期时间戳(创单后 +30min)
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  finished_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_crypto_payments_status ON crypto_payments(status);
CREATE INDEX IF NOT EXISTS idx_crypto_payments_address ON crypto_payments(address);
CREATE INDEX IF NOT EXISTS idx_crypto_payments_expires ON crypto_payments(expires_at);
CREATE INDEX IF NOT EXISTS idx_crypto_payments_chart ON crypto_payments(chart_id);

-- HD wallet 状态:跟踪下一个待派生的 index
CREATE TABLE IF NOT EXISTS crypto_hd_wallet (
  id INTEGER PRIMARY KEY DEFAULT 1,
  next_index INTEGER NOT NULL DEFAULT 0,  -- 下一个要派生的子地址 index
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- 汇率缓存(USD/XRP)
CREATE TABLE IF NOT EXISTS crypto_fx_cache (
  id INTEGER PRIMARY KEY DEFAULT 1,
  rate REAL NOT NULL,             -- 1 XRP = ? USD
  fetched_at INTEGER NOT NULL     -- unix timestamp
);
