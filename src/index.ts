/**
 * Cloudflare Workers 主入口 — PurpleStar API
 *
 * 架构：
 *   - 排盘：客户端用 iztro 库直接生成（无服务端计算）
 *   - 缓存：客户端把 chart 传到 /api/chart/save 存到 D1（付费时给后端读 chart 用）
 *   - 支付：Stripe Payment Link（固定 URL，硬编码在前端），webhook 只负责记录
 *   - AI 解读：客户端发 chartId + sessionId → Worker 用 Stripe API 校验 session
 *     已支付，再读 D1 里的 chart，调 Claude 生成解读
 *
 * 注意：
 *   - 不 import Stripe SDK / Anthropic SDK — 用 fetch 直接调 REST API。
 *     这样 esbuild 不需要 external/bundle 那些 npm packages,
 *     bundle 输出自包含,CF runtime 直接跑。
 *   - Stripe API: https://docs.stripe.com/api
 *   - Anthropic API: https://docs.anthropic.com/claude/reference/messages
 *
 * 路由：
 *   POST /api/chart/save     暂存 chart 到 D1
 *   GET  /api/chart/:id      查询暂存的 chart
 *   POST /api/interpret      生成 AI 解读（Stripe API 校验订单已支付）
 *   POST /api/webhook/stripe Stripe 支付回调（HMAC 验签 + 留痕）
 *   GET  /api/debug/session/:id  查看 session 详情（需 secret header）
 *   GET  /health
 *   POST /indexnow           推送 URL 到 IndexNow(Bing/Yandex/Naver/Seznam)
 */

const INDEXNOW_KEY = '75be619ec13248df8a79e3d91176d28f';
const INDEXNOW_KEY_LOCATION = 'https://purplestar.cc/75be619ec13248df8a79e3d91176d28f.txt';

import { Hono } from 'hono';
import { cors } from 'hono/cors';

export interface Env {
  ANTHROPIC_API_KEY: string;
  STRIPE_SECRET_KEY: string;
  STRIPE_WEBHOOK_SECRET: string;
  NOWPAYMENTS_API_KEY: string;
  NOWPAYMENTS_IPN_SECRET: string;
  XRP_MNEMONIC: string;          // BIP39 mnemonic for self-hosted HD wallet
  XRP_USD_PRICE_URL: string;     // e.g. "https://api.coingecko.com/api/v3/simple/price?ids=ripple&vs_currencies=usd"
  SITE_URL: string;
  ALLOWED_ORIGIN: string;
  DB: D1Database;
}

const app = new Hono<{ Bindings: Env }>();

// CORS
app.use('*', cors({
  origin: (origin, c) => {
    if (origin && origin === c.env.ALLOWED_ORIGIN) return origin;
    if (origin?.startsWith('http://localhost')) return origin;
    return c.env.ALLOWED_ORIGIN;
  },
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Stripe-Signature'],
  maxAge: 86400,
}));

app.get('/health', (c) => c.json({ status: 'ok', service: 'purplestar-api', timestamp: Date.now() }));

// ====================================================================
// Stripe REST helper — 替代 Stripe SDK
//   用 fetch 直接调 https://api.stripe.com/v1/...
// ====================================================================

async function stripeRetrieveSession(secretKey: string, sessionId: string): Promise<any> {
  const r = await fetch(`https://api.stripe.com/v1/checkout/sessions/${encodeURIComponent(sessionId)}?expand[]=line_items`, {
    headers: {
      'Authorization': `Bearer ${secretKey}`,
      'Stripe-Version': '2025-02-24.acacia',
    },
  });
  if (!r.ok) {
    const text = await r.text();
    throw new Error(`Stripe API ${r.status}: ${text.slice(0, 200)}`);
  }
  return r.json();
}

// ====================================================================
// Debug endpoint
// ====================================================================

app.get('/api/debug/session/:id', async (c) => {
  const id = c.req.param('id');
  const secret = c.req.header('x-debug-key');
  if (secret !== c.env.STRIPE_WEBHOOK_SECRET) {
    return c.json({ error: 'Forbidden' }, 403);
  }
  try {
    const s = await stripeRetrieveSession(c.env.STRIPE_SECRET_KEY, id);
    return c.json({
      id: s.id,
      payment_status: s.payment_status,
      amount_total: s.amount_total,
      amount_subtotal: s.amount_subtotal,
      currency: s.currency,
      customer_email: s.customer_details?.email,
      metadata: s.metadata,
      payment_link: s.payment_link,
      line_items: s.line_items,
    });
  } catch (err: any) {
    return c.json({ error: err.message }, 400);
  }
});

// ====================================================================
// 图表暂存
// ====================================================================

app.post('/api/chart/save', async (c) => {
  const body = await c.req.json() as { id: string; chart: any };
  if (!body.id || !body.chart) return c.json({ error: 'Missing fields.' }, 400);

  const now = Math.floor(Date.now() / 1000);
  await c.env.DB.prepare(
    `INSERT OR REPLACE INTO charts (id, input_json, chart_json, expires_at) VALUES (?, ?, ?, ?)`
  ).bind(body.id, '{}', JSON.stringify(body.chart), now + 86400).run();

  return c.json({ id: body.id, saved: true });
});

app.get('/api/chart/:id', async (c) => {
  const id = c.req.param('id');
  const row = await c.env.DB.prepare(
    `SELECT chart_json FROM charts WHERE id = ? AND (expires_at IS NULL OR expires_at > ?)`
  ).bind(id, Math.floor(Date.now() / 1000)).first<{ chart_json: string }>();

  if (!row) return c.json({ error: 'Not found.' }, 404);
  return c.json({ id, ...JSON.parse(row.chart_json) });
});

// ====================================================================
// 限流
// ====================================================================

async function checkRate(c: any, ip: string, limit: number): Promise<boolean> {
  const now = Math.floor(Date.now() / 1000);
  const key = `rl:${ip}:${Math.floor(now / 60)}`;
  const counter: any = await c.env.DB.prepare(
    `SELECT count FROM rate_limits WHERE key = ?`
  ).bind(key).first();

  const count = counter?.count ?? 0;
  if (count >= limit) return false;

  await c.env.DB.prepare(
    `INSERT INTO rate_limits (key, count, expires_at) VALUES (?, ?, ?)
     ON CONFLICT(key) DO UPDATE SET count = count + 1`
  ).bind(key, count + 1, now + 120).run();

  return true;
}

// ====================================================================
// AI 解读
// ====================================================================

const SYSTEM_PROMPT = `You are an expert Ziwei Doushu (Purple Star Astrology) astrologer trained on the Ni Haixia Tianji lineage — the most authoritative contemporary interpretation system.

Your role is to deliver an accurate, insightful, and culturally-bridgeable interpretation of a person's birth chart to an English-speaking audience.

Principles:
1. Use accessible English with brief Chinese concept translations + Western parallels
2. Be specific, not generic — reference exact stars and palaces
3. Cite classical sources (Gu Su Fu, Chen Xi Yi lineage) when invoking patterns
4. Balance tradition and modernity — frame insights in practical modern terms
5. Avoid absolute predictions — use "tendencies suggest", "often indicates", "you may find"
6. Add actionable wisdom — each section ends with 1-2 suggestions
7. Use markdown: ## for sections, **bold** for key terms, > for important quotes

Output should feel like a wise, empathetic, authoritative astrologer — not a fortune cookie.`;

app.post('/api/interpret', async (c) => {
  const ip = c.req.header('cf-connecting-ip') || 'unknown';
  if (!await checkRate(c, ip, 5)) {
    return c.json({ error: 'Too many requests.' }, 429);
  }

  const { chartId, chart: clientChart, tier, sessionId, nowpaymentsPaymentId, selfCryptoOrderId } = await c.req.json() as {
    chartId?: string;
    chart?: any;
    tier: 'basic' | 'premium';
    sessionId?: string;
    nowpaymentsPaymentId?: string;
    selfCryptoOrderId?: string;
  };

  // 至少需要一个 payment ID
  if (!sessionId && !nowpaymentsPaymentId && !selfCryptoOrderId) {
    return c.json({ error: 'Missing sessionId, nowpaymentsPaymentId, or selfCryptoOrderId.' }, 400);
  }

  let paymentVerified = false;
  let paymentMethod: 'stripe' | 'nowpayments' | 'self_crypto' | null = null;
  let paymentRecordId: string = sessionId || nowpaymentsPaymentId || selfCryptoOrderId || '';

  // ===== Stripe 路径 =====
  if (sessionId) {
    if (!sessionId.startsWith('cs_')) {
      return c.json({ error: 'Invalid sessionId format.' }, 400);
    }
    let session: any;
    try {
      session = await stripeRetrieveSession(c.env.STRIPE_SECRET_KEY, sessionId);
    } catch (err: any) {
      return c.json({ error: `Stripe lookup failed: ${err.message}` }, 400);
    }
    if (session.payment_status !== 'paid') {
      return c.json({ error: 'Payment not verified.', status: session.payment_status }, 403);
    }
    const tierAmounts: Record<string, number[]> = {
      basic: [1290],
      premium: [1990],
    };
    const validAmounts = tierAmounts[tier] || [];
    if (!validAmounts.includes(session.amount_total)) {
      return c.json({
        error: `Session amount ${session.amount_total} does not match tier ${tier} (expected one of ${validAmounts.join(', ')}).`,
      }, 403);
    }
    paymentVerified = true;
    paymentMethod = 'stripe';
  }

  // ===== NOWPayments 路径 =====
  if (nowpaymentsPaymentId && !paymentVerified) {
    // payment_id 是数字,order_id 是 UUID — 两个都可能传
    const row = await c.env.DB.prepare(
      `SELECT payment_id, order_id, tier, status FROM nowpayments_payments WHERE payment_id = ? OR order_id = ?`
    ).bind(Number(nowpaymentsPaymentId) || 0, nowpaymentsPaymentId).first<any>();

    if (!row) {
      return c.json({ error: 'NOWPayments payment not found.' }, 404);
    }
    // finished = 钱到账;confirmed / sending = 链上确认中(放行以减少用户等待)
    if (!['finished', 'confirmed', 'sending'].includes(row.status)) {
      return c.json({ error: `NOWPayments payment not finished (status: ${row.status}).`, status: row.status }, 403);
    }
    if (row.tier !== tier) {
      return c.json({ error: `Payment tier ${row.tier} does not match requested ${tier}.` }, 403);
    }
    paymentVerified = true;
    paymentMethod = 'nowpayments';
    paymentRecordId = String(row.payment_id);
  }

  // ===== 自托管 XRP 路径 =====
  if (selfCryptoOrderId && !paymentVerified) {
    const row = await c.env.DB.prepare(
      `SELECT order_id, tier, status, chart_id FROM crypto_payments WHERE order_id = ?`
    ).bind(selfCryptoOrderId).first<any>();
    if (!row) {
      return c.json({ error: 'Self-hosted crypto payment not found.' }, 404);
    }
    if (row.status !== 'finished' && row.status !== 'confirmed') {
      return c.json({ error: `Crypto payment not confirmed (status: ${row.status}).`, status: row.status }, 403);
    }
    if (row.tier !== tier) {
      return c.json({ error: `Payment tier ${row.tier} does not match requested ${tier}.` }, 403);
    }
    paymentVerified = true;
    paymentMethod = 'self_crypto';
    paymentRecordId = row.order_id;
  }

  if (!paymentVerified) {
    return c.json({ error: 'Payment not verified.' }, 403);
  }

  // 优先用前端传的 chart，否则从 D1 拉
  let chart = clientChart;
  if (!chart) {
    if (!chartId) return c.json({ error: 'Missing chart. Provide chartId or chart.' }, 400);
    const row = await c.env.DB.prepare(
      `SELECT chart_json FROM charts WHERE id = ? AND (expires_at IS NULL OR expires_at > ?)`
    ).bind(chartId, Math.floor(Date.now() / 1000)).first<{ chart_json: string }>();
    if (!row) return c.json({ error: 'Chart not found in DB.' }, 404);
    chart = JSON.parse(row.chart_json);
  }

  // 缓存命中
  const cached = await c.env.DB.prepare(
    `SELECT content FROM readings WHERE order_id = ?`
  ).bind(paymentRecordId).first<{ content: string }>();
  if (cached) {
    return c.json({ reading: cached.content, cached: true });
  }

  // 调 Anthropic REST API
  const context = chartToPromptContext(chart);
  const userPrompt = tier === 'premium'
    ? `Generate a COMPREHENSIVE Ziwei Doushu reading (3,000-5,000 words) for:\n\n${context}\n\nCover 13 themes in order:
1. Life Overview
2. Personality & Temperament
3. Career & Wealth Path
4. Relationships & Marriage
5. Family & Social Bonds
6. Health & Vitality
7. Travel & External Relations
8. Mental State & Spirituality
9. Major Luck Periods (next 10-year cycles)
10. Annual Fortune ${new Date().getFullYear()}
11. Auspicious Patterns
12. Challenges & Remedies
13. Practical Wisdom`
    : `Generate a CONCISE Ziwei Doushu reading (500-800 words) for:\n\n${context}\n\nCover 5 themes:
1. Cosmic Identity
2. Career & Money
3. Relationships
4. Life Cycles
5. One Key Insight

End with brief encouragement.`;

  const anthropicResp = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': c.env.ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      model: 'claude-sonnet-4-5',
      max_tokens: tier === 'premium' ? 8000 : 2000,
      system: SYSTEM_PROMPT,
      messages: [{ role: 'user', content: userPrompt }],
    }),
  });

  if (!anthropicResp.ok) {
    const errText = await anthropicResp.text();
    return c.json({ error: `Anthropic API ${anthropicResp.status}: ${errText.slice(0, 300)}` }, 502);
  }

  const anthropicJson: any = await anthropicResp.json();
  const text = anthropicJson.content?.[0]?.type === 'text' ? anthropicJson.content[0].text : '';

  await c.env.DB.prepare(
    `INSERT INTO readings (id, chart_id, order_id, tier, content, tokens_used) VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(
    crypto.randomUUID(),
    chartId || 'unknown',
    paymentRecordId,
    tier,
    text,
    anthropicJson.usage?.output_tokens ?? 0
  ).run();

  return c.json({ reading: text, tier, tokensUsed: anthropicJson.usage });
});

// ====================================================================
// Stripe Webhook — HMAC 验签 + 留痕
// ====================================================================

app.post('/api/webhook/stripe', async (c) => {
  const sig = c.req.header('stripe-signature');
  const body = await c.req.text();

  if (!sig) return c.json({ error: 'No signature' }, 400);

  const parts = sig.split(',').reduce((acc: any, p) => {
    const [k, v] = p.split('=');
    acc[k] = v;
    return acc;
  }, {} as Record<string, string>);
  const timestamp = parts.t;
  const v1 = parts.v1;
  if (!timestamp || !v1) return c.json({ error: 'Invalid signature header' }, 400);

  const age = Math.abs(Date.now() / 1000 - Number(timestamp));
  if (age > 300) return c.json({ error: 'Timestamp too old' }, 400);

  const signedPayload = `${timestamp}.${body}`;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(c.env.STRIPE_WEBHOOK_SECRET),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );
  const sigBytes = hexToBytes(v1);
  const expectedSig = await crypto.subtle.verify(
    'HMAC',
    key,
    sigBytes as BufferSource,
    new TextEncoder().encode(signedPayload) as BufferSource
  );
  if (!expectedSig) return c.json({ error: 'Invalid signature' }, 400);

  const event = JSON.parse(body);
  console.log(`[webhook] verified: type=${event.type}, id=${event.id}`);

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    try {
      await c.env.DB.prepare(
        `INSERT OR IGNORE INTO payments (session_id, amount_total, currency, customer_email, status, paid_at)
         VALUES (?, ?, ?, ?, 'paid', unixepoch())`
      ).bind(
        session.id,
        session.amount_total ?? 0,
        session.currency ?? 'usd',
        session.customer_details?.email ?? null
      ).run();
    } catch (err: any) {
      console.log(`[webhook] payments insert skipped: ${err.message}`);
    }
  }

  return c.json({ received: true });
});

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

// ====================================================================
// Helpers
// ====================================================================

function chartToPromptContext(chart: any): string {
  const lines: string[] = [];
  lines.push(`Birth Date (Solar): ${chart.solarDate}`);
  lines.push(`Birth Date (Lunar): ${chart.lunarDate}`);
  lines.push(`Zodiac: ${chart.chineseZodiac}`);
  lines.push(`Five Element Class: ${chart.fiveElementClass}`);
  lines.push(`Destiny Palace Branch: ${chart.destinyPalaceBranch}`);
  lines.push('');
  lines.push('Palaces:');
  if (chart.palaces && Array.isArray(chart.palaces)) {
    chart.palaces.forEach((p: any) => {
      const stars = p.mainStars?.map((s: any) => `${s.nameEN || s.nameCN} (${s.nameCN})`).join(', ') || '(empty)';
      lines.push(`  ${p.palaceNameEN} (${p.palaceNameCN}, ${p.earthlyBranch}): ${stars}`);
      if (p.sihua && p.sihua.length > 0) {
        lines.push(`    Sihua: ${p.sihua.map((s: any) => `${s.star}(${s.type})`).join(', ')}`);
      }
    });
  }
  if (chart.summary?.dominantStars?.length > 0) {
    lines.push('');
    lines.push(`Dominant Stars: ${chart.summary.dominantStars.join(', ')}`);
  }
  if (chart.summary?.keyPatterns?.length > 0) {
    lines.push(`Key Patterns: ${chart.summary.keyPatterns.join('; ')}`);
  }
  return lines.join('\n');
}

// ====================================================================
// IndexNow 推送端点
// ====================================================================

app.post('/indexnow', async (c) => {
  try {
    const body = await c.req.json().catch(() => null);
    if (!body || !Array.isArray(body.urls)) {
      return c.json({ ok: false, error: 'body must be { urls: string[] }' }, 400);
    }
    const urls = body.urls.filter((u: unknown): u is string => typeof u === 'string');
    if (urls.length === 0) return c.json({ ok: false, error: 'urls array empty' }, 400);
    if (urls.length > 10000) return c.json({ ok: false, error: 'too many urls (max 10000)' }, 400);

    const host = 'https://purplestar.cc';
    for (const u of urls) {
      if (!u.startsWith(host)) {
        return c.json({ ok: false, error: `url outside host: ${u}` }, 400);
      }
    }

    const payload = {
      host: 'purplestar.cc',
      key: INDEXNOW_KEY,
      keyLocation: INDEXNOW_KEY_LOCATION,
      urlList: urls,
    };

    const r = await fetch('https://api.indexnow.org/indexnow', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
      body: JSON.stringify(payload),
    });

    const text = await r.text();
    // IndexNow 状态码:
    //   200 = OK, URL submitted
    //   202 = Accepted (queued)
    //   429 = Too many requests — URL 通常已被接收,只是同一 IP 短时间不能再推
    //   400/403/422 = 真错误(格式错 / key 无效 / URL 不属于 host)
    // 把 200/202/429 都视为"推送意图已送达",仅 4xx 其它状态算失败。
    // 这避免 worker 用同一 IP 频繁调时被误判失败(其实 URL 已经在 IndexNow 队列里)。
    const accepted = r.status === 200 || r.status === 202 || r.status === 429;
    const httpStatus = accepted ? 200 : 502;
    return c.json({
      ok: accepted,
      indexnow_status: r.status,
      indexnow_body: text.slice(0, 300),
      pushed: urls.length,
      note: r.status === 429
        ? 'IndexNow rate-limited this IP. URLs were likely already received — Bing will pick them up within 24-48h. No need to retry.'
        : r.status === 202
        ? 'URLs queued by IndexNow. They will be crawled soon.'
        : undefined,
    }, httpStatus);
  } catch (err: any) {
    return c.json({ ok: false, error: err.message }, 500);
  }
});

// ====================================================================
// 自托管加密货币支付 — 派生 XRP 收款地址,链上 watcher 监听
//   docs: see src/lib/xrp-hd.ts
//   路径:m / 44' / 144' / 0' / 0 / <next_index>
//   状态机:waiting → confirming (链上确认中) → confirmed → finished
//                              ↘ failed / expired (>30 min)
//   锁定价格:创单时 USD→XRP 汇率,30 分钟内按此金额收(防止汇率波动)
//   链上 watcher:CF Cron Triggers (每 60s 一次,扫 XRP ledger)
// ====================================================================

import { deriveXrpAddressFromMnemonic } from './lib/xrp-hd';
import { deriveTronAddressFromMnemonic } from './lib/tron-hd';

const SELF_TIER_AMOUNTS: Record<string, { usd: number; product: string; expires_sec: number }> = {
  basic: { usd: 12.9, product: 'PurpleStar Basic Reading', expires_sec: 1800 },   // 30 min
  premium: { usd: 19.9, product: 'PurpleStar Premium Reading', expires_sec: 1800 },
};

// 简单的 USD/XRP 汇率缓存(D1 存最近一次查询结果,5 分钟过期)
async function getXrpUsdRate(env: Env): Promise<number> {
  return getFxRate(env, 'xrp', 'XRP_USD_PRICE_URL', 'ripple', 1.4);
}

async function getUsdtUsdRate(env: Env): Promise<number> {
  // USDT 通常 ≈ $1,但保险起见查一下。CoinGecko id = 'tether'
  return getFxRate(env, 'usdt', 'USDT_USD_PRICE_URL', 'tether', 1.0);
}

// 通用 FX rate 缓存(cache key by coin)
async function getFxRate(
  env: Env,
  coin: string,
  envVarKey: string,
  coingeckoId: string,
  fallback: number,
): Promise<number> {
  const cached = await env.DB.prepare(
    `SELECT rate, fetched_at FROM crypto_fx_cache WHERE id = ?`
  ).bind(coin === 'xrp' ? 1 : (coin === 'usdt' ? 2 : 3)).first<{ rate: number; fetched_at: number }>();
  const now = Math.floor(Date.now() / 1000);
  if (cached && (now - cached.fetched_at) < 300) return cached.rate;
  const url = (env as any)[envVarKey] || `https://api.coingecko.com/api/v3/simple/price?ids=${coingeckoId}&vs_currencies=usd`;
  try {
    const r = await fetch(url);
    if (!r.ok) throw new Error(`FX rate fetch failed: ${r.status}`);
    const j: any = await r.json();
    const rate = j?.[coingeckoId]?.usd;
    if (typeof rate !== 'number') throw new Error('rate missing in FX response');
    await env.DB.prepare(
      `INSERT OR REPLACE INTO crypto_fx_cache (id, rate, fetched_at) VALUES (?, ?, ?)`
    ).bind(coin === 'xrp' ? 1 : (coin === 'usdt' ? 2 : 3), rate, now).run();
    return rate;
  } catch (e) {
    if (cached) return cached.rate;
    console.error(`[crypto ${coin}] FX rate fallback:`, e);
    return fallback;
  }
}

// atomic next_index — 按币种各自递增(XRP / Tron / 未来 BTC 用不同派生路径)
// 单一 index 改为每币种一行
async function allocateNextDerivationIndex(env: Env, payCurrency: string): Promise<number> {
  await env.DB.prepare(
    `INSERT OR IGNORE INTO crypto_hd_wallet_per_currency (pay_currency, next_index, updated_at) VALUES (?, 0, unixepoch())`
  ).bind(payCurrency).run();
  const row = await env.DB.prepare(
    `SELECT next_index FROM crypto_hd_wallet_per_currency WHERE pay_currency = ?`
  ).bind(payCurrency).first<{ next_index: number }>();
  const idx = row?.next_index ?? 0;
  await env.DB.prepare(
    `UPDATE crypto_hd_wallet_per_currency SET next_index = next_index + 1, updated_at = unixepoch() WHERE pay_currency = ?`
  ).bind(payCurrency).run();
  return idx;
}

// 幂等 init — D1 schema 部署(CF token 没 D1 权限时,worker 自己 IF NOT EXISTS 建表)
let _dbInitPromise: Promise<void> | null = null;
async function ensureCryptoSchema(env: Env): Promise<void> {
  if (_dbInitPromise) return _dbInitPromise;
  _dbInitPromise = (async () => {
    const stmts = [
      `CREATE TABLE IF NOT EXISTS crypto_payments (
        order_id TEXT PRIMARY KEY,
        address TEXT UNIQUE NOT NULL,
        derivation_index INTEGER NOT NULL,
        tier TEXT NOT NULL,
        chart_id TEXT,
        amount_xrp REAL NOT NULL,
        amount_usd REAL NOT NULL,
        xrp_usd_rate REAL NOT NULL,
        status TEXT NOT NULL DEFAULT 'waiting',
        tx_hash TEXT,
        paid_at INTEGER,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL DEFAULT (unixepoch()),
        finished_at INTEGER
      )`,
      `CREATE TABLE IF NOT EXISTS crypto_hd_wallet (
        id INTEGER PRIMARY KEY DEFAULT 1,
        next_index INTEGER NOT NULL DEFAULT 0,
        updated_at INTEGER NOT NULL DEFAULT (unixepoch())
      )`,
      `CREATE TABLE IF NOT EXISTS crypto_fx_cache (
        id INTEGER PRIMARY KEY DEFAULT 1,
        rate REAL NOT NULL,
        fetched_at INTEGER NOT NULL
      )`,
      // multi-currency 扩展 (USDT TRC20 等):每加一个币种,加一个派生索引字段 + 金额字段
      `CREATE TABLE IF NOT EXISTS crypto_hd_wallet_per_currency (
        pay_currency TEXT PRIMARY KEY,
        next_index INTEGER NOT NULL DEFAULT 0,
        updated_at INTEGER NOT NULL DEFAULT (unixepoch())
      )`,
      // ALTER TABLE IF NOT EXISTS — SQLite 不支持,改成 try/catch 每列
      `ALTER TABLE crypto_payments ADD COLUMN pay_currency TEXT NOT NULL DEFAULT 'xrp'`,
      `ALTER TABLE crypto_payments ADD COLUMN amount_usdt REAL`,
      `ALTER TABLE crypto_payments ADD COLUMN usdt_usd_rate REAL`,
      `ALTER TABLE crypto_payments ADD COLUMN amount_btc REAL`,
      `ALTER TABLE crypto_payments ADD COLUMN btc_usd_rate REAL`,
      `CREATE INDEX IF NOT EXISTS idx_crypto_payments_currency ON crypto_payments(pay_currency)`,
    ];
    for (const sql of stmts) {
      try { await env.DB.prepare(sql).run(); } catch (e: any) { /* ignore */ }
    }
  })();
  return _dbInitPromise;
}

app.post('/api/crypto/create-payment', async (c) => {
  try {
    // 幂等建表(D1 token 没 schema 权限时,worker 启动时自己 IF NOT EXISTS)
    await ensureCryptoSchema(c.env);

    const body = await c.req.json().catch(() => null) as {
      tier?: string; chartId?: string; chart?: any; pay_currency?: string;
    } | null;
    if (!body) return c.json({ error: 'invalid JSON body' }, 400);

    const tier = body.tier;
    if (tier !== 'basic' && tier !== 'premium') {
      return c.json({ error: 'tier must be basic or premium' }, 400);
    }
    const payCurrency = (body.pay_currency || 'xrp').toLowerCase();
    if (!['xrp', 'usdt_trc20'].includes(payCurrency)) {
      return c.json({ error: `pay_currency must be one of: xrp, usdt_trc20 (got: ${payCurrency})` }, 400);
    }
    const { usd, expires_sec } = SELF_TIER_AMOUNTS[tier];

    // 暂存 chart(可选)
    if (body.chart && body.chartId) {
      const now = Math.floor(Date.now() / 1000);
      await c.env.DB.prepare(
        `INSERT OR REPLACE INTO charts (id, input_json, chart_json, expires_at) VALUES (?, ?, ?, ?)`
      ).bind(body.chartId, '{}', JSON.stringify(body.chart), now + 86400).run();
    }

    // 派生新地址(每币种独立 HD index)
    const orderId = crypto.randomUUID();
    const derivationIndex = await allocateNextDerivationIndex(c.env, payCurrency);
    let address: string;
    let payAmount: number;
    let fxRate: number;

    if (payCurrency === 'xrp') {
      const derived = deriveXrpAddressFromMnemonic(c.env.XRP_MNEMONIC, derivationIndex);
      address = derived.address;
      const xrpUsd = await getXrpUsdRate(c.env);
      fxRate = xrpUsd;
      payAmount = Math.ceil((usd / xrpUsd) * 1.05 * 1_000_000) / 1_000_000; // 6 位精度,向上取整
    } else {
      // usdt_trc20 — Tron HD wallet
      const derived = deriveTronAddressFromMnemonic(c.env.XRP_MNEMONIC, derivationIndex);
      address = derived.address;
      const usdtUsd = await getUsdtUsdRate(c.env);
      fxRate = usdtUsd;
      // USDT TRC20 6 decimals,与 XRP 一致精度
      payAmount = Math.ceil((usd / usdtUsd) * 1.05 * 1_000_000) / 1_000_000;
    }

    const now = Math.floor(Date.now() / 1000);
    // 通用 INSERT — amount_xrp 在 usdt 订单里填 0,xrp_usd_rate 在 usdt 里填 usdt_usd_rate
    const amountXrpForRow = payCurrency === 'xrp' ? payAmount : 0;
    const amountUsdtForRow = payCurrency === 'usdt_trc20' ? payAmount : null;
    const xrpRateForRow = payCurrency === 'xrp' ? fxRate : null;
    const usdtRateForRow = payCurrency === 'usdt_trc20' ? fxRate : null;
    await c.env.DB.prepare(
      `INSERT INTO crypto_payments
         (order_id, address, derivation_index, pay_currency, tier, chart_id,
          amount_xrp, amount_usd, xrp_usd_rate, amount_usdt, usdt_usd_rate,
          status, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'waiting', ?, ?)`
    ).bind(
      orderId,
      address,
      derivationIndex,
      payCurrency,
      tier,
      body.chartId || null,
      amountXrpForRow,
      usd,
      xrpRateForRow,
      amountUsdtForRow,
      usdtRateForRow,
      now + expires_sec,
      now,
    ).run();

    return c.json({
      ok: true,
      order_id: orderId,
      pay_address: address,
      pay_amount: payAmount,
      pay_currency: payCurrency,
      amount_usd: usd,
      fx_rate: fxRate,
      tier,
      expires_at: now + expires_sec,
      expires_in_sec: expires_sec,
    });
  } catch (err: any) {
    return c.json({ ok: false, error: err.message }, 500);
  }
});

// 状态查询(支持多币种 xrp | usdt_trc20)
app.get('/api/crypto/payment/:orderId', async (c) => {
  const orderId = c.req.param('orderId');
  await ensureCryptoSchema(c.env);
  const row = await c.env.DB.prepare(
    `SELECT order_id, address, derivation_index, pay_currency, tier, chart_id,
            amount_xrp, amount_usd, xrp_usd_rate,
            amount_usdt, usdt_usd_rate,
            status, tx_hash, paid_at, expires_at, created_at, finished_at
     FROM crypto_payments WHERE order_id = ?`
  ).bind(orderId).first<any>();
  if (!row) return c.json({ error: 'payment not found' }, 404);
  const now = Math.floor(Date.now() / 1000);
  const expired = now > row.expires_at && row.status === 'waiting';
  const payCurrency = row.pay_currency || 'xrp';
  const amountUnits = payCurrency === 'xrp' ? row.amount_xrp : row.amount_usdt;
  const fxRate = payCurrency === 'xrp' ? row.xrp_usd_rate : row.usdt_usd_rate;
  return c.json({
    ...row,
    status: expired ? 'expired' : row.status,
    pay_currency: payCurrency,
    pay_amount: amountUnits,
    fx_rate: fxRate,
  });
});


// ====================================================================
// 旧的 NOWPayments 路由 — 已禁用(KYC 未通过),保留代码以备重启
//   启用方式:取消下面整段注释,改回 /api/nowpayments/* 即可
// ====================================================================
/*
const NOWPAYMENTS_TIER_AMOUNTS_DISABLED: Record<string, { usd: number; product: string }> = {
  basic: { usd: 12.9, product: 'PurpleStar Basic Reading' },
  premium: { usd: 19.9, product: 'PurpleStar Premium Reading' },
};

app.post('/api/nowpayments/create-payment', async (c) => { ... 已禁用 ... });
  try {
    const body = await c.req.json().catch(() => null) as { tier?: string; chartId?: string; chart?: any } | null;
    if (!body) return c.json({ error: 'invalid JSON body' }, 400);

    const tier = body.tier;
    if (tier !== 'basic' && tier !== 'premium') {
      return c.json({ error: 'tier must be basic or premium' }, 400);
    }
    const { usd, product } = NOWPAYMENTS_TIER_AMOUNTS[tier];

    // 把 chart(如果前端传了)暂存到 charts 表,跟 Stripe 流程对齐
    // 这样 /report 页面如果丢了 sessionStorage,也能从 D1 拿回
    if (body.chart && body.chartId) {
      const now = Math.floor(Date.now() / 1000);
      await c.env.DB.prepare(
        `INSERT OR REPLACE INTO charts (id, input_json, chart_json, expires_at) VALUES (?, ?, ?, ?)`
      ).bind(body.chartId, '{}', JSON.stringify(body.chart), now + 86400).run();
    }

    // 创建 NOWPayments payment
    // pay_currency 选型:
    //   - USDT TRC20:最低 $11.52 等值,$9.9 不行
    //   - BTC:最低 0.0002879 BTC ≈ $22 当前价,$9.9/$19.9 也不行
    //   - XRP:最低 $8.72 等值,$9.9/$19.9 都 OK,XRP 链上 3 秒确认,手续费几乎为零
    // 结论:XRP 是这个价位唯一能保留 $9.9 起步的币种
    const orderId = crypto.randomUUID();
    const npResp = await fetch('https://api.nowpayments.io/v1/payment', {
      method: 'POST',
      headers: {
        'x-api-key': c.env.NOWPAYMENTS_API_KEY,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        price_amount: usd,
        price_currency: 'usd',
        pay_currency: 'xrp',
        order_id: orderId,
        order_description: `${product} (Chart ${body.chartId || 'inline'})`,
        ipn_callback_url: `${c.env.SITE_URL}/api/nowpayments/webhook`,
        success_url: `${c.env.SITE_URL}/payment-return-crypto?order_id=${orderId}&tier=${tier}&chartId=${body.chartId || ''}`,
        cancel_url: `${c.env.SITE_URL}/chart?id=${body.chartId || ''}`,
      }),
    });

    if (!npResp.ok) {
      const errText = await npResp.text();
      return c.json({ error: `NOWPayments API ${npResp.status}: ${errText.slice(0, 300)}` }, 502);
    }

    const npJson: any = await npResp.json();
    // NOWPayments 返回:{ payment_id, payment_status, pay_address, pay_amount, pay_currency, ... }
    // hosted invoice URL 在 invoice_url 或 invoice_id 拼接
    const paymentId = npJson.payment_id;
    const invoiceUrl = npJson.invoice_url
      || (npJson.invoice_id ? `https://nowpayments.io/payment/?iid=${npJson.invoice_id}` : null)
      || `https://nowpayments.io/payment/?paymentId=${paymentId}`;

    // 写 D1:order_id → payment_id 映射,webhook 回调时更新 status
    await c.env.DB.prepare(
      `INSERT INTO nowpayments_payments (payment_id, order_id, tier, chart_id, amount_usd, pay_currency, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, unixepoch())`
    ).bind(
      paymentId,
      orderId,
      tier,
      body.chartId || null,
      usd,
      npJson.pay_currency || null,
      npJson.payment_status || 'waiting',
    ).run();

    return c.json({
      ok: true,
      payment_id: paymentId,
      order_id: orderId,
      invoice_url: invoiceUrl,
      pay_address: npJson.pay_address,
      pay_amount: npJson.pay_amount,
      pay_currency: npJson.pay_currency,
      amount_usd: usd,
      tier,
    });
  } catch (err: any) {
    return c.json({ ok: false, error: err.message }, 500);
  }
});

// IPN webhook — NOWPayments 服务器主动通知支付状态
//   签名:NOWPayments 用 IPN secret 签 JSON body (HMAC-SHA512,hex)
//   header: x-nowpayments-sig
//   文档:https://nowpayments.io/help/why-do-you-need-ipn
app.post('/api/nowpayments/webhook', async (c) => {
  try {
    const raw = await c.req.text();
    const sig = c.req.header('x-nowpayments-sig');

    if (!sig) {
      console.log('[nowpayments webhook] missing signature');
      return c.json({ error: 'missing x-nowpayments-sig' }, 400);
    }

    // HMAC-SHA512 验证
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(c.env.NOWPAYMENTS_IPN_SECRET),
      { name: 'HMAC', hash: 'SHA-512' },
      false,
      ['sign']
    );
    const sigBytes = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(raw));
    const expectedHex = Array.from(new Uint8Array(sigBytes))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    if (expectedHex !== sig.toLowerCase()) {
      console.log('[nowpayments webhook] signature mismatch');
      return c.json({ error: 'invalid signature' }, 400);
    }

    const payload = JSON.parse(raw);
    const paymentId = payload.payment_id;
    const status = payload.payment_status; // waiting / confirming / confirmed / sending / finished / failed / refunded

    console.log(`[nowpayments webhook] payment_id=${paymentId} status=${status}`);

    // 更新 D1 状态,finished/failed 时记时间戳
    await c.env.DB.prepare(
      `UPDATE nowpayments_payments SET status = ?, finished_at = CASE WHEN ? IN ('finished','failed','refunded') THEN unixepoch() ELSE finished_at END WHERE payment_id = ?`
    ).bind(status, status, paymentId).run();

    return c.json({ received: true });
  } catch (err: any) {
    console.log(`[nowpayments webhook] error: ${err.message}`);
    return c.json({ error: err.message }, 500);
  }
});

// 校验端点(供前端 /report 调):查 payment_id 是否 finished
app.get('/api/nowpayments/payment/:id', async (c) => {
  const id = c.req.param('id');
  // payment_id 是数字,order_id 是 UUID 字符串 — 用 UNION 风格查询两个字段
  const row = await c.env.DB.prepare(
    `SELECT payment_id, order_id, tier, chart_id, amount_usd, pay_currency, status, created_at, finished_at
     FROM nowpayments_payments WHERE payment_id = ? OR order_id = ?`
  ).bind(Number(id) || 0, id).first<any>();

  if (!row) return c.json({ error: 'payment not found' }, 404);
  return c.json(row);
});
*/


// ====================================================================
// CF Cron Trigger — 链上 watcher
//   每 60 秒扫一次所有 status IN (waiting, confirming) 的订单
//   用 xrpl.org public rippled JSON-RPC 查每个地址的入账
//   命中:更新 status=finished/confirmed,记录 tx_hash
// ====================================================================

interface RippleTransaction {
  tx: {
    hash: string;
    Account: string;
    Destination?: string;
    Amount?: string | { value: string; currency: string; issuer?: string };
    DestinationTag?: number;
  };
  meta?: { TransactionResult?: string };
  ledger_index?: number;
  date?: number;
}

async function fetchAccountTxs(address: string, limit = 20): Promise<RippleTransaction[]> {
  // Public rippled HTTP JSON-RPC endpoint
  const r = await fetch('https://xrplcluster.com/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      method: 'account_tx',
      params: [{
        account: address,
        ledger_index_min: -1,
        ledger_index_max: -1,
        limit,
        forward: true,  // newest first
      }],
    }),
  });
  if (!r.ok) throw new Error(`XRPL RPC ${r.status}`);
  const j: any = await r.json();
  return j?.result?.transactions || [];
}

/**
 * Fetch incoming USDT TRC20 transactions for a Tron address via TronGrid.
 * Public endpoint, no API key needed for low volume; rate limit is generous.
 * Returns the `data` array (each item has token_info, to, value, transaction_id, block_timestamp, confirmations).
 */
async function fetchTronTrc20Txs(address: string, limit = 20): Promise<any[]> {
  const url = `https://api.trongrid.io/v1/accounts/${address}/transactions/trc20?only_confirmed=true&limit=${limit}`;
  const r = await fetch(url, { headers: { 'Accept': 'application/json' } });
  if (!r.ok) throw new Error(`TronGrid ${r.status}`);
  const j: any = await r.json();
  return j?.data || [];
}

async function watchCryptoPayments(env: Env): Promise<{ scanned: number; confirmed: number; expired: number }> {
  const now = Math.floor(Date.now() / 1000);
  // 取所有未完成且未过期的订单,包含 pay_currency 和 amount 字段
  const pending = await env.DB.prepare(
    `SELECT order_id, address, pay_currency, amount_xrp, amount_usdt, status, expires_at, created_at, tier
     FROM crypto_payments
     WHERE status IN ('waiting', 'confirming') AND expires_at > ?
     ORDER BY created_at ASC
     LIMIT 50`
  ).bind(now).all<any>();

  let confirmed = 0;
  for (const p of pending.results || []) {
    try {
      const payCurrency = p.pay_currency || 'xrp';
      if (payCurrency === 'xrp') {
        // XRP — XRPL account_tx
        const txs = await fetchAccountTxs(p.address, 20);
        for (const t of txs) {
          if (t.tx?.Destination !== p.address) continue;
          if (t.meta?.TransactionResult && t.meta.TransactionResult !== 'tesSUCCESS') continue;
          const amt = t.tx.Amount;
          const drops = typeof amt === 'string' ? amt : null;
          if (!drops) continue;
          const xrpReceived = Number(drops) / 1_000_000;
          if (xrpReceived >= p.amount_xrp * 0.95) {
            const txHash = t.tx.hash;
            await env.DB.prepare(
              `UPDATE crypto_payments
               SET status = 'finished', tx_hash = ?, paid_at = ?, finished_at = ?
               WHERE order_id = ? AND status IN ('waiting', 'confirming')`
            ).bind(txHash, now, now, p.order_id).run();
            confirmed++;
            console.log(`[watcher/xrp] finished order=${p.order_id} addr=${p.address} tx=${txHash} received=${xrpReceived} XRP`);
            break;
          }
        }
      } else if (payCurrency === 'usdt_trc20') {
        // USDT TRC20 — TronGrid /v1/accounts/{addr}/transactions/trc20
        const trc20Txs = await fetchTronTrc20Txs(p.address, 20);
        const USDT_CONTRACT = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t';
        for (const tx of trc20Txs) {
          if (tx.token_info?.address !== USDT_CONTRACT) continue;
          if (tx.to !== p.address) continue;
          // confirmed status — block too deep = unconfirmed
          // trongrid returns confirmations from block height; treat confirmed=true if present
          if (tx.confirmations !== undefined && tx.confirmations < 1) continue;
          // amount: USDT TRC20 6 decimals — string
          const raw = tx.value || tx.amount_str;
          if (!raw) continue;
          // trongrid sometimes returns numeric amount (already divided by 10^6); sometimes raw 6-decimal string
          let received: number;
          if (typeof raw === 'number') {
            received = raw;
          } else {
            received = Number(raw) / 1_000_000;
          }
          if (received >= p.amount_usdt * 0.95) {
            const txHash = tx.transaction_id;
            await env.DB.prepare(
              `UPDATE crypto_payments
               SET status = 'finished', tx_hash = ?, paid_at = ?, finished_at = ?
               WHERE order_id = ? AND status IN ('waiting', 'confirming')`
            ).bind(txHash, now, now, p.order_id).run();
            confirmed++;
            console.log(`[watcher/usdt] finished order=${p.order_id} addr=${p.address} tx=${txHash} received=${received} USDT`);
            break;
          }
        }
      }
    } catch (err: any) {
      console.log(`[watcher] error for ${p.address}: ${err.message}`);
    }
  }

  // 处理过期订单
  const expired = await env.DB.prepare(
    `UPDATE crypto_payments SET status = 'expired', finished_at = ?
     WHERE status IN ('waiting', 'confirming') AND expires_at <= ?`
  ).bind(now, now).run();

  return {
    scanned: pending.results?.length || 0,
    confirmed,
    expired: expired.meta?.changes || 0,
  };
}

// CF scheduled handler — wrangler.toml 里 [triggers] crons = ["*\/2 * * * *"] 每 2 分钟
async function handleScheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
  ctx.waitUntil(
    watchCryptoPayments(env).then(r =>
      console.log(`[cron] watcher: scanned=${r.scanned} confirmed=${r.confirmed} expired=${r.expired}`)
    ).catch(e => console.error('[cron] watcher error:', e))
  );
}

export default app;
export { handleScheduled };

