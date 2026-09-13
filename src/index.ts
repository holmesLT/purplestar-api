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
  // Cryptomus (方案 B 加密支付) — 通过 `wrangler secret put` 配置
  CRYPTOMUS_MERCHANT_ID?: string;
  CRYPTOMUS_PAYMENT_API_KEY?: string;
  ADMIN_KEY?: string;
  ARBITRUM_RPC_URL?: string;  // 免费注册的专属 RPC(Alchemy/Ankr/dRPC 等),配了就优先用
}

// ============================================================================
// Cryptomus 支付网关
//   - 建单:  POST https://api.cryptomus.com/v1/payment
//   - 查单:  GET  https://api.cryptomus.com/v1/payment/{uuid}
//   - 回调:  POST {API}/api/crypto/webhook/cryptomus  (sign = md5(b64(body)+key))
//   验签:  sign = md5(base64(JSON body) + PAYMENT_API_KEY);GET 空 body 时
//          base64('') === '' 故 sign = md5(API_KEY)
// ============================================================================

const CRYPTOMUS_API = 'https://api.cryptomus.com/v1';
// 挂在你自己的 worker 域名下;改域名时同步修改
const CRYPTOMUS_WEBHOOK_URL = 'https://api.purplestar.cc/api/crypto/webhook/cryptomus';
// Cryptomus 发票有效期(秒)。文档默认/最小值较宽,取 1 小时。
const CRYPTOMUS_LIFETIME_SEC = 3600;

function md5(input: string): string {
  const msg = new TextEncoder().encode(input);
  const bitLen = msg.length * 8;
  const padded = new Uint8Array((((msg.length + 8) >> 6) + 1) << 6);
  padded.set(msg);
  padded[msg.length] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padded.length - 8, bitLen >>> 0, true);
  dv.setUint32(padded.length - 4, Math.floor(bitLen / 0x100000000), true);

  const S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
             5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
             4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
             6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
  const K = new Uint32Array(64);
  for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296);

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  for (let off = 0; off < padded.length; off += 64) {
    const M = new Uint32Array(16);
    for (let i = 0; i < 16; i++) M[i] = dv.getUint32(off + i * 4, true);
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F: number, g: number;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + K[i] + M[g]) >>> 0;
      A = D; D = C; C = B;
      B = (B + ((F << S[i]) | (F >>> (32 - S[i])))) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }
  const out = new Uint32Array([a0, b0, c0, d0]);
  return Array.from(new Uint8Array(out.buffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function cryptomusRequest(
  env: Env,
  method: 'GET' | 'POST',
  path: string,
  body?: Record<string, unknown>,
): Promise<any> {
  const apiKey = env.CRYPTOMUS_PAYMENT_API_KEY!;
  const bodyJson = body ? JSON.stringify(body) : '';
  const sign = md5(btoa(bodyJson) + apiKey);
  const resp = await fetch(`${CRYPTOMUS_API}${path}`, {
    method,
    headers: {
      merchant: env.CRYPTOMUS_MERCHANT_ID!,
      sign,
      'Content-Type': 'application/json',
    },
    body: method === 'POST' ? bodyJson : undefined,
  });
  const data: any = await resp.json().catch(() => null);
  if (!resp.ok || !data || data.state !== 0) {
    throw new Error(`Cryptomus ${path} failed (${resp.status}): ${JSON.stringify(data)}`);
  }
  return data.result;
}

// Cryptomus payment_status → 本库 crypto_payments.status
// 成功态映射为 'confirmed'(/api/interpret 的解锁校验已接受该状态)
function mapCryptomusStatus(ps: string): 'waiting' | 'confirmed' | 'failed' | 'expired' {
  switch (ps) {
    case 'confirmed':
    case 'paid':          // 已打款、等待网络确认;TRC20 通常秒级进入 confirmed
      return 'confirmed';
    case 'canceled':
    case 'fail':
    case 'wrong_amount':
      return 'failed';
    case 'expired':
    case 'not_paid':
      return 'expired';
    default:              // check / process / confirm_check / create / etc.
      return 'waiting';
  }
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
// Admin endpoints — guarded by ADMIN_KEY secret (set via wrangler secret put ADMIN_KEY)
//   POST /api/admin/reset-hd-counters
//     - DELETE all crypto_payments test orders
//     - DELETE crypto_hd_wallet_per_currency rows
//     - INSERT fresh rows for 'xrp' and 'usdt_trc20' at next_index = 0
//     - Use after replacing XRP_MNEMONIC to start fresh address space
// ====================================================================
async function requireAdmin(c: any): Promise<boolean> {
  const auth = c.req.header('X-Admin-Key') || c.req.header('Authorization')?.replace(/^Bearer\s+/i, '');
  return !!auth && auth === (c.env as any).ADMIN_KEY;
}

// 归集配置与 gas 赞助地址(需给赞助地址充少量 Arbitrum ETH,归集才能执行)
app.post('/api/admin/sweep-now', async (c) => {
  if (c.req.header('x-admin-key') !== c.env.ADMIN_KEY) return c.json({ error: 'unauthorized' }, 403);
  await ensureCryptoSchema(c.env);
  try {
    const result = await sweepEvmOrders(c.env);
    return c.json({ ok: true, ...result });
  } catch (err: any) {
    return c.json({ ok: false, error: err.message, stack: err.stack?.slice(0, 500) }, 500);
  }
});

app.get('/api/admin/rpc-diag', async (c) => {
  if (c.req.header('x-admin-key') !== c.env.ADMIN_KEY) return c.json({ error: 'unauthorized' }, 403);
  const endpoints = c.env.ARBITRUM_RPC_URL ? [c.env.ARBITRUM_RPC_URL, ...ARBITUM_RPCS] : ARBITUM_RPCS;
  const results: any[] = [];
  for (const rpc of endpoints) {
    try {
      const r = await fetch(rpc, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_blockNumber', params: [] }),
      });
      let body: any = null;
      try { body = await r.json(); } catch { try { body = (await r.text()).slice(0, 120); } catch {} }
      results.push({ rpc: rpc.slice(0, 60), status: r.status, ok: !!body?.result, result: body?.result ?? String(body?.message ?? '').slice(0, 80) });
    } catch (err: any) {
      results.push({ rpc: rpc.slice(0, 60), error: err.message.slice(0, 120) });
    }
  }
  return c.json({ has_custom: !!c.env.ARBITRUM_RPC_URL, results });
});

app.get('/api/admin/sweep-info', async (c) => {
  if (!(await requireAdmin(c))) return c.json({ error: 'unauthorized' }, 401);
  const sponsor = deriveEvmKeypairFromMnemonic(c.env.XRP_MNEMONIC, SWEEP_SPONSOR_INDEX);
  const sponsorTron = deriveTronAddressFromMnemonic(c.env.XRP_MNEMONIC, SWEEP_SPONSOR_INDEX);
  return c.json({
    evm: {
      sponsor_address: sponsor.address,
      sweep_dest: SWEEP_DEST_EVM,
      note: 'Send ~0.0005-0.001 ETH (Arbitrum One) to sponsor_address once — it pays gas for all sweeps.',
    },
    tron: {
      sponsor_address: sponsorTron.address,
      note: 'TRC20 auto-sweep not implemented (energy cost). Use export-derivation-key + TronLink for manual withdrawal.',
    },
    sweep_min_usd: Number(SWEEP_MIN) / 1e6,
  });
});

// 导出某个派生索引的私钥(敏感!用于 TronLink 手动提取 TRC20 收款)
app.get('/api/admin/export-derivation-key', async (c) => {
  if (!(await requireAdmin(c))) return c.json({ error: 'unauthorized' }, 401);
  const index = parseInt(c.req.query('index') || '-1');
  const currency = (c.req.query('currency') || 'usdt_trc20').toLowerCase();
  if (!Number.isInteger(index) || index < 0) return c.json({ error: 'invalid index' }, 400);
  if (currency === 'usdt_trc20') {
    const kp = deriveTronAddressFromMnemonic(c.env.XRP_MNEMONIC, index);
    const pk = deriveTronPrivateKeyFromMnemonic(c.env.XRP_MNEMONIC, index);
    return c.json({ currency, index, address: kp.address, private_key_hex: pk });
  }
  if (currency === 'usdt_arb' || currency === 'usdc_arb') {
    const kp = deriveEvmKeypairFromMnemonic(c.env.XRP_MNEMONIC, index);
    return c.json({ currency, index, address: kp.address, private_key_hex: kp.private_key_hex });
  }
  return c.json({ error: 'unsupported currency' }, 400);
});

app.post('/api/admin/reset-hd-counters', async (c) => {
  if (!(await requireAdmin(c))) return c.json({ error: 'unauthorized' }, 401);
  try {
    await ensureCryptoSchema(c.env);
    const now = Math.floor(Date.now() / 1000);
    const before = await c.env.DB.prepare(`SELECT COUNT(*) as n FROM crypto_payments`).first<{ n: number }>();
    await c.env.DB.prepare(`DELETE FROM crypto_payments`).run();
    await c.env.DB.prepare(`DELETE FROM crypto_hd_wallet_per_currency`).run();
    await c.env.DB.prepare(
      `INSERT INTO crypto_hd_wallet_per_currency (pay_currency, next_index, updated_at) VALUES ('xrp', 0, ?), ('usdt_trc20', 0, ?)`
    ).bind(now, now).run();
    return c.json({ ok: true, deleted_payments: before?.n ?? 0, reset_at: now });
  } catch (err: any) {
    return c.json({ ok: false, error: err.message }, 500);
  }
});

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
import { deriveTronAddressFromMnemonic, deriveTronPrivateKeyFromMnemonic } from './lib/tron-hd';
import { deriveEvmAddressFromMnemonic, deriveEvmKeypairFromMnemonic } from './lib/evm-hd';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';

// 方案 2.5 — 每单派生独立地址,稳定币直收(1 USDT/USDC ≈ $1,无需汇率换算)
//   usdt_trc20 : USDT  on Tron (TRC20)     — 派生路径 m/44'/195'/0'/0/i,计数器 key 'usdt_trc20'
//   usdt_arb   : USDT  on Arbitrum One     — 派生路径 m/44'/60'/0'/0/i, 计数器 key 'evm'
//   usdc_arb   : USDC  on Arbitrum One     — 同上,与 usdt_arb 共享 'evm' 计数器(同链同地址格式)
// EVM 地址两条链通用,故 usdt_arb / usdc_arb 必须共用计数器才能保证地址按订单唯一。
const SUPPORTED_PAY_CURRENCIES = ['usdt_trc20', 'usdt_arb', 'usdc_arb'] as const;
type PayCurrency = typeof SUPPORTED_PAY_CURRENCIES[number];

// Arbitrum One 上的 ERC-20 合约(均为 6 位小数)
const ARB_TOKENS: Record<string, string> = {
  usdt_arb: '0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9', // USDT
  usdc_arb: '0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8', // USDC (bridged)
};
const ARBITRUM_RPC = 'https://arb1.arbitrum.io/rpc';
// ERC-20 Transfer(address,address,uint256) 的 topic0
const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

// ============================================================================
// 自动归集 (sweep) — 把派生地址收到的稳定币转到用户主钱包
//   EVM (Arbitrum): 全自动。gas 赞助账户 = 助记词 index 999999999(与订单地址不冲突),
//     用户一次性给赞助地址充少量 ETH(约 0.0005 ETH 够几十次),每次归集 gas ≈ $0.0001。
//   Tron: TRC20 转账需烧约 13.4 TRX 能力,自动归集成本高 — 采用
//     /api/admin/export-derivation-key 导出私钥 + TronLink 手动提取。
// ============================================================================

const SWEEP_DEST_EVM = '0x428b574Ced1a7C76415E4666d0fA6440C85C0bE4';   // 用户 Trust Wallet (Arbitrum One)
const SWEEP_SPONSOR_INDEX = 999999999;                                  // gas 赞助账户的派生索引
const SWEEP_MIN = 1_000_000n;                                           // 最低归集余额 1 USDT (6 decimals)
const SWEEP_GAS_WEI = 200_000n * 10n**7n;                               // 200k gas × 1 gwei 预算(实际远低于此)
const SWEEP_GAS_TOPUP_WEI = 10n**15n;                                   // 每次补 0.001 ETH gas
const ARB_CHAIN_ID = 42161n;

// —— RLP 编码(仅覆盖本场景:整数 / 字节串 / 嵌套列表)——
function rlpEncode(item: Uint8Array | Uint8Array[]): Uint8Array {
  if (Array.isArray(item)) {
    // 递归编码每个元素(否则长度前缀和空串全部丢失,交易非法)
    const payload = concatBytes(...item.map(x => rlpEncode(x as Uint8Array)));
    return wrapRlp(payload, 0xc0);
  }
  if (item.length === 1 && item[0] < 0x80) return item;
  return wrapRlp(item, 0x80);
}
function wrapRlp(payload: Uint8Array, offset: number): Uint8Array {
  if (payload.length <= 55) {
    const out = new Uint8Array(payload.length + 1);
    out[0] = offset + payload.length;
    out.set(payload, 1);
    return out;
  }
  const lenBytes = minimalBytes(BigInt(payload.length));
  const out = new Uint8Array(payload.length + 1 + lenBytes.length);
  out[0] = offset + 55 + lenBytes.length;
  out.set(lenBytes, 1);
  out.set(payload, 1 + lenBytes.length);
  return out;
}
function minimalBytes(n: bigint): Uint8Array {
  // EIP-155/RLP: 整数 0 必须编码为空字节串(nonce=0、value=0 时必须走空串)
  if (n === 0n) return new Uint8Array(0);
  const hex = n.toString(16).padStart(2, '0');
  const bytes = hex.length % 2 ? '0' + hex : hex;
  return Uint8Array.from(bytes.match(/.{2}/g)!.map(h => parseInt(h, 16)));
}
function intToMinimalBytes(n: bigint): Uint8Array { return minimalBytes(n); }
function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((a, b) => a + b.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}
function bytesToHex(b: Uint8Array): string { return '0x' + Array.from(b).map(x => x.toString(16).padStart(2, '0')).join(''); }
function pad32Bytes(hexNoPrefix: string): Uint8Array {
  let h = hexNoPrefix.replace(/^0x/, '');
  if (h.length % 2) h = '0' + h;
  const b = hexToBytes(h);
  const out = new Uint8Array(32);
  out.set(b, 32 - b.length);
  return out;
}

// —— EVM 交易签名(EIP-155 legacy)+ 广播 ——
async function signAndSendEvmTx(env: Env, fromIndex: number, to: string, value: bigint, data: string): Promise<string> {
  const keypair = deriveEvmKeypairFromMnemonic(env.XRP_MNEMONIC, fromIndex);
  const fromAddr = keypair.address_lowercase;

  const nonce = BigInt(await arbRpc(env, 'eth_getTransactionCount', [fromAddr, 'pending']));
  const gasPrice = BigInt(await arbRpc(env, 'eth_gasPrice', [])) * 12n / 10n + 10n**7n; // 抬 20% 避免卡单
  const gasLimit = 300_000n;
  const chainId = ARB_CHAIN_ID;

  const unsigned = rlpEncode([
    intToMinimalBytes(nonce),
    intToMinimalBytes(gasPrice),
    intToMinimalBytes(gasLimit),
    hexToBytes(to.replace(/^0x/, '')),
    intToMinimalBytes(value),
    hexToBytes(data.replace(/^0x/, '')),
    intToMinimalBytes(chainId),
    new Uint8Array(0),
    new Uint8Array(0),
  ]);
  const sighash = keccak_256(unsigned);
  // noble v2: format 'compact' → 64 字节 r||s;恢复位需要自行确定
  const sig64 = secp256k1.sign(sighash, hexToBytes(keypair.private_key_hex.replace(/^0x/, '')), { format: 'compact', prehash: false });
  const compressedPub = secp256k1.getPublicKey(hexToBytes(keypair.private_key_hex.slice(2)), true);
  let recovery = 0n;
  let found = false;
  let diag = '';
  for (const recid of [0, 1]) {
    const compact65 = new Uint8Array(65);
    compact65[0] = recid;
    compact65.set(sig64, 1);
    const pub = secp256k1.recoverPublicKey(compact65, sighash, { prehash: false });
    // 正确的地址计算:解压公钥取 X||Y,keccak 后取末 20 字节
    const xy = secp256k1.Point.fromBytes(pub).toBytes(false).slice(1, 65);
    const recAddr = '0x' + bytesToHex(keccak_256(xy)).slice(2).slice(-40);
    const verifyOk = secp256k1.verify(sig64, sighash, pub, { prehash: false });
    diag += ` recid=${recid}:addr=${recAddr}:verify=${verifyOk}`;
    if (bytesEqual(pub, compressedPub)) { recovery = BigInt(recid); found = true; }
  }
  if (!found) {
    throw new Error(`recovery failed — expected addr ${keypair.address}.${diag}`);
  }
  const v = chainId * 2n + 35n + recovery;
  const r = BigInt(bytesToHex(sig64.slice(0, 32)));
  const s = BigInt(bytesToHex(sig64.slice(32, 64)));

  const signed = rlpEncode([
    intToMinimalBytes(nonce),
    intToMinimalBytes(gasPrice),
    intToMinimalBytes(gasLimit),
    hexToBytes(to.replace(/^0x/, '')),
    intToMinimalBytes(value),
    hexToBytes(data.replace(/^0x/, '')),
    intToMinimalBytes(v),
    intToMinimalBytes(r),
    intToMinimalBytes(s),
  ]);
  const rawHex = bytesToHex(signed);
  try {
    return await arbRpc(env, 'eth_sendRawTransaction', [rawHex]);
  } catch (err: any) {
    // 广播失败时把原始交易暴露在错误里,便于本地重播诊断
    throw new Error(`${err.message} || rawTx=${rawHex}${diag} || unsigned=${bytesToHex(unsigned)} sighash=${bytesToHex(sighash)}`);
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

async function erc20BalanceOf(env: Env, token: string, holder: string): Promise<bigint> {
  const data = '0x70a08231' + bytesToHex(pad32Bytes(holder.replace(/^0x/, ''))).slice(2);
  const result: string = await arbRpc(env, 'eth_call', [{ to: token, data }, 'latest']);
  return BigInt(result);
}

async function sweepEvmOrders(env: Env): Promise<{ attempted: number; swept: number; errors: string[] }> {
  await ensureCryptoSchema(env);  // cron 不走业务端点,必须自己跑 schema 迁移
  let attempted = 0, swept = 0;
  const errors: string[] = [];
  const rows = await env.DB.prepare(
    `SELECT order_id, address, derivation_index, pay_currency, amount_usdt, swept
     FROM crypto_payments
     WHERE status IN ('finished', 'confirmed') AND swept IN (0, 1)
       AND pay_currency IN ('usdt_arb', 'usdc_arb')
     ORDER BY created_at ASC LIMIT 20`
  ).all<any>();

  for (const p of rows.results || []) {
    try {
      const token = ARB_TOKENS[p.pay_currency];
      const tokenBalance = await erc20BalanceOf(env, token, p.address);
      if (tokenBalance === 0n) {
        // 地址空(可能已手动转走)— 标记完成
        await env.DB.prepare(`UPDATE crypto_payments SET swept = 2 WHERE order_id = ?`).bind(p.order_id).run();
        continue;
      }
      if (tokenBalance < SWEEP_MIN) continue; // 低于 1 USDT 暂不归集

      const ethBalance = BigInt(await arbRpc(env, 'eth_getBalance', [p.address, 'latest']));
      const sweepValue = tokenBalance; // 全额转出

      if (ethBalance < SWEEP_GAS_WEI) {
        // 阶段 1:赞助账户给派生地址补 gas(只在 swept=0 时补一次,避免重复)
        if (p.swept === 0) {
          attempted++;
          const sponsorBal = BigInt(await arbRpc(env, 'eth_getBalance', [
            deriveEvmKeypairFromMnemonic(env.XRP_MNEMONIC, SWEEP_SPONSOR_INDEX).address_lowercase, 'latest',
          ]));
          if (sponsorBal < SWEEP_GAS_WEI + 10n**13n) {
            console.error(`[sweep] gas sponsor underfunded — send ETH (Arbitrum One) to the sponsor address`);
            continue;
          }
          await signAndSendEvmTx(env, SWEEP_SPONSOR_INDEX, p.address, SWEEP_GAS_TOPUP_WEI, '0x');
          await env.DB.prepare(`UPDATE crypto_payments SET swept = 1 WHERE order_id = ?`).bind(p.order_id).run();
          console.log(`[sweep] gas topped up for ${p.order_id}`);
        }
        continue; // 等 gas 到位,下一轮 cron 再归集
      }

      // 阶段 2:归集 — 派生地址把全部 USDT/USDC 转到目标钱包
      attempted++;
      const data = '0xa9059cbb'
        + bytesToHex(pad32Bytes(SWEEP_DEST_EVM.replace(/^0x/, ''))).slice(2)
        + bytesToHex(pad32Bytes(sweepValue.toString(16))).slice(2);
      const txHash = await signAndSendEvmTx(env, p.derivation_index ?? SWEEP_SPONSOR_INDEX, token, 0n, data);
      await env.DB.prepare(
        `UPDATE crypto_payments SET swept = 2, swept_tx = ? WHERE order_id = ?`
      ).bind(txHash, p.order_id).run();
      swept++;
      console.log(`[sweep] swept ${sweepValue} of ${p.pay_currency} from ${p.order_id} → ${SWEEP_DEST_EVM} tx=${txHash}`);
    } catch (err: any) {
      errors.push(`${p.order_id}: ${err.message}`);
      console.error(`[sweep] error for ${p.order_id}: ${err.message}`);
    }
  }
  return { attempted, swept, errors };
}

const SELF_TIER_AMOUNTS: Record<string, { usd: number; product: string; expires_sec: number }> = {
  basic: { usd: 3.99, product: 'PurpleStar AI Reading', expires_sec: 1800 },   // 30 min — 与 Stripe 价格一致
  premium: { usd: 9.99, product: 'PurpleStar Premium Full Report', expires_sec: 1800 },
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
// 第一次见到一个新币种时,从旧的全局 crypto_hd_wallet 拿当前 max(避免与历史 XRP 订单撞 address)
async function allocateNextDerivationIndex(env: Env, payCurrency: string): Promise<number> {
  // 先看这个币种是不是已经有自己的 counter
  const existing = await env.DB.prepare(
    `SELECT next_index FROM crypto_hd_wallet_per_currency WHERE pay_currency = ?`
  ).bind(payCurrency).first<{ next_index: number }>();
  if (!existing) {
    // 第一次用这个币种 — 检查旧的全局 counter(只对 XRP 适用),从那里继续
    let startIdx = 0;
    if (payCurrency === 'xrp') {
      const oldRow = await env.DB.prepare(
        `SELECT next_index FROM crypto_hd_wallet WHERE id = 1`
      ).first<{ next_index: number }>();
      startIdx = oldRow?.next_index ?? 0;
    }
    await env.DB.prepare(
      `INSERT OR IGNORE INTO crypto_hd_wallet_per_currency (pay_currency, next_index, updated_at) VALUES (?, ?, unixepoch())`
    ).bind(payCurrency, startIdx).run();
    if (startIdx > 0) {
      console.log(`[hd-index] migrated ${payCurrency} start_idx=${startIdx} from legacy crypto_hd_wallet`);
    }
  }
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
      // Cryptomus(方案 B)扩展列 — 已弃用(项目被拒审),保留列避免历史数据丢失
      `ALTER TABLE crypto_payments ADD COLUMN processor TEXT NOT NULL DEFAULT 'self_hd'`,
      `ALTER TABLE crypto_payments ADD COLUMN cryptomus_uuid TEXT`,
      `ALTER TABLE crypto_payments ADD COLUMN invoice_url TEXT`,
      // 方案 2.5 扩展列
      `ALTER TABLE crypto_payments ADD COLUMN from_block INTEGER`,      // EVM 扫描起始块
      `ALTER TABLE crypto_payments ADD COLUMN claimed_txid TEXT`,       // 用户手动申报的 TXID
      // 归集状态:0=待归集 1=gas已补 2=已归集/无需归集
      `ALTER TABLE crypto_payments ADD COLUMN swept INTEGER NOT NULL DEFAULT 0`,
      `ALTER TABLE crypto_payments ADD COLUMN swept_tx TEXT`,
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

    // 暂存 chart(可选)
    if (body.chart && body.chartId) {
      const now0 = Math.floor(Date.now() / 1000);
      await c.env.DB.prepare(
        `INSERT OR REPLACE INTO charts (id, input_json, chart_json, expires_at) VALUES (?, ?, ?, ?)`
      ).bind(body.chartId, '{}', JSON.stringify(body.chart), now0 + 86400).run();
    }

    // ===== 方案 2.5 — 每单派生独立地址,稳定币直收 =====
    //   用户钱包 → 我们的派生地址(链上),无任何第三方;资金 100% 自托管。
    //   地址按订单唯一 → 归因确定,无撞单;金额 1:1 美元,无汇率换算。
    const payCurrency = (body.pay_currency || 'usdt_trc20').toLowerCase() as PayCurrency;
    if (!(SUPPORTED_PAY_CURRENCIES as readonly string[]).includes(payCurrency)) {
      return c.json({ error: `pay_currency must be one of: ${SUPPORTED_PAY_CURRENCIES.join(', ')} (got: ${payCurrency})` }, 400);
    }
    const { usd, expires_sec } = SELF_TIER_AMOUNTS[tier];

    const orderId = crypto.randomUUID();
    // EVM 两币种(usdt_arb / usdc_arb)同链同地址格式,必须共用 'evm' 计数器才能按订单唯一
    const counterKey = payCurrency === 'usdt_trc20' ? 'usdt_trc20' : 'evm';
    const derivationIndex = await allocateNextDerivationIndex(c.env, counterKey);

    let address: string;
    let fromBlock: number | null = null;
    if (payCurrency === 'usdt_trc20') {
      address = deriveTronAddressFromMnemonic(c.env.XRP_MNEMONIC, derivationIndex).address;
    } else {
      address = deriveEvmAddressFromMnemonic(c.env.XRP_MNEMONIC, derivationIndex).address_lowercase;
      // 记录建单时区块号,watcher 只扫这之后的 Transfer 日志
      fromBlock = parseInt(await arbRpc(c.env, 'eth_blockNumber', []), 16);
    }

    const now = Math.floor(Date.now() / 1000);
    // 稳定币 1:1 美元 — 金额统一存 amount_usdt(通用 6 位小数金额列),usdt_usd_rate = 1
    await c.env.DB.prepare(
      `INSERT INTO crypto_payments
         (order_id, address, derivation_index, pay_currency, tier, chart_id,
          amount_xrp, amount_usd, xrp_usd_rate, amount_usdt, usdt_usd_rate,
          status, expires_at, created_at, processor, from_block)
       VALUES (?, ?, ?, ?, ?, ?, 0, ?, 1, ?, 1, 'waiting', ?, ?, 'self_hd', ?)`
    ).bind(
      orderId,
      address,
      derivationIndex,
      payCurrency,
      tier,
      body.chartId || null,
      usd,
      usd,
      now + expires_sec,
      now,
      fromBlock,
    ).run();

    return c.json({
      ok: true,
      order_id: orderId,
      pay_address: address,
      pay_amount: usd,
      pay_currency: payCurrency,
      amount_usd: usd,
      tier,
      expires_at: now + expires_sec,
      expires_in_sec: expires_sec,
    });
  } catch (err: any) {
    return c.json({ ok: false, error: err.message }, 500);
  }
});

// 状态查询(支持多币种 xrp | usdt_trc20 | cryptomus)
app.get('/api/crypto/payment/:orderId', async (c) => {
  const orderId = c.req.param('orderId');
  await ensureCryptoSchema(c.env);
  const row = await c.env.DB.prepare(
    `SELECT order_id, address, derivation_index, pay_currency, tier, chart_id,
            amount_xrp, amount_usd, xrp_usd_rate,
            amount_usdt, usdt_usd_rate,
            status, tx_hash, paid_at, expires_at, created_at, finished_at,
            processor, cryptomus_uuid, invoice_url, from_block, claimed_txid
     FROM crypto_payments WHERE order_id = ?`
  ).bind(orderId).first<any>();
  if (!row) return c.json({ error: 'payment not found' }, 404);
  const now = Math.floor(Date.now() / 1000);
  const expired = now > row.expires_at && row.status === 'waiting';

  // Cryptomus 订单:waiting 状态下主动向网关实时查询(webhook 丢失的兜底)
  if (
    row.processor === 'cryptomus' && row.status === 'waiting' && !expired &&
    row.cryptomus_uuid && c.env.CRYPTOMUS_MERCHANT_ID && c.env.CRYPTOMUS_PAYMENT_API_KEY
  ) {
    try {
      const live = await cryptomusRequest(c.env, 'GET', `/payment/${row.cryptomus_uuid}`);
      const mapped = mapCryptomusStatus(live.payment_status || live.status || '');
      if (mapped === 'confirmed') {
        await c.env.DB.prepare(
          `UPDATE crypto_payments SET status = 'confirmed', paid_at = ?, finished_at = ?
           WHERE order_id = ? AND status = 'waiting'`
        ).bind(now, now, orderId).run();
        row.status = 'confirmed';
        row.paid_at = now;
        row.finished_at = now;
      } else if (mapped === 'failed' || mapped === 'expired') {
        await c.env.DB.prepare(
          `UPDATE crypto_payments SET status = ? WHERE order_id = ? AND status = 'waiting'`
        ).bind(mapped, orderId).run();
        row.status = mapped;
      }
    } catch (e: any) {
      console.error(`[cryptomus] live status sync failed for ${orderId}:`, e.message);
    }
  }

  // 方案 2.5 — 派生地址订单:状态查询时顺带做一次链上扫描(cron 是 2 分钟兜底,这里秒级响应)
  if (
    row.processor === 'self_hd' && row.status === 'waiting' && !expired &&
    (SUPPORTED_PAY_CURRENCIES as readonly string[]).includes(row.pay_currency)
  ) {
    try {
      if (await scanOrderIncoming(c.env, row, now)) {
        const updated = await c.env.DB.prepare(
          `SELECT order_id, address, derivation_index, pay_currency, tier, chart_id,
                  amount_xrp, amount_usd, xrp_usd_rate, amount_usdt, usdt_usd_rate,
                  status, tx_hash, paid_at, expires_at, created_at, finished_at,
                  processor, from_block, claimed_txid
           FROM crypto_payments WHERE order_id = ?`
        ).bind(orderId).first<any>();
        if (updated) Object.assign(row, updated);
      }
    } catch (e: any) {
      console.error(`[scan] live scan failed for ${orderId}: ${e.message}`);
    }
  }

  const stillWaiting = now > row.expires_at && row.status === 'waiting';
  const payCurrency = row.pay_currency || 'xrp';
  const amountUnits = payCurrency === 'xrp' ? row.amount_xrp : row.amount_usdt;
  const fxRate = payCurrency === 'xrp' ? row.xrp_usd_rate : row.usdt_usd_rate;
  return c.json({
    ...row,
    status: stillWaiting ? 'expired' : row.status,
    pay_currency: payCurrency,
    pay_amount: amountUnits,
    fx_rate: fxRate,
  });
});

// 用户手动申报付款(TXID 兜底:链上自动核对万一漏单时的人工通道)
// 申报仅落库待人工核对,不自动解锁 — 防止伪造 TXID 白嫖报告
app.post('/api/crypto/claim', async (c) => {
  await ensureCryptoSchema(c.env);
  const body = await c.req.json().catch(() => null) as { order_id?: string; txid?: string } | null;
  if (!body?.order_id || !body?.txid) return c.json({ error: 'order_id and txid required' }, 400);
  const txid = body.txid.trim();
  if (txid.length < 10 || txid.length > 128) return c.json({ error: 'invalid txid' }, 400);
  const r = await c.env.DB.prepare(
    `UPDATE crypto_payments SET claimed_txid = ? WHERE order_id = ? AND status = 'waiting'`
  ).bind(txid, body.order_id).run();
  if (!r.meta.changes) return c.json({ error: 'order not found or not waiting' }, 404);
  return c.json({
    ok: true,
    note: 'Claim recorded. We will verify the transaction on-chain and unlock your reading shortly.',
  });
});

// Cryptomus 支付回调 — 验签:sign = md5(base64(rawBody) + PAYMENT_API_KEY)
app.post('/api/crypto/webhook/cryptomus', async (c) => {
  if (!c.env.CRYPTOMUS_PAYMENT_API_KEY) {
    return c.json({ error: 'cryptomus not configured' }, 503);
  }
  const raw = await c.req.text();
  const signHeader = c.req.header('sign') || '';
  const expected = md5(btoa(raw) + c.env.CRYPTOMUS_PAYMENT_API_KEY);
  if (signHeader !== expected) {
    return c.json({ error: 'invalid signature' }, 403);
  }

  let payload: any;
  try {
    payload = JSON.parse(raw);
  } catch {
    return c.json({ error: 'invalid JSON body' }, 400);
  }

  const orderId = payload.order_id;
  const mapped = mapCryptomusStatus(payload.status || payload.payment_status || '');
  if (!orderId || mapped === 'waiting') {
    // 中间态(check/process/confirm_check)无需落库
    return c.json({ ok: true, ignored: true });
  }

  await ensureCryptoSchema(c.env);
  const now = Math.floor(Date.now() / 1000);
  if (mapped === 'confirmed') {
    await c.env.DB.prepare(
      `UPDATE crypto_payments
       SET status = 'confirmed', paid_at = ?, finished_at = ?, cryptomus_uuid = ?
       WHERE order_id = ? AND status IN ('waiting', 'confirmed')`
    ).bind(now, now, payload.uuid || null, orderId).run();
  } else {
    // failed / expired — 不覆盖已确认订单
    await c.env.DB.prepare(
      `UPDATE crypto_payments SET status = ? WHERE order_id = ? AND status = 'waiting'`
    ).bind(mapped, orderId).run();
  }
  return c.json({ ok: true });
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

const ARBITUM_RPCS = [
  'https://arb1.arbitrum.io/rpc',
  'https://arbitrum-one.publicnode.com',
  'https://arbitrum.llamarpc.com',
  'https://1rpc.io/arb',
  'https://arbitrum.drpc.org',
  'https://arb-mainnet.public.blastapi.io',
];

// Arbitrum RPC 调用(公共节点限流较严:多端点轮换 + 每端点重试一次)
async function arbRpc(env: Env, method: string, params: any[]): Promise<any> {
  const endpoints = env.ARBITRUM_RPC_URL ? [env.ARBITRUM_RPC_URL, ...ARBITUM_RPCS] : ARBITUM_RPCS;
  let lastErr = 'unknown';
  for (const rpc of endpoints) {
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const r = await fetch(rpc, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
        });
        const j: any = await r.json().catch(() => null);
        if (j?.error) throw new Error(`rpc error: ${JSON.stringify(j.error)}`);
        if (j?.result !== undefined) return j.result;
        lastErr = `no result (${r.status})`;
      } catch (e: any) {
        lastErr = e.message;
      }
      if (attempt === 0) await new Promise(res => setTimeout(res, 400));
    }
  }
  throw new Error(`Arbitrum RPC ${method} failed on all endpoints: ${lastErr}`);
}

// EVM (Arbitrum One) 入账扫描 — eth_getLogs 查 ERC-20 Transfer 日志(to = 派生地址)
// 公共 RPC 对单次区块范围有限制,按 5000 块分片(Arbitrum 出块 ~0.25s,30 分钟 ≈ 7200 块)
async function fetchArbTransfers(env: Env, token: string, toAddress: string, fromBlock: number): Promise<any[]> {
  const paddedTopic = '0x' + '0'.repeat(24) + toAddress.replace(/^0x/, '').toLowerCase();
  const latest = parseInt(await arbRpc(env, 'eth_blockNumber', []), 16);

  const all: any[] = [];
  const CHUNK = 5000;
  for (let start = Math.max(0, fromBlock); start <= latest; start += CHUNK) {
    const end = Math.min(start + CHUNK - 1, latest);
    const logs = await arbRpc(env, 'eth_getLogs', [{ address: token, fromBlock: '0x' + start.toString(16), toBlock: '0x' + end.toString(16), topics: [TRANSFER_TOPIC, null, paddedTopic] }]);
    all.push(...(logs || []));
    if (end >= latest) break;
  }
  return all;
}

/**
 * 扫描单个订单的链上入账;收款 ≥ 应付 × 0.95 则确认订单(写库 + 记 tx_hash)。
 * 供 cron watcher(全部待付订单)和状态查询路由(单订单实时扫)共用。
 * 返回是否发生了确认。
 */
async function scanOrderIncoming(env: Env, p: any, now: number): Promise<boolean> {
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
        await env.DB.prepare(
          `UPDATE crypto_payments
           SET status = 'finished', tx_hash = ?, paid_at = ?, finished_at = ?
           WHERE order_id = ? AND status IN ('waiting', 'confirming')`
        ).bind(t.tx.hash, now, now, p.order_id).run();
        return true;
      }
    }
    return false;
  }

  if (payCurrency === 'usdt_trc20') {
    // USDT TRC20 — TronGrid /v1/accounts/{addr}/transactions/trc20
    const trc20Txs = await fetchTronTrc20Txs(p.address, 20);
    const USDT_CONTRACT = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t';
    for (const tx of trc20Txs) {
      if (tx.token_info?.address !== USDT_CONTRACT) continue;
      if (tx.to !== p.address) continue;
      if (tx.confirmations !== undefined && tx.confirmations < 1) continue;
      const raw = tx.value || tx.amount_str;
      if (!raw) continue;
      // trongrid 有时返回已除以 10^6 的数值,有时是原始 6 位小数字符串
      const received = typeof raw === 'number' ? raw : Number(raw) / 1_000_000;
      if (received >= p.amount_usdt * 0.95) {
        await env.DB.prepare(
          `UPDATE crypto_payments
           SET status = 'finished', tx_hash = ?, paid_at = ?, finished_at = ?
           WHERE order_id = ? AND status IN ('waiting', 'confirming')`
        ).bind(tx.transaction_id, now, now, p.order_id).run();
        return true;
      }
    }
    return false;
  }

  if (payCurrency === 'usdt_arb' || payCurrency === 'usdc_arb') {
    const token = ARB_TOKENS[payCurrency];
    const logs = await fetchArbTransfers(env, token, p.address, p.from_block ?? 0);
    let received = 0;
    let txHash: string | null = null;
    const paddedTopic = '0x' + '0'.repeat(24) + p.address.replace(/^0x/, '').toLowerCase();
    for (const log of logs) {
      if (!log.topics || log.topics[2]?.toLowerCase() !== paddedTopic) continue;
      received += Number(BigInt(log.data)) / 1e6;
      if (!txHash) txHash = log.transactionHash;
    }
    if (received >= p.amount_usdt * 0.95 && txHash) {
      await env.DB.prepare(
        `UPDATE crypto_payments
         SET status = 'finished', tx_hash = ?, paid_at = ?, finished_at = ?
         WHERE order_id = ? AND status IN ('waiting', 'confirming')`
      ).bind(txHash, now, now, p.order_id).run();
      return true;
    }
    return false;
  }

  return false;
}

async function watchCryptoPayments(env: Env): Promise<{ scanned: number; confirmed: number; expired: number }> {
  await ensureCryptoSchema(env);  // cron 不走业务端点,必须自己跑 schema 迁移
  const now = Math.floor(Date.now() / 1000);
  // 取所有未完成且未过期的订单(含方案 2.5 的三个币种和旧 xrp 单)
  const pending = await env.DB.prepare(
    `SELECT order_id, address, pay_currency, amount_xrp, amount_usdt, amount_usd, status, expires_at, created_at, tier, from_block
     FROM crypto_payments
     WHERE status IN ('waiting', 'confirming') AND expires_at > ?
     ORDER BY created_at ASC
     LIMIT 50`
  ).bind(now).all<any>();

  let confirmed = 0;
  for (const p of pending.results || []) {
    try {
      if (await scanOrderIncoming(env, p, now)) {
        confirmed++;
        console.log(`[watcher/${p.pay_currency}] confirmed order=${p.order_id} addr=${p.address}`);
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
  // 自动归集:确认订单的 Arbitrum 稳定币 → 用户主钱包
  ctx.waitUntil(
    sweepEvmOrders(env).then(r =>
      console.log(`[cron] sweep: attempted=${r.attempted} swept=${r.swept}`)
    ).catch(e => console.error('[cron] sweep error:', e))
  );
}

export default app;
export { handleScheduled };

