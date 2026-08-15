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
 * 路由：
 *   POST /api/chart/save     暂存 chart 到 D1
 *   GET  /api/chart/:id      查询暂存的 chart
 *   POST /api/interpret      生成 AI 解读（Stripe API 校验订单已支付）
 *   POST /api/webhook/stripe Stripe 支付回调（记录日志，写 payments 表留痕）
 *   GET  /health
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import Anthropic from '@anthropic-ai/sdk';
import Stripe from 'stripe';

export interface Env {
  // Secrets
  ANTHROPIC_API_KEY: string;
  STRIPE_SECRET_KEY: string;
  STRIPE_WEBHOOK_SECRET: string;

  // Vars
  SITE_URL: string;
  ALLOWED_ORIGIN: string;

  // D1
  DB: D1Database;
}

const app = new Hono<{ Bindings: Env }>();

// CORS — 同时允许新老域名(过渡期 techhouse.ccwu.cc 还可能在老用户访问)
// 永久接受 primary domain(purplestar.cc)和老域名(techhouse.ccwu.cc)
app.use('*', cors({
  origin: (origin, c) => {
    // 允许的 origin 列表(写死比读 env 更安全)
    const allowed = new Set([
      c.env.ALLOWED_ORIGIN,                                  // 主域名
      'https://purplestar.techhouse.ccwu.cc',                // 老域名(过渡)
      'https://techhouse.ccwu.cc',                           // 老根域(意外)
    ]);
    if (origin && allowed.has(origin)) return origin;
    if (origin?.startsWith('http://localhost')) return origin; // dev
    // 不在白名单:echo 主域名(stripe / 监控脚本无 origin 时 fallback)
    return c.env.ALLOWED_ORIGIN;
  },
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Stripe-Signature'],
  maxAge: 86400,
}));

app.get('/health', (c) => c.json({ status: 'ok', service: 'purplestar-api', timestamp: Date.now() }));

// ====================================================================
// 图表暂存（用于付费场景：Stripe 校验通过后能从 D1 读到 chart）
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
// AI 解读 — Stripe API 实时校验 session 已支付
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

  const { chartId, chart: clientChart, tier, sessionId } = await c.req.json() as {
    chartId?: string;
    chart?: any;
    tier: 'basic' | 'premium';
    sessionId: string;
  };

  if (!sessionId) return c.json({ error: 'Missing sessionId.' }, 400);
  if (!sessionId.startsWith('cs_')) {
    return c.json({ error: 'Invalid sessionId format.' }, 400);
  }

  // 用 Stripe API 实时校验 session 已支付
  // apiVersion 必须是 SDK 支持的版本(SDK 17 → '2025-02-24.acacia')。
  // 老代码写 '2025-09-30.clover' 已不在 SDK 17 白名单。
  const stripe = new Stripe(c.env.STRIPE_SECRET_KEY, { apiVersion: '2025-02-24.acacia' });
  let session: any; // Stripe SDK 17 移除了 Checkout.Session generic,用 any 兼容
  try {
    session = await stripe.checkout.sessions.retrieve(sessionId);
  } catch (err: any) {
    return c.json({ error: `Stripe lookup failed: ${err.message}` }, 400);
  }

  if (session.payment_status !== 'paid') {
    return c.json({ error: 'Payment not verified.', status: session.payment_status }, 403);
  }

  // 校验 tier 金额匹配（防止用户用 basic session 拿 premium 报告）
  const expectedAmount = tier === 'premium' ? 2999 : 999;
  if (session.amount_total !== expectedAmount) {
    return c.json({ error: `Session amount ${session.amount_total} does not match tier ${tier} (${expectedAmount}).` }, 403);
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
  ).bind(sessionId).first<{ content: string }>();
  if (cached) {
    return c.json({ reading: cached.content, cached: true });
  }

  // 调 Claude
  const anthropic = new Anthropic({ apiKey: c.env.ANTHROPIC_API_KEY });
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

  const message = await anthropic.messages.create({
    model: 'claude-sonnet-4-5',
    max_tokens: tier === 'premium' ? 8000 : 2000,
    system: SYSTEM_PROMPT,
    messages: [{ role: 'user', content: userPrompt }],
  });

  const text = message.content[0].type === 'text' ? message.content[0].text : '';

  await c.env.DB.prepare(
    `INSERT INTO readings (id, chart_id, order_id, tier, content, tokens_used) VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(
    crypto.randomUUID(),
    chartId || 'unknown',
    sessionId,
    tier,
    text,
    (message.usage as any)?.output_tokens ?? 0
  ).run();

  return c.json({ reading: text, tier, tokensUsed: message.usage });
});

// ====================================================================
// Stripe Webhook — 自实现 HMAC 验签 + 留痕
// ====================================================================

app.post('/api/webhook/stripe', async (c) => {
  const sig = c.req.header('stripe-signature');
  const body = await c.req.text();

  if (!sig) return c.json({ error: 'No signature' }, 400);

  // 自实现 Stripe webhook 签名验证（避免 Stripe SDK 18+ 在 Workers 上的 SubtleCryptoProvider 同步问题）
  // 格式: t=<timestamp>,v1=<hmac_sha256(timestamp.body, secret)>
  const parts = sig.split(',').reduce((acc: any, p) => {
    const [k, v] = p.split('=');
    acc[k] = v;
    return acc;
  }, {} as Record<string, string>);
  const timestamp = parts.t;
  const v1 = parts.v1;
  if (!timestamp || !v1) return c.json({ error: 'Invalid signature header' }, 400);

  // 防重放
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
    // 留痕：写入 payments 表便于对账
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

export default app;
