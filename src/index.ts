/**
 * Cloudflare Workers 主入口 — PurpleStar API
 *
 * 架构：
 *   - 排盘：客户端用 iztro 库直接生成（无服务端计算）
 *   - 缓存：客户端把 chart 传到 /api/chart/save 存到 D1（仅用于付费时给后端用）
 *   - AI 解读：客户端发 chart + sessionId → Worker 调 Claude
 *   - 支付：Worker 创建 Stripe Checkout Session
 *
 * 路由：
 *   POST /api/chart/save    暂存 chart 到 D1（client 提供数据）
 *   GET  /api/chart/:id     查询暂存的 chart
 *   POST /api/checkout      创建 Stripe Checkout
 *   POST /api/interpret     生成 AI 解读（验证订单）
 *   POST /api/webhook/stripe  Stripe 支付回调
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

// CORS
app.use('*', cors({
  origin: (origin, c) => {
    const allowed = c.env.ALLOWED_ORIGIN;
    if (origin === allowed) return origin;
    if (origin?.startsWith('http://localhost')) return origin;
    return allowed;
  },
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  allowHeaders: ['Content-Type'],
  maxAge: 86400,
}));

app.get('/health', (c) => c.json({ status: 'ok', service: 'purplestar-api', timestamp: Date.now() }));

// ====================================================================
// 图表暂存（用于付费场景：Stripe webhook 后能找到 chart）
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
  const counter = await c.env.DB.prepare(
    `SELECT count FROM rate_limits WHERE key = ?`
  ).bind(key).first<{ count: number }>();

  const count = counter?.count ?? 0;
  if (count >= limit) return false;

  await c.env.DB.prepare(
    `INSERT INTO rate_limits (key, count, expires_at) VALUES (?, ?, ?)
     ON CONFLICT(key) DO UPDATE SET count = count + 1`
  ).bind(key, count + 1, now + 120).run();

  return true;
}

// ====================================================================
// Stripe Checkout
// ====================================================================

app.post('/api/checkout', async (c) => {
  const ip = c.req.header('cf-connecting-ip') || 'unknown';
  if (!await checkRate(c, ip, 10)) {
    return c.json({ error: 'Too many requests.' }, 429);
  }

  const { chartId, tier } = await c.req.json() as { chartId: string; tier: 'basic' | 'premium' };

  const prices: Record<string, number> = { basic: 999, premium: 2999 };
  if (!prices[tier]) return c.json({ error: 'Invalid tier.' }, 400);

  const chart = await c.env.DB.prepare(`SELECT id FROM charts WHERE id = ?`).bind(chartId).first();
  if (!chart) return c.json({ error: 'Chart not found. Please regenerate.' }, 404);

  const stripe = new Stripe(c.env.STRIPE_SECRET_KEY, { apiVersion: '2024-06-20' });
  const session = await stripe.checkout.sessions.create({
    mode: 'payment',
    payment_method_types: ['card'],
    line_items: [{
      price_data: {
        currency: 'usd',
        product_data: {
          name: tier === 'premium' ? 'PurpleStar Premium Full Report' : 'PurpleStar AI Reading',
          description: tier === 'premium'
            ? 'Comprehensive 3,000-5,000 word Ziwei Doushu reading covering 13 life themes.'
            : 'Concise 500-800 word Ziwei Doushu reading covering 5 essential themes.',
        },
        unit_amount: prices[tier],
      },
      quantity: 1,
    }],
    metadata: { chartId, tier },
    success_url: `${c.env.SITE_URL}/report/?chartId=${chartId}&tier=${tier}&session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${c.env.SITE_URL}/`,
  });

  await c.env.DB.prepare(
    `INSERT OR REPLACE INTO orders (id, chart_id, tier, amount, status) VALUES (?, ?, ?, ?, 'pending')`
  ).bind(session.id, chartId, tier, prices[tier]).run();

  return c.json({ url: session.url, sessionId: session.id });
});

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

  const { chart, tier, sessionId } = await c.req.json() as {
    chart: any; tier: 'basic' | 'premium'; sessionId: string;
  };

  if (!sessionId || !chart) return c.json({ error: 'Missing fields.' }, 400);

  // 验证订单已支付
  const order = await c.env.DB.prepare(
    `SELECT status, tier, chart_id FROM orders WHERE id = ?`
  ).bind(sessionId).first<{ status: string; tier: string; chart_id: string }>();

  if (!order || order.status !== 'paid') {
    return c.json({ error: 'Payment not verified.', status: order?.status }, 403);
  }

  if (order.tier !== tier) {
    return c.json({ error: `Order is for tier ${order.tier}, not ${tier}.` }, 403);
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
    ? `Generate a COMPREHENSIVE Ziwei Doushu reading (3,000-5,000 words) for:\n\n${context}\n\nCover 13 themes in order:\n1. Life Overview\n2. Personality & Temperament\n3. Career & Wealth Path\n4. Relationships & Marriage\n5. Family & Social Bonds\n6. Health & Vitality\n7. Travel & External Relations\n8. Mental State & Spirituality\n9. Major Luck Periods (next 10-year cycles)\n10. Annual Fortune ${new Date().getFullYear()}\n11. Auspicious Patterns\n12. Challenges & Remedies\n13. Practical Wisdom`
    : `Generate a CONCISE Ziwei Doushu reading (500-800 words) for:\n\n${context}\n\nCover 5 themes:\n1. Cosmic Identity\n2. Career & Money\n3. Relationships\n4. Life Cycles\n5. One Key Insight\n\nEnd with brief encouragement.`;

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
    order.chart_id,
    sessionId,
    tier,
    text,
    (message.usage as any)?.output_tokens ?? 0
  ).run();

  return c.json({ reading: text, tier, tokensUsed: message.usage });
});

// ====================================================================
// Stripe Webhook
// ====================================================================

app.post('/api/webhook/stripe', async (c) => {
  const stripe = new Stripe(c.env.STRIPE_SECRET_KEY, { apiVersion: '2024-06-20' });
  const sig = c.req.header('stripe-signature');
  const body = await c.req.text();

  if (!sig) return c.json({ error: 'No signature' }, 400);

  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(body, sig, c.env.STRIPE_WEBHOOK_SECRET);
  } catch (err: any) {
    return c.json({ error: err.message }, 400);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object as Stripe.Checkout.Session;
    await c.env.DB.prepare(
      `UPDATE orders SET status = 'paid', paid_at = unixepoch(), customer_email = ? WHERE id = ?`
    ).bind(session.customer_details?.email || null, session.id).run();
    console.log(`Payment received: ${session.id}`);
  }

  return c.json({ received: true });
});

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
