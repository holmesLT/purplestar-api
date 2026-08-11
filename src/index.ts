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
// Stripe Payment Link (sandbox-friendly: Checkout Session API blocked on new accounts)
// ====================================================================
// 策略：用 paymentLinks.create 创建链接，after_completion 用 redirect 到 success_url
// Payment Link 支付完成后 Stripe 会创建一个对应的 Checkout Session，sessionId 在
// `checkout.session.completed` webhook 里能拿到 — 我们用 plink_<uuid> 占位 id，
// webhook 到达时把 order id 更新成真实 cs_test_xxx，/api/interpret 按 sessionId 查就行。
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

  const stripe = new Stripe(c.env.STRIPE_SECRET_KEY, { apiVersion: '2025-09-30.clover' });

  const lineItem = {
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
  } as const;

  const successUrl = `${c.env.SITE_URL}/report/?chartId=${chartId}&tier=${tier}&session_id={CHECKOUT_SESSION_ID}`;

  const paymentLink = await stripe.paymentLinks.create({
    line_items: [lineItem],
    metadata: { chartId, tier, _placeholder: '1' },
    after_completion: {
      type: 'redirect',
      redirect: { url: successUrl },
    },
    allow_promotion_codes: false,
  });

  // Placeholder id — webhook 会更新成真实 cs_test_xxx
  const placeholderId = `plink_${crypto.randomUUID()}`;
  await c.env.DB.prepare(
    `INSERT OR REPLACE INTO orders (id, chart_id, tier, amount, status) VALUES (?, ?, ?, ?, 'pending')`
  ).bind(placeholderId, chartId, tier, prices[tier]).run();

  return c.json({ url: paymentLink.url, sessionId: placeholderId });
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

  const { chartId, chart: clientChart, tier, sessionId } = await c.req.json() as {
    chartId?: string;
    chart?: any;
    tier: 'basic' | 'premium';
    sessionId: string;
  };

  if (!sessionId) return c.json({ error: 'Missing sessionId.' }, 400);

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

  // 优先用前端传的 chart，否则从 D1 拉（Payment Link 流程下前端没 hash）
  let chart = clientChart;
  if (!chart) {
    const lookupId = chartId || order.chart_id;
    if (!lookupId) return c.json({ error: 'Missing chart. Provide chartId or chart.' }, 400);

    const row = await c.env.DB.prepare(
      `SELECT chart_json FROM charts WHERE id = ? AND (expires_at IS NULL OR expires_at > ?)`
    ).bind(lookupId, Math.floor(Date.now() / 1000)).first<{ chart_json: string }>();

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

app.post('/api/webhook/debug', async (c) => {
  // DEBUG ONLY: 接受任意 JSON，模拟 webhook 事件
  // 用 STRIPE_SECRET_KEY 作为 token 防止滥用
  const auth = c.req.header('authorization');
  if (auth !== `Bearer ${c.env.STRIPE_SECRET_KEY}`) {
    return c.json({ error: 'unauthorized' }, 401);
  }
  const body = await c.req.json() as { type: string; data: { object: any } };
  console.log(`[webhook-debug] type: ${body.type}`);
  if (body.type === 'checkout.session.completed') {
    const session = body.data.object;
    const realSessionId = session.id;
    const customerEmail = session.customer_details?.email || null;
    const metadata = session.metadata || {};
    const chartId = metadata.chartId as string | undefined;

    const direct = await c.env.DB.prepare(
      `UPDATE orders SET status = 'paid', paid_at = unixepoch(), customer_email = ? WHERE id = ?`
    ).bind(customerEmail, realSessionId).run();
    console.log(`[webhook-debug] direct update: ${JSON.stringify(direct)}`);

    if (chartId) {
      const placeholder = await c.env.DB.prepare(
        `SELECT id FROM orders WHERE chart_id = ? AND status = 'pending' AND id LIKE 'plink_%' LIMIT 1`
      ).bind(chartId).first<{ id: string }>();
      if (placeholder) {
        await c.env.DB.prepare(`DELETE FROM orders WHERE id = ?`).bind(placeholder.id).run();
        await c.env.DB.prepare(
          `INSERT INTO orders (id, chart_id, tier, amount, status, paid_at, customer_email) VALUES (?, ?, ?, ?, 'paid', unixepoch(), ?)`
        ).bind(realSessionId, chartId, metadata.tier || 'basic', session.amount_total || 999, customerEmail).run();
        console.log(`[webhook-debug] replaced ${placeholder.id} -> ${realSessionId}`);
      }
    }
    return c.json({ debug: true, realSessionId, placeholderFound: !!chartId });
  }
  return c.json({ debug: true, type: body.type, handled: false });
});

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
  }, {});
  const timestamp = parts.t;
  const v1 = parts.v1;

  if (!timestamp || !v1) {
    return c.json({ error: 'Invalid signature header' }, 400);
  }

  // Reject signatures older than 5 minutes (replay protection)
  const age = Math.abs(Date.now() / 1000 - Number(timestamp));
  if (age > 300) {
    return c.json({ error: 'Timestamp too old' }, 400);
  }

  const signedPayload = `${timestamp}.${body}`;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(c.env.STRIPE_WEBHOOK_SECRET),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );
  const expectedSig = await crypto.subtle.verify(
    'HMAC',
    key,
    hexToBytes(v1),
    new TextEncoder().encode(signedPayload)
  );

  if (!expectedSig) {
    return c.json({ error: 'Invalid signature' }, 400);
  }

  const event = JSON.parse(body) as Stripe.Event;
  console.log(`[webhook] verified: type=${event.type}, id=${event.id}`);

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object as Stripe.Checkout.Session;
    const realSessionId = session.id;
    const customerEmail = session.customer_details?.email || null;
    const metadata = session.metadata || {};
    const chartId = metadata.chartId as string | undefined;

    // 1. 直接按真实 sessionId 更新（如果有的话）
    const direct = await c.env.DB.prepare(
      `UPDATE orders SET status = 'paid', paid_at = unixepoch(), customer_email = ? WHERE id = ?`
    ).bind(customerEmail, realSessionId).run();
    console.log(`[webhook] direct update on ${realSessionId}: meta=${direct.metaChanges}`);

    // 2. 如果是通过 Payment Link 进入的，按 chartId 找到 placeholder order 并替换 id
    if (chartId) {
      const placeholder = await c.env.DB.prepare(
        `SELECT id FROM orders WHERE chart_id = ? AND status = 'pending' AND id LIKE 'plink_%' LIMIT 1`
      ).bind(chartId).first<{ id: string }>();

      if (placeholder) {
        // 把 placeholder 行的 id 改成真实 sessionId，并标记 paid
        await c.env.DB.prepare(
          `DELETE FROM orders WHERE id = ?`
        ).bind(placeholder.id).run();
        await c.env.DB.prepare(
          `INSERT INTO orders (id, chart_id, tier, amount, status, paid_at, customer_email) VALUES (?, ?, ?, ?, 'paid', unixepoch(), ?)`
        ).bind(realSessionId, chartId, metadata.tier || 'basic', session.amount_total || 999, customerEmail).run();
        console.log(`[webhook] replaced placeholder ${placeholder.id} -> ${realSessionId} for chart ${chartId}`);
      } else {
        console.log(`[webhook] no placeholder found for chart ${chartId}`);
      }
    }
  }

  return c.json({ received: true });
});

// ====================================================================
// Helpers
// ====================================================================

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

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
