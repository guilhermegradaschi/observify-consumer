// metrics-consumer.js
const crypto = require("node:crypto");
const { PrismaClient } = require("@prisma/client");

const pg = new PrismaClient();

// ---------- tipos "lógicos" ----------
function toEnv(v) {
  if (!v) return undefined;
  const u = String(v).toUpperCase();
  if (u === "PROD" || u === "HMG" || u === "DEV") return u;
  if (u === "PRODUCTION" || u === "PRD") return "PROD";
  if (["STAGING", "HOMOLOG", "HOMOL", "HML"].includes(u)) return "HMG";
  if (["DEVELOPMENT", "DEVELOP", "DEVEL"].includes(u)) return "DEV";
  return undefined;
}

// ---------- bins / bigints / quantis ----------
const PG_INT8_MAX = 9223372036854775807n;

function clampBI(x) {
  return x > PG_INT8_MAX ? PG_INT8_MAX : x;
}

const BINS_MS = [
  0, 50, 100, 200, 300, 400, 500, 750, 1000, 1500, 2000, 3000, 5000, 8000,
  12000, 20000, 30000, 45000, 60000, 120000, 300000,
];

function padCounts(arr) {
  const out = Array(BINS_MS.length).fill(0);
  if (Array.isArray(arr)) {
    const n = Math.min(arr.length, BINS_MS.length);
    for (let i = 0; i < n; i++) out[i] = Math.max(0, Math.trunc(arr[i] || 0));
  }
  return out;
}

function qFromHistMs(hist, q) {
  const total = hist.reduce((a, b) => a + b, 0);
  if (!total) return 0;
  const target = total * q;
  let cum = 0;
  for (let i = 0; i < hist.length; i++) {
    const count = hist[i];
    if (!count) continue;
    const prevCum = cum;
    cum += count;
    if (cum >= target) {
      const binStart = i === 0 ? 0 : BINS_MS[i - 1];
      const binEnd = BINS_MS[i];
      const within = (target - prevCum) / count;
      return binStart + within * (binEnd - binStart);
    }
  }
  return BINS_MS[BINS_MS.length - 1];
}

function qFromHistUsBI(hist, q) {
  const ms = qFromHistMs(hist, q);
  const us = BigInt(Math.round(ms * 1000));
  return clampBI(us);
}

// ---------- utils ----------
function nowIso() {
  return new Date().toISOString();
}
function shortId() {
  return crypto.randomBytes(5).toString("hex");
}
function msSince(startNs) {
  return Number((process.hrtime.bigint() - startNs) / BigInt(1_000_000));
}
function sha256(s) {
  return crypto.createHash("sha256").update(s).digest("hex");
}
function hk(headers, k) {
  return headers[k] ?? headers[k.toLowerCase()] ?? headers[k.toUpperCase()];
}
function getRawBody(event) {
  const body = event && event.body;
  const isB64 = !!(event && event.isBase64Encoded);
  if (Buffer.isBuffer(body)) return body;
  if (typeof body === "string")
    return isB64 ? Buffer.from(body, "base64") : Buffer.from(body, "utf8");

  if (
    body &&
    typeof body === "object" &&
    "buffer" in body &&
    body instanceof Uint8Array
  ) {
    return Buffer.from(body);
  }

  if (
    Array.isArray(body) &&
    body.every(
      (n) => typeof n === "number" && Number.isInteger(n) && n >= 0 && n <= 255,
    )
  ) {
    return Buffer.from(body);
  }

  if (body == null) return Buffer.alloc(0);
  return Buffer.from(JSON.stringify(body), "utf8");
}
function isTrue(v) {
  const s = String(v ?? "")
    .toLowerCase()
    .trim();
  return s === "1" || s === "true" || s === "yes" || s === "y" || s === "on";
}
function recoverFromNumbersArray(arr) {
  if (!Array.isArray(arr) || !arr.every((n) => typeof n === "number"))
    return null;
  try {
    const txt = Buffer.from(arr).toString("utf8").trim();
    const j = txt ? JSON.parse(txt) : null;
    if (Array.isArray(j)) return j;
    if (Array.isArray(j && j.logs)) return j.logs;
    return null;
  } catch {
    return null;
  }
}
function recoverFromNdjson(s) {
  const lines = s
    .split("\n")
    .map((x) => x.trim())
    .filter(Boolean);
  if (!lines.length) return null;
  try {
    return lines.map((l) => JSON.parse(l));
  } catch {
    return null;
  }
}
function normalizeEnv(v) {
  return toEnv(v) || "PROD";
}
function serviceSlugWithEnv(service, env) {
  const base = service ? String(service).trim() : "";
  if (!base) return "";
  const envNorm = normalizeEnv(env);
  return `${base}::${envNorm}`;
}
function normalizeRoute(v) {
  const s = String(v ?? "").trim();
  return s || null;
}
function normalizeMethod(v) {
  const s = String(v ?? "").trim();
  if (!s) return null;
  return s.toUpperCase();
}
function safePreview(buf, max) {
  const m = max || 512;
  const txt = buf.toString("utf8");
  const slice = txt.slice(0, m);
  return slice.replace(
    /[\u0000-\u001F\u007F-\u009F]/g,
    (ch) => "\\u" + ch.charCodeAt(0).toString(16).padStart(4, "0"),
  );
}
function redactHeaders(h) {
  const hidden = new Set([
    "authorization",
    "x-api-key",
    "cookie",
    "set-cookie",
  ]);
  const out = {};
  for (const k of Object.keys(h || {})) {
    out[k] = hidden.has(k.toLowerCase()) ? "[redacted]" : h[k];
  }
  return out;
}
function looksAggMetric(o) {
  return o && typeof o === "object" && "tsBucketMs" in o && "reqCount" in o;
}

// ---------- logger ----------
function log(level, ctx, msg, extra) {
  if (level === "DEBUG" && !ctx.debug) return;
  const base = { t: nowIso(), level, reqId: ctx.reqId, msg, ...(extra || {}) };
  if (level === "ERROR") console.error(base);
  else if (level === "WARN") console.warn(base);
  else console.log(base);
}

// ---------- auth helpers ----------
function pickApiKey(event) {
  const h = (event && event.headers) || {};
  const fromHeader = hk(h, "x-api-key");
  if (fromHeader) return String(fromHeader).trim();
  const auth = hk(h, "authorization");
  if (auth && /^bearer\s+/i.test(String(auth)))
    return String(auth)
      .replace(/^bearer\s+/i, "")
      .trim();
  return null;
}

// ---------- services helper (service::ENV) ----------
async function resolveServices(orgId, metrics) {
  const slugEnv = new Map();

  for (const m of metrics) {
    const slug = serviceSlugWithEnv(m.service, m.env);
    if (!slug) continue;
    if (!slugEnv.has(slug)) slugEnv.set(slug, normalizeEnv(m.env));
  }

  const slugs = Array.from(slugEnv.keys());
  if (!slugs.length) return new Map();

  const existing = await pg.service.findMany({
    where: { orgId, slug: { in: slugs } },
    select: { id: true, slug: true },
  });
  const slugToId = new Map(existing.map((s) => [s.slug, s.id]));

  const missing = slugs.filter((s) => !slugToId.has(s));
  if (missing.length) {
    const data = missing.map((slug) => ({
      orgId,
      slug,
      name: slug,
      env: slugEnv.get(slug) || "PROD",
    }));
    await pg.service.createMany({
      data,
      skipDuplicates: true,
    });

    const all = await pg.service.findMany({
      where: { orgId, slug: { in: slugs } },
      select: { id: true, slug: true },
    });
    slugToId.clear();
    for (const s of all) slugToId.set(s.slug, s.id);
  }

  return slugToId;
}

// ---------- ingest agregado -> MetricRollup1m ----------
async function ingestAggregatedMetrics(orgId, metrics, ctx) {
  const rawAgg = metrics;

  const slugToId = await resolveServices(orgId, rawAgg);

  const accMap = new Map();

  for (const m of rawAgg) {
    const serviceSlug = serviceSlugWithEnv(m.service, m.env);
    const serviceId = serviceSlug ? slugToId.get(serviceSlug) || null : null;
    if (!serviceId) continue;

    const route = normalizeRoute(m.route);
    const method = normalizeMethod(m.method);
    if (!route || !method) continue;

    const tsNum = Number(m.tsBucketMs);
    if (!Number.isFinite(tsNum)) continue;
    const tsBucketMs = BigInt(Math.trunc(tsNum));

    const reqCount = BigInt(Math.max(0, Math.trunc(Number(m.reqCount ?? 0))));
    if (reqCount === 0n) continue;

    const errCount = BigInt(Math.max(0, Math.trunc(Number(m.errCount ?? 0))));

    const histRaw = Array.isArray(m.histCounts) ? m.histCounts : [];
    const histNorm = Array(BINS_MS.length).fill(0);
    const n = Math.min(histRaw.length, BINS_MS.length);
    for (let i = 0; i < n; i++) {
      const v = Number(histRaw[i] || 0);
      histNorm[i] = Number.isFinite(v) && v > 0 ? Math.trunc(v) : 0;
    }

    const sumDurMs = Number(m.sumDurMs ?? 0);
    const sumUs = sumDurMs > 0 ? BigInt(Math.round(sumDurMs * 1000)) : 0n;

    let sumUs2 = 0n;
    for (let i = 0; i < histNorm.length; i++) {
      const c = histNorm[i];
      if (!c) continue;
      const ms = BINS_MS[i];
      const us = BigInt(ms * 1000);
      let term = us * us * BigInt(c);
      if (term > PG_INT8_MAX) term = PG_INT8_MAX;
      const next = sumUs2 + term;
      sumUs2 = next > PG_INT8_MAX ? PG_INT8_MAX : next;
    }

    const sat = Math.max(0, Math.trunc(Number(m.satCount ?? 0)));
    const tol = Math.max(0, Math.trunc(Number(m.tolCount ?? 0)));
    const tot = Math.max(0, Math.trunc(Number(m.totCount ?? 0)));

    const key = `${tsBucketMs}:${orgId}:${serviceId}:${route}:${method}`;

    let acc = accMap.get(key);
    if (!acc) {
      acc = {
        tsBucketMs,
        orgId,
        serviceId,
        route,
        method,
        req: 0n,
        err: 0n,
        sumUs: 0n,
        sumUs2: 0n,
        hist: Array(BINS_MS.length).fill(0),
        sat: 0,
        tol: 0,
        tot: 0,
      };
      accMap.set(key, acc);
    }

    acc.req += reqCount;
    acc.err += errCount;
    acc.sumUs += sumUs;
    acc.sumUs2 += sumUs2;
    for (let i = 0; i < BINS_MS.length; i++) acc.hist[i] += histNorm[i];
    acc.sat += sat;
    acc.tol += tol;
    acc.tot += tot;
  }

  if (!accMap.size) {
    log("WARN", ctx, "agg.no_valid_rows");
    return;
  }

  const accArr = Array.from(accMap.values());

  const existing = await pg.metricRollup1m.findMany({
    where: {
      OR: accArr.map((k) => ({
        tsBucketMs: k.tsBucketMs,
        orgId: k.orgId,
        serviceId: k.serviceId,
        route: k.route,
        method: k.method,
      })),
    },
  });

  const existingMap = new Map();
  for (const r of existing) {
    const key = `${r.tsBucketMs}:${r.orgId}:${r.serviceId}:${r.route}:${r.method}`;
    existingMap.set(key, r);
  }

  let inserted = 0;
  let updated = 0;

  for (const a of accArr) {
    if (!a.req) continue;

    const key = `${a.tsBucketMs}:${a.orgId}:${a.serviceId}:${a.route}:${a.method}`;
    const cur = existingMap.get(key);

    if (!cur) {
      const p95Us = qFromHistUsBI(a.hist, 0.95);
      const p99Us = qFromHistUsBI(a.hist, 0.99);

      await pg.metricRollup1m.create({
        data: {
          tsBucketMs: a.tsBucketMs,
          orgId: a.orgId,
          serviceId: a.serviceId,
          route: a.route,
          method: a.method,
          reqCount: clampBI(a.req),
          errCount: clampBI(a.err),
          sumDurUs: clampBI(a.sumUs),
          sumDurUs2: clampBI(a.sumUs2),
          satCount: a.sat,
          tolCount: a.tol,
          totCount: a.tot,
          histCounts: { set: a.hist },
          p95Us,
          p99Us,
        },
      });
      inserted++;
    } else {
      const baseHist = padCounts(cur.histCounts);
      const hist = Array(BINS_MS.length).fill(0);
      for (let i = 0; i < BINS_MS.length; i++)
        hist[i] = baseHist[i] + a.hist[i];

      const req = clampBI(cur.reqCount + a.req);
      const err = clampBI(cur.errCount + a.err);
      const sumUs = clampBI(cur.sumDurUs + a.sumUs);
      const sumUs2 = clampBI(cur.sumDurUs2 + a.sumUs2);
      const sat = cur.satCount + a.sat;
      const tol = cur.tolCount + a.tol;
      const tot = cur.totCount + a.tot;

      const p95Us = qFromHistUsBI(hist, 0.95);
      const p99Us = qFromHistUsBI(hist, 0.99);

      await pg.metricRollup1m.update({
        where: {
          tsBucketMs_orgId_serviceId_route_method: {
            tsBucketMs: cur.tsBucketMs,
            orgId: cur.orgId,
            serviceId: cur.serviceId,
            route: cur.route,
            method: cur.method,
          },
        },
        data: {
          reqCount: req,
          errCount: err,
          sumDurUs: sumUs,
          sumDurUs2: sumUs2,
          satCount: sat,
          tolCount: tol,
          totCount: tot,
          histCounts: { set: hist },
          p95Us,
          p99Us,
        },
      });
      updated++;
    }
  }

  log("INFO", ctx, "agg.ingest.ok", {
    buckets: accMap.size,
    inserted,
    updated,
  });
}

// ---------- handler ----------
async function handler(event) {
  const headers = (event && event.headers) || {};
  const reqId =
    hk(headers, "x-request-id") || crypto.randomBytes(5).toString("hex");
  const debugHeader = hk(headers, "x-debug");
  const debug = isTrue(process.env.DEBUG_METRICS) || isTrue(debugHeader);
  const ctx = { reqId: String(reqId), debug };

  const started = process.hrtime.bigint();
  const meta = {
    method: event && event.httpMethod,
    path: event && (event.path || event.rawUrl || event.url),
    contentType: hk(headers, "content-type"),
    isBase64Encoded: !!(event && event.isBase64Encoded),
  };
  log("INFO", ctx, "ingest.start", meta);
  if (ctx.debug) {
    log("DEBUG", ctx, "ingest.eventHeaders", {
      headers: redactHeaders(headers),
    });
    const raw0 = getRawBody(event);
    log("DEBUG", ctx, "ingest.body.preview", {
      size: raw0.length,
      preview: safePreview(raw0, 512),
    });
  }

  try {
    if (!event || event.httpMethod !== "POST") {
      log("WARN", ctx, "ingest.method_not_allowed", {
        methodTried: event && event.httpMethod,
      });
      return { statusCode: 405, body: '{"message":"Method Not Allowed"}' };
    }

    const apiKey = pickApiKey(event);
    if (!apiKey) {
      log("WARN", ctx, "auth.missing_api_key");
      return { statusCode: 401, body: '{"message":"Missing API key"}' };
    }
    const apiKeyHash = sha256(apiKey);
    log("DEBUG", ctx, "auth.hash_computed", {
      apiKeyHashPrefix: apiKeyHash.slice(0, 12),
    });

    const ak = await pg.orgApiKey.findUnique({
      where: { hash: apiKeyHash },
    });
    log("DEBUG", ctx, "auth.lookup_done", {
      found: !!ak,
      active: ak && ak.active,
      expiresAt: ak && ak.expiresAt,
      revokedAt: ak && ak.revokedAt,
    });
    if (
      !ak ||
      !ak.active ||
      (ak.expiresAt && ak.expiresAt < new Date()) ||
      ak.revokedAt
    ) {
      log("WARN", ctx, "auth.invalid_key", {
        reason: !ak
          ? "not_found"
          : !ak.active
            ? "inactive"
            : ak.revokedAt
              ? "revoked"
              : "expired",
      });
      return { statusCode: 403, body: '{"message":"Invalid API key"}' };
    }
    const orgId = ak.orgId;

    const parseStart = process.hrtime.bigint();
    const raw = getRawBody(event);
    let metrics = [];

    try {
      const text = raw.toString("utf8").trim();
      if (text) {
        const j = JSON.parse(text);
        if (Array.isArray(j)) metrics = j;
        else if (Array.isArray(j && j.logs)) metrics = j.logs;
        else {
          const nd = recoverFromNdjson(text);
          if (nd) metrics = nd;
        }
      }
    } catch {
      // fallback
    }

    if (!metrics.length) {
      const b = event.body;
      if (typeof b === "string") {
        try {
          const j = JSON.parse(b);
          if (Array.isArray(j)) metrics = j;
          else if (Array.isArray(j && j.logs)) metrics = j.logs;
        } catch {
          const nd = recoverFromNdjson(String(b));
          if (nd) metrics = nd;
        }
      } else {
        const fixed = recoverFromNumbersArray(b);
        if (fixed) metrics = fixed;
      }
    }

    log("DEBUG", ctx, "parse.done", {
      tookMs: msSince(parseStart),
      items: metrics.length,
      sample: metrics.length ? [metrics[0]] : undefined,
    });
    if (!metrics.length) {
      log("WARN", ctx, "validation.no_metrics");
      return { statusCode: 422, body: '{"message":"No metrics"}' };
    }

    if (!looksAggMetric(metrics[0])) {
      log("WARN", ctx, "validation.only_agg_supported", {
        sample: [metrics[0]],
      });
      return {
        statusCode: 422,
        body: '{"message":"Payload must be AggMetricInput[]"}',
      };
    }

    const aggStart = process.hrtime.bigint();
    await ingestAggregatedMetrics(orgId, metrics, ctx);
    log("INFO", ctx, "ingest.ok_agg", {
      totalMs: msSince(started),
      aggMs: msSince(aggStart),
      items: metrics.length,
    });
    return { statusCode: 200, body: '{"message":"Metrics aggregated"}' };
  } catch (e) {
    const errId = shortId();
    log("ERROR", ctx, "ingest.fail", {
      errId,
      error: String((e && e.message) || e),
      stack:
        e && e.stack
          ? String(e.stack).split("\n").slice(0, 8).join("\n")
          : undefined,
      safeContext: {
        method: event && event.httpMethod,
        path: event && (event.path || event.rawUrl || event.url),
        headers: redactHeaders((event && event.headers) || {}),
      },
    });
    return {
      statusCode: 500,
      body: JSON.stringify({ message: "Internal error", errId }),
    };
  } finally {
    log("DEBUG", ctx, "ingest.end", { totalMs: msSince(started) });
  }
}

module.exports = { handler };
