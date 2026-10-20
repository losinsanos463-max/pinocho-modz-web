import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));
const port = Number(process.env.PORT || 3000);
const isProd = process.env.NODE_ENV === 'production';
const apiSecret = process.env.API_SECRET || (isProd ? '' : 'dev-secret-change-me');
if (isProd && apiSecret.length < 32) throw new Error('API_SECRET debe tener al menos 32 caracteres en producción');
const dataFile = process.env.DATA_FILE || path.join(root, 'web', 'data.json');
const tokens = new Map();
const keyPattern = /^PINOCHO-[A-Za-z0-9]{3}$/;
const defaultData = {
  config: {
    tutorialUrl: process.env.PUBLIC_TUTORIAL_URL || 'https://example.com/tutorial',
    shortenerUrl: process.env.PUBLIC_SHORTENER_URL || 'https://example.com/shortener',
    maintenance: false
  },
  keys: []
};

async function readData() {
  try { return JSON.parse(await fs.readFile(dataFile, 'utf8')); }
  catch { await fs.mkdir(path.dirname(dataFile), { recursive: true }); await writeData(defaultData); return structuredClone(defaultData); }
}
async function writeData(data) {
  await fs.mkdir(path.dirname(dataFile), { recursive: true });
  await fs.writeFile(dataFile, JSON.stringify(data, null, 2));
}
function json(res, status, payload) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'access-control-allow-origin': '*' });
  res.end(JSON.stringify(payload));
}
function html(res, body, status = 200) { res.writeHead(status, { 'content-type': 'text/html; charset=utf-8' }); res.end(body); }
async function body(req) {
  let raw = ''; for await (const chunk of req) raw += chunk;
  try { return raw ? JSON.parse(raw) : {}; } catch { return null; }
}
function authorized(req) { return req.headers['x-api-key'] === apiSecret; }
function cleanExpired(data) { const now = Date.now(); data.keys.forEach(k => { if (k.status !== 'revoked' && k.expiresAt <= now) k.status = 'expired'; }); }
function remaining(expiresAt) { return Math.max(0, expiresAt - Date.now()); }
function randomKey() { const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; let suffix = ''; for (let i = 0; i < 3; i++) suffix += chars[crypto.randomInt(chars.length)]; return `PINOCHO-${suffix}`; }
function publicConfig(data) { return { tutorialUrl: data.config.tutorialUrl, shortenerUrl: data.config.shortenerUrl, maintenance: Boolean(data.config.maintenance) }; }
function landing() { return fs.readFile(path.join(root, 'public', 'index.html'), 'utf8'); }
async function verifyTurnstile(token, remoteIp) {
  if (!process.env.TURNSTILE_SECRET || !token) return false;
  const form = new URLSearchParams({ secret: process.env.TURNSTILE_SECRET, response: token });
  if (remoteIp) form.set('remoteip', remoteIp);
  try {
    const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: form, signal: AbortSignal.timeout(5000) });
    const result = await response.json();
    return response.ok && result.success === true;
  } catch { return false; }
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const data = await readData(); cleanExpired(data); await writeData(data);
  if (req.method === 'OPTIONS') { res.writeHead(204, { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'content-type,x-api-key', 'access-control-allow-methods': 'GET,POST,OPTIONS' }); return res.end(); }
  if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/claim')) return html(res, await landing());
  if (req.method === 'GET' && url.pathname === '/health') return json(res, 200, { ok: true, service: 'pinocho-modz-web' });
  if (req.method === 'GET' && url.pathname === '/api/get_config') return json(res, 200, publicConfig(data));
  if (req.method === 'POST' && url.pathname === '/api/start') {
    if (data.config.maintenance) return json(res, 503, { maintenance: true, message: 'Servicio temporalmente en mantenimiento' });
    const token = crypto.randomBytes(24).toString('base64url'); tokens.set(token, { expiresAt: Date.now() + 5 * 60_000, used: false });
    return json(res, 200, { token, expiresInSeconds: 300, shortenerUrl: data.config.shortenerUrl, returnUrl: `/claim?token=${encodeURIComponent(token)}` });
  }
  if (req.method === 'POST' && url.pathname === '/api/claim') {
    const input = await body(req); const record = input && tokens.get(input.token);
    if (!record || record.used || record.expiresAt <= Date.now()) return json(res, 401, { valid: false, message: 'Token inválido, usado o expirado' });
    if (process.env.TURNSTILE_ENABLED === 'true') {
      if (!process.env.TURNSTILE_SECRET) return json(res, 503, { valid: false, message: 'Anti-bot no configurado en el servidor' });
      if (!(await verifyTurnstile(input.captchaToken, req.headers['x-forwarded-for']?.split(',')[0]?.trim()))) return json(res, 403, { valid: false, message: 'Verificación anti-bot no válida' });
    }
    const key = data.keys.find(k => k.status === 'available' && k.expiresAt > Date.now());
    if (!key) return json(res, 409, { valid: false, message: 'No hay licencias disponibles' });
    record.used = true; key.status = 'claimed'; key.claimedAt = new Date().toISOString(); await writeData(data);
    return json(res, 200, { valid: true, key: key.key, validUntil: new Date(key.expiresAt).toISOString(), remainingMs: remaining(key.expiresAt) });
  }
  if (req.method === 'POST' && url.pathname === '/api/sync_keys') {
    if (!authorized(req)) return json(res, 401, { ok: false, message: 'API key inválida' });
    const input = await body(req); if (!input || !Array.isArray(input.keys)) return json(res, 400, { ok: false, message: 'Se esperaba {keys: [...], config?: {...}}' });
    if (input.config && typeof input.config === 'object') {
      if (typeof input.config.tutorialUrl === 'string' && input.config.tutorialUrl.trim()) data.config.tutorialUrl = input.config.tutorialUrl.trim();
      if (typeof input.config.shortenerUrl === 'string' && input.config.shortenerUrl.trim()) data.config.shortenerUrl = input.config.shortenerUrl.trim();
      if (typeof input.config.maintenance === 'boolean') data.config.maintenance = input.config.maintenance;
    }
    let inserted = 0; for (const item of input.keys) { if (!item || !keyPattern.test(item.key)) continue; if (data.keys.some(k => k.key === item.key)) continue; const expiresAt = Number(item.expiresAt); if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) continue; data.keys.push({ key: item.key, createdAt: item.createdAt || new Date().toISOString(), expiresAt, status: 'available' }); inserted++; }
    await writeData(data); return json(res, 200, { ok: true, inserted, total: data.keys.length });
  }
  if (req.method === 'POST' && url.pathname === '/api/validate_key') {
    const input = await body(req); if (!input || typeof input.key !== 'string' || typeof input.device_id !== 'string') return json(res, 400, { status: 400, valid: false, message: 'key y device_id son obligatorios' });
    if (data.config.maintenance) return json(res, 503, { status: 503, maintenance: true, message: 'Aplicación en mantenimiento' });
    const key = data.keys.find(k => k.key === input.key); if (!key || key.status === 'revoked' || key.expiresAt <= Date.now()) return json(res, 401, { status: 401, valid: false, message: 'Key inválida o expirada' });
    if (!key.deviceId) { key.deviceId = crypto.createHash('sha256').update(input.device_id).digest('hex').slice(0, 32); key.status = 'in_use'; await writeData(data); }
    if (key.deviceId !== crypto.createHash('sha256').update(input.device_id).digest('hex').slice(0, 32)) return json(res, 409, { status: 409, valid: false, message: 'La key está vinculada a otro dispositivo' });
    return json(res, 200, { status: 200, valid: true, remaining_time: `${Math.ceil(remaining(key.expiresAt) / 3_600_000)}h`, remainingMs: remaining(key.expiresAt), maintenance: false });
  }
  if (req.method === 'GET' && url.pathname === '/manus-routes.json') { try { const file = await fs.readFile(path.join(root, 'public', 'manus-routes.json')); res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-cache' }); return res.end(file); } catch {} }
  if (req.method === 'GET' && url.pathname.startsWith('/public/')) { try { const file = await fs.readFile(path.join(root, url.pathname)); const types = { '.css': 'text/css; charset=utf-8', '.js': 'application/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8' }; res.writeHead(200, { 'content-type': types[path.extname(url.pathname)] || 'application/octet-stream' }); return res.end(file); } catch {} }
  return json(res, 404, { message: 'Ruta no encontrada' });
});
server.listen(port, '0.0.0.0', () => console.log(`PINOCHO MODZ web listening on 0.0.0.0:${port}`));
