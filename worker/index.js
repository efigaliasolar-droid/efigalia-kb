// Cloudflare Worker para Efigalia
// Fase A: auth con token HMAC-SHA256 (JWT estándar) + redacción de PINs.
// Endpoints públicos: GET /foto/:key, POST /auth/login.
// Resto: requieren Authorization: Bearer <token>.
// POST /data: además requiere rol admin (puede sobrescribir usuarios y PINs).

const ALLOWED_ORIGINS = new Set([
  'https://efigaliasolar-droid.github.io'
]);

const SESSION_TTL_SECONDS = 24 * 60 * 60; // 24h

// ── CORS ──────────────────────────────────────────────────
function corsHeaders(request) {
  const origin = request.headers.get('Origin') || '';
  const allow = ALLOWED_ORIGINS.has(origin) ? origin : '';
  return {
    'Access-Control-Allow-Origin': allow,
    'Vary': 'Origin',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  };
}

function json(body, status, cors) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, 'Content-Type': 'application/json' },
  });
}

// ── Base64URL helpers ────────────────────────────────────
const enc = new TextEncoder();
const dec = new TextDecoder();
function b64uFromBytes(bytes) {
  let s = btoa(String.fromCharCode(...bytes));
  return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64uFromString(str) {
  return b64uFromBytes(enc.encode(str));
}
function b64uToBytes(b64u) {
  const b64 = b64u.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((b64u.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ── JWT HS256 ────────────────────────────────────────────
async function hmacKey(secret) {
  return crypto.subtle.importKey(
    'raw', enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign', 'verify']
  );
}
async function signJWT(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const h = b64uFromString(JSON.stringify(header));
  const p = b64uFromString(JSON.stringify(payload));
  const data = h + '.' + p;
  const key = await hmacKey(secret);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(data)));
  return data + '.' + b64uFromBytes(sig);
}
async function verifyJWT(token, secret) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  const data = h + '.' + p;
  const key = await hmacKey(secret);
  let ok = false;
  try { ok = await crypto.subtle.verify('HMAC', key, b64uToBytes(s), enc.encode(data)); }
  catch { return null; }
  if (!ok) return null;
  let payload;
  try { payload = JSON.parse(dec.decode(b64uToBytes(p))); }
  catch { return null; }
  if (!payload.exp || Math.floor(Date.now() / 1000) > payload.exp) return null;
  return payload;
}

// ── SHA-256 hex (compat con cliente legado) ──────────────
async function sha256Hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', enc.encode(str));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Auth helpers ─────────────────────────────────────────
async function getAuth(request, env) {
  const h = request.headers.get('Authorization') || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  return verifyJWT(m[1], env.JWT_SECRET);
}
function isAdminRole(rol) {
  return rol === 'admin' || rol === 'ambos';
}

// ── Datos en R2 ──────────────────────────────────────────
async function loadData(env) {
  const obj = await env.FOTOS.get('kb/data.json');
  if (!obj) return [];
  try { return JSON.parse(await obj.text()); } catch { return []; }
}

// Devuelve el array sin los campos pin/pinHash de los instaladores.
function redactPins(arr) {
  if (!Array.isArray(arr)) return arr;
  return arr.map(it => {
    if (it && it.tipo === 'instalador' && (it.pin !== undefined || it.pinHash !== undefined)) {
      const { pin, pinHash, ...rest } = it;
      return rest;
    }
    return it;
  });
}

// ── Handler principal ────────────────────────────────────
export default {
  async fetch(request, env) {
    const cors = corsHeaders(request);

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: cors });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    // — PÚBLICO: servir fotos por key —
    if (path.startsWith('/foto/') && request.method === 'GET') {
      const key = path.slice(6);
      const obj = await env.FOTOS.get(key);
      if (!obj) return new Response('Not found', { status: 404, headers: cors });
      return new Response(obj.body, {
        headers: { ...cors, 'Content-Type': obj.httpMetadata?.contentType || 'image/jpeg' },
      });
    }

    // — PÚBLICO: listado mínimo de nombres para el dropdown de login —
    // Solo nombres de instaladores activos. Sin PINs, sin roles, sin metadata.
    if (path === '/auth/users' && request.method === 'GET') {
      const data = await loadData(env);
      const nombres = data
        .filter(i => i && i.tipo === 'instalador' && i.activa !== false && typeof i.nombre === 'string')
        .map(i => ({ nombre: i.nombre }))
        .sort((a, b) => a.nombre.localeCompare(b.nombre));
      return json(nombres, 200, cors);
    }

    // — PÚBLICO: login —
    if (path === '/auth/login' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return json({ error: 'bad json' }, 400, cors); }
      const nombre = (body && typeof body.nombre === 'string') ? body.nombre.trim() : '';
      const pin    = (body && typeof body.pin === 'string')    ? body.pin.trim()    : '';
      if (!nombre || !pin) return json({ error: 'Falta nombre o PIN' }, 400, cors);

      const data = await loadData(env);
      const user = data.find(i => i && i.tipo === 'instalador' && i.nombre === nombre && i.activa !== false);

      // Delay ~150 ms para que la respuesta tarde igual aunque el usuario no exista (timing).
      await new Promise(r => setTimeout(r, 150));

      if (!user) return json({ error: 'Usuario o PIN incorrecto' }, 401, cors);

      let ok = false;
      if (typeof user.pin === 'string' && user.pin.length > 0) {
        ok = (user.pin === pin);
      } else if (typeof user.pinHash === 'string' && user.pinHash.length > 0) {
        ok = (user.pinHash === await sha256Hex(pin));
      }
      if (!ok) return json({ error: 'Usuario o PIN incorrecto' }, 401, cors);

      const now = Math.floor(Date.now() / 1000);
      const payload = {
        sub: user.nombre,
        rol: user.rol || 'instalador',
        iat: now,
        exp: now + SESSION_TTL_SECONDS,
      };
      const token = await signJWT(payload, env.JWT_SECRET);
      return json({ token, user: { nombre: user.nombre, rol: payload.rol } }, 200, cors);
    }

    // — RESTO: requieren auth válida —
    const auth = await getAuth(request, env);
    if (!auth) return json({ error: 'Auth requerida' }, 401, cors);

    // — PROXY ANTHROPIC (cualquier usuario autenticado) —
    if (path === '/ai' && request.method === 'POST') {
      const body = await request.json();
      const res = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': env.ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      return json(data, res.status, cors);
    }

    // — DATOS MAESTROS (incluye usuarios y PINs) —
    if (path === '/data') {
      const KEY = 'kb/data.json';
      if (request.method === 'GET') {
        const arr = await loadData(env);
        return json(redactPins(arr), 200, cors);
      }
      if (request.method === 'POST') {
        if (!isAdminRole(auth.rol)) return json({ error: 'Solo admin' }, 403, cors);
        const text = await request.text();
        let incoming;
        try { incoming = JSON.parse(text); } catch { return json({ error: 'JSON inválido' }, 400, cors); }
        if (!Array.isArray(incoming)) return json({ error: 'Se esperaba array' }, 400, cors);

        // El cliente recibe los PINs redactados (sin pin/pinHash). Para no borrar
        // los PINs almacenados al guardar, mergeamos por id: si el item entrante
        // no trae pin/pinHash pero el existente sí, preservamos los del existente.
        const existing = await loadData(env);
        const byId = new Map();
        for (const it of existing) if (it && it.id !== undefined) byId.set(it.id, it);
        // Convención: undefined = no enviado (preservar lo existente); null = borrar intencionado.
        const merged = incoming.map(it => {
          if (!it || it.tipo !== 'instalador' || it.id === undefined) return it;
          const prev = byId.get(it.id);
          if (!prev) return it; // usuario nuevo, lo dejamos tal cual
          const out = { ...it };
          if (out.pin === undefined)     { if (prev.pin !== undefined) out.pin = prev.pin; }
          else if (out.pin === null)     { delete out.pin; }
          if (out.pinHash === undefined) { if (prev.pinHash !== undefined) out.pinHash = prev.pinHash; }
          else if (out.pinHash === null) { delete out.pinHash; }
          return out;
        });

        await env.FOTOS.put(KEY, JSON.stringify(merged), { httpMetadata: { contentType: 'application/json' } });
        return new Response('ok', { headers: cors });
      }
    }

    // — DATOS OPERATIVOS (cualquier usuario autenticado) —
    for (const entity of ['movimientos', 'partes', 'visitas', 'materiales']) {
      if (path === '/' + entity) {
        const KEY = 'kb/' + entity + '.json';
        if (request.method === 'GET') {
          const obj = await env.FOTOS.get(KEY);
          const text = obj ? await obj.text() : '[]';
          return new Response(text, { headers: { ...cors, 'Content-Type': 'application/json' } });
        }
        if (request.method === 'POST') {
          const text = await request.text();
          try { JSON.parse(text); } catch { return json({ error: 'JSON inválido' }, 400, cors); }
          await env.FOTOS.put(KEY, text, { httpMetadata: { contentType: 'application/json' } });
          return new Response('ok', { headers: cors });
        }
      }
    }

    // — SUBIDA FOTOS —
    if (path === '/foto' && request.method === 'POST') {
      const formData = await request.formData();
      const file = formData.get('file');
      if (!file) return new Response('No file', { status: 400, headers: cors });
      const ext = (file.name || '').split('.').pop() || 'jpg';
      const key = 'fotos/' + Date.now() + '_' + Math.random().toString(36).slice(2) + '.' + ext;
      await env.FOTOS.put(key, file.stream(), {
        httpMetadata: { contentType: file.type }
      });
      const fotoUrl = 'https://efigalia-kb.efigalia-solar.workers.dev/foto/' + key;
      return json({ url: fotoUrl, nombre: file.name || key }, 200, cors);
    }

    return new Response('Not found', { status: 404, headers: cors });
  },
};
