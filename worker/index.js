// Cloudflare Worker para Efigalia
// Fase B: PINs hasheados con PBKDF2 (100k iter, sal por usuario).
// Endpoints públicos: GET /foto/:key, GET /auth/users, POST /auth/login.
// Resto: requieren Authorization: Bearer <token>.

const ALLOWED_ORIGINS = new Set([
  'https://efigaliasolar-droid.github.io'
]);

const SESSION_TTL_SECONDS = 24 * 60 * 60; // 24h
const PBKDF2_ITER = 100000;

const MAX_PHOTO_BYTES = 10 * 1024 * 1024; // 10 MB
const ALLOWED_PHOTO_MIMES = new Set(['image/jpeg', 'image/png', 'image/webp']);

// ── CORS ──────────────────────────────────────────────────
function corsHeaders(request) {
  const origin = request.headers.get('Origin') || '';
  const allow = ALLOWED_ORIGINS.has(origin) ? origin : '';
  return {
    'Access-Control-Allow-Origin': allow,
    'Vary': 'Origin',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, If-Match',
    'Access-Control-Expose-Headers': 'ETag',
    'Access-Control-Max-Age': '86400',
  };
}

function json(body, status, cors) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, 'Content-Type': 'application/json' },
  });
}

// ── Encoding helpers ─────────────────────────────────────
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
function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
function bytesToHex(bytes) {
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
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

// ── PBKDF2 para PINs ─────────────────────────────────────
async function pbkdf2Hash(pin, saltHex, iterations) {
  const salt = hexToBytes(saltHex);
  const key = await crypto.subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    key, 256
  );
  return bytesToHex(new Uint8Array(bits));
}
async function generatePinFields(pin) {
  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const pinSalt = bytesToHex(saltBytes);
  const pinPBKDF2 = await pbkdf2Hash(pin, pinSalt, PBKDF2_ITER);
  return { pinPBKDF2, pinSalt, pinIter: PBKDF2_ITER };
}
function constantTimeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
function isValidPin(pin) {
  return typeof pin === 'string' && /^\d{4,8}$/.test(pin);
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
const DATA_KEY = 'kb/data.json';

// Devuelve {text, etag} o {text:null, etag:null} si no existe.
async function loadRaw(env, key) {
  const obj = await env.FOTOS.get(key);
  if (!obj) return { text: null, etag: null };
  const text = await obj.text();
  const etag = await etagOf(text);
  return { text, etag };
}
async function etagOf(text) {
  const buf = await crypto.subtle.digest('SHA-256', enc.encode(text));
  return '"' + bytesToHex(new Uint8Array(buf)) + '"';
}

// loadData usa loadRaw; mantenemos el alias para no tocar el resto del worker.
async function loadData(env) {
  const { text } = await loadRaw(env, DATA_KEY);
  if (!text) return [];
  try { return JSON.parse(text); } catch { return []; }
}
async function saveData(env, arr) {
  await env.FOTOS.put(DATA_KEY, JSON.stringify(arr), {
    httpMetadata: { contentType: 'application/json' },
  });
}

// Comprueba If-Match. Devuelve {ok, currentEtag, currentText}.
// Regla:
//   - Si el archivo NO existe: aceptar (primera escritura) sólo si If-Match es '*' o falta.
//   - Si el archivo existe: exigir If-Match con etag actual o '*'.
async function checkIfMatch(request, env, key) {
  const ifMatch = (request.headers.get('If-Match') || '').trim();
  const { text, etag } = await loadRaw(env, key);
  if (text === null) {
    if (!ifMatch || ifMatch === '*') return { ok: true, currentEtag: null, currentText: null };
    return { ok: false, currentEtag: null, currentText: null };
  }
  if (!ifMatch) return { ok: false, currentEtag: etag, currentText: text };
  if (ifMatch === '*') return { ok: true, currentEtag: etag, currentText: text };
  const norm = s => s.replace(/^W\//, '');
  return { ok: norm(ifMatch) === norm(etag), currentEtag: etag, currentText: text };
}

// Copia el texto actual a kb/_backups/<entidad>-<ISOtimestamp>.json antes de
// sobreescribir. Si no había nada (primera escritura), no hace nada.
async function backupCurrent(env, key, currentText) {
  if (!currentText) return;
  const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const filename = key.split('/').pop().replace(/\.json$/, '');
  const backupKey = 'kb/_backups/' + filename + '-' + ts + '.json';
  await env.FOTOS.put(backupKey, currentText, {
    httpMetadata: { contentType: 'application/json' },
  });
}

// Devuelve el array sin los campos de PIN (cualquier formato) de los instaladores.
// Añade hasPin: true si tenía algún campo de PIN, para que la UI pueda indicar
// estado sin exponer el hash.
function redactPins(arr) {
  if (!Array.isArray(arr)) return arr;
  return arr.map(it => {
    if (it && it.tipo === 'instalador') {
      const { pin, pinHash, pinPBKDF2, pinSalt, pinIter, ...rest } = it;
      rest.hasPin = !!(pinPBKDF2 || pin || pinHash);
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

      // Delay constante para no filtrar si el usuario existe o no.
      await new Promise(r => setTimeout(r, 150));

      if (!user) return json({ error: 'Usuario o PIN incorrecto' }, 401, cors);

      let ok = false;

      // 1) Bootstrap PIN temporal (env vars). Solo válido si AMBOS están
      //    configurados Y el nombre del login coincide con BOOTSTRAP_ADMIN_NAME.
      //    Pensado para recuperar/asignar el primer PIN PBKDF2 y luego borrar
      //    los secrets. Restringir por nombre evita que otros usuarios que
      //    descubran el PIN bootstrap puedan suplantar.
      if (env.BOOTSTRAP_PIN && env.BOOTSTRAP_ADMIN_NAME &&
          typeof env.BOOTSTRAP_PIN === 'string' && env.BOOTSTRAP_PIN.length >= 8 &&
          user.nombre === env.BOOTSTRAP_ADMIN_NAME) {
        if (constantTimeEqual(pin, env.BOOTSTRAP_PIN)) ok = true;
      }

      // 2) PIN PBKDF2 normal.
      if (!ok && user.pinPBKDF2 && user.pinSalt && user.pinIter) {
        const hash = await pbkdf2Hash(pin, user.pinSalt, user.pinIter);
        ok = constantTimeEqual(hash, user.pinPBKDF2);
      }

      // 3) Formatos viejos (pin claro, pinHash SHA256): YA NO se aceptan.
      //    Si el usuario solo los tiene, hay que reasignar PIN vía /auth/set-pin.

      if (!ok) {
        if (!user.pinPBKDF2 && (user.pin || user.pinHash)) {
          return json({ error: 'PIN no migrado. Pide al admin que te asigne un PIN nuevo.' }, 401, cors);
        }
        if (!user.pinPBKDF2) {
          return json({ error: 'PIN no asignado. Pide al admin que te asigne uno.' }, 401, cors);
        }
        return json({ error: 'Usuario o PIN incorrecto' }, 401, cors);
      }

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

    // — Cambiar mi propio PIN (cualquier autenticado) —
    if (path === '/auth/change-pin' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return json({ error: 'bad json' }, 400, cors); }
      const oldPin = typeof body.oldPin === 'string' ? body.oldPin.trim() : '';
      const newPin = typeof body.newPin === 'string' ? body.newPin.trim() : '';
      if (!isValidPin(newPin)) return json({ error: 'PIN nuevo debe ser 4-8 dígitos' }, 400, cors);

      const data = await loadData(env);
      const idx = data.findIndex(i => i && i.tipo === 'instalador' && i.nombre === auth.sub);
      if (idx === -1) return json({ error: 'Usuario no encontrado' }, 404, cors);
      const user = data[idx];

      // Si el usuario ya tiene PIN PBKDF2, exigimos verificar el oldPin.
      // Si no tiene (acaba de loguearse por bootstrap), permitimos setear sin oldPin.
      if (user.pinPBKDF2 && user.pinSalt && user.pinIter) {
        if (!oldPin) return json({ error: 'Falta PIN actual' }, 400, cors);
        const oldHash = await pbkdf2Hash(oldPin, user.pinSalt, user.pinIter);
        if (!constantTimeEqual(oldHash, user.pinPBKDF2)) {
          return json({ error: 'PIN actual incorrecto' }, 401, cors);
        }
      }

      const fields = await generatePinFields(newPin);
      data[idx] = { ...user, ...fields };
      delete data[idx].pin;
      delete data[idx].pinHash;
      await saveData(env, data);
      return json({ ok: true }, 200, cors);
    }

    // — Asignar PIN a otro usuario (solo admin) —
    if (path === '/auth/set-pin' && request.method === 'POST') {
      if (!isAdminRole(auth.rol)) return json({ error: 'Solo admin' }, 403, cors);
      let body;
      try { body = await request.json(); } catch { return json({ error: 'bad json' }, 400, cors); }
      const id     = body && body.id;
      const nombre = body && typeof body.nombre === 'string' ? body.nombre.trim() : '';
      const pin    = body && typeof body.pin === 'string'    ? body.pin.trim()    : '';
      if (!isValidPin(pin)) return json({ error: 'PIN debe ser 4-8 dígitos' }, 400, cors);
      if (!id && !nombre)   return json({ error: 'Falta id o nombre' }, 400, cors);

      const data = await loadData(env);
      const idx = data.findIndex(i =>
        i && i.tipo === 'instalador' &&
        (id !== undefined && id !== null ? i.id === id : i.nombre === nombre)
      );
      if (idx === -1) return json({ error: 'Usuario no encontrado' }, 404, cors);

      const fields = await generatePinFields(pin);
      data[idx] = { ...data[idx], ...fields };
      delete data[idx].pin;
      delete data[idx].pinHash;
      await saveData(env, data);
      return json({ ok: true }, 200, cors);
    }

    // — PROXY ANTHROPIC (cualquier autenticado) —
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

    // — DATOS MAESTROS (incluye usuarios) —
    if (path === '/data') {
      if (request.method === 'GET') {
        const { text, etag } = await loadRaw(env, DATA_KEY);
        let arr = [];
        if (text) { try { arr = JSON.parse(text); } catch {} }
        const body = JSON.stringify(redactPins(arr));
        return new Response(body, {
          headers: { ...cors, 'Content-Type': 'application/json', 'ETag': etag || '"empty"' },
        });
      }
      if (request.method === 'POST') {
        if (!isAdminRole(auth.rol)) return json({ error: 'Solo admin' }, 403, cors);
        const check = await checkIfMatch(request, env, DATA_KEY);
        if (!check.ok) return json({ error: 'Conflict', currentEtag: check.currentEtag }, 409, cors);

        const text = await request.text();
        let incoming;
        try { incoming = JSON.parse(text); } catch { return json({ error: 'JSON inválido' }, 400, cors); }
        if (!Array.isArray(incoming)) return json({ error: 'Se esperaba array' }, 400, cors);

        // Los campos de PIN se gestionan EXCLUSIVAMENTE vía /auth/set-pin y
        // /auth/change-pin. POST /data los stripea siempre y preserva los del
        // existing (solo el formato nuevo PBKDF2; el viejo pin/pinHash se
        // descarta como migración silenciosa).
        let existing = [];
        if (check.currentText) { try { existing = JSON.parse(check.currentText); } catch {} }
        const byId = new Map();
        for (const it of existing) if (it && it.id !== undefined) byId.set(it.id, it);

        const merged = incoming.map(it => {
          if (!it || it.tipo !== 'instalador') return it;
          const { pin, pinHash, pinPBKDF2, pinSalt, pinIter, ...rest } = it;
          if (it.id === undefined) return rest;
          const prev = byId.get(it.id);
          if (!prev) return rest;
          const out = { ...rest };
          if (prev.pinPBKDF2) out.pinPBKDF2 = prev.pinPBKDF2;
          if (prev.pinSalt)   out.pinSalt   = prev.pinSalt;
          if (prev.pinIter)   out.pinIter   = prev.pinIter;
          return out;
        });

        await backupCurrent(env, DATA_KEY, check.currentText);
        const newText = JSON.stringify(merged);
        await env.FOTOS.put(DATA_KEY, newText, { httpMetadata: { contentType: 'application/json' } });
        return new Response('ok', { headers: { ...cors, 'ETag': await etagOf(newText) } });
      }
    }

    // — DATOS OPERATIVOS (cualquier autenticado) —
    for (const entity of ['movimientos', 'partes', 'visitas', 'materiales']) {
      if (path === '/' + entity) {
        const KEY = 'kb/' + entity + '.json';
        if (request.method === 'GET') {
          const { text, etag } = await loadRaw(env, KEY);
          return new Response(text || '[]', {
            headers: { ...cors, 'Content-Type': 'application/json', 'ETag': etag || '"empty"' },
          });
        }
        if (request.method === 'POST') {
          const check = await checkIfMatch(request, env, KEY);
          if (!check.ok) return json({ error: 'Conflict', currentEtag: check.currentEtag }, 409, cors);

          const text = await request.text();
          try { JSON.parse(text); } catch { return json({ error: 'JSON inválido' }, 400, cors); }

          await backupCurrent(env, KEY, check.currentText);
          await env.FOTOS.put(KEY, text, { httpMetadata: { contentType: 'application/json' } });
          return new Response('ok', { headers: { ...cors, 'ETag': await etagOf(text) } });
        }
      }
    }

    // — SUBIDA FOTOS (validada) —
    if (path === '/foto' && request.method === 'POST') {
      const formData = await request.formData();
      const file = formData.get('file');
      if (!file) return json({ error: 'No file' }, 400, cors);
      if (typeof file.size === 'number' && file.size > MAX_PHOTO_BYTES) {
        return json({ error: 'Archivo > 10 MB' }, 413, cors);
      }
      if (!ALLOWED_PHOTO_MIMES.has(file.type)) {
        return json({ error: 'Tipo no permitido (jpg/png/webp)' }, 415, cors);
      }
      const ext = (file.name || '').split('.').pop() || 'jpg';
      const safeExt = /^[a-zA-Z0-9]{1,5}$/.test(ext) ? ext.toLowerCase() : 'jpg';
      const key = 'fotos/' + Date.now() + '_' + Math.random().toString(36).slice(2) + '.' + safeExt;
      await env.FOTOS.put(key, file.stream(), {
        httpMetadata: { contentType: file.type }
      });
      const fotoUrl = 'https://efigalia-kb.efigalia-solar.workers.dev/foto/' + key;
      return json({ url: fotoUrl, nombre: file.name || key }, 200, cors);
    }

    return new Response('Not found', { status: 404, headers: cors });
  },
};
