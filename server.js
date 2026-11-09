// Seguridad y Riesgos · Polígrafías — servidor
const path = require('path');
const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;
app.set('trust proxy', 1);

const pool = process.env.DATABASE_URL
  ? new Pool({ connectionString: process.env.DATABASE_URL })
  : null;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS usuarios (
  id SERIAL PRIMARY KEY,
  usuario TEXT UNIQUE NOT NULL,
  nombre TEXT NOT NULL,
  rol TEXT NOT NULL,
  correo TEXT,
  zona TEXT,
  password_hash TEXT,
  activo BOOLEAN DEFAULT TRUE,
  creado TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS pruebas (
  id SERIAL PRIMARY KEY,
  fecha DATE NOT NULL,
  hora TIME,
  poligrafista TEXT,
  evaluado TEXT,
  cc TEXT,
  tipo TEXT,
  estado TEXT DEFAULT 'programada',
  datos JSONB DEFAULT '{}'::jsonb,
  creado TIMESTAMPTZ DEFAULT now(),
  actualizado TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS resultados (
  id SERIAL PRIMARY KEY,
  prueba_id INTEGER REFERENCES pruebas(id) ON DELETE SET NULL,
  poligrafista TEXT,
  cc TEXT,
  resultado TEXT,
  fecha DATE,
  datos JSONB DEFAULT '{}'::jsonb,
  creado TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS programacion (
  id SERIAL PRIMARY KEY,
  semana DATE,
  poligrafista TEXT,
  datos JSONB DEFAULT '{}'::jsonb,
  creado TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS vencimientos (
  id SERIAL PRIMARY KEY,
  cc TEXT,
  nombre TEXT,
  contrato TEXT,
  regional TEXT,
  cliente TEXT,
  fecha_ultima DATE,
  fecha_vence DATE,
  datos JSONB DEFAULT '{}'::jsonb,
  creado TIMESTAMPTZ DEFAULT now()
);
ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS hash_legado TEXT;
ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS debe_cambiar BOOLEAN DEFAULT TRUE;
ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS permisos JSONB;
ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS telefono TEXT;
ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS color TEXT;
ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS estado TEXT DEFAULT 'activo';
ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS sin_claves BOOLEAN DEFAULT FALSE;
CREATE TABLE IF NOT EXISTS bitacora (
  id BIGSERIAL PRIMARY KEY,
  fecha TIMESTAMPTZ DEFAULT now(),
  usuario TEXT,
  nombre TEXT,
  rol TEXT,
  accion TEXT NOT NULL,
  detalle TEXT,
  resultado TEXT DEFAULT 'ok',
  ip TEXT,
  agente TEXT
);
CREATE INDEX IF NOT EXISTS bitacora_fecha ON bitacora (fecha DESC);
ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS intentos INTEGER DEFAULT 0;
ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS bloqueado_hasta TIMESTAMPTZ;
ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS ultimo_ingreso TIMESTAMPTZ;
ALTER TABLE resultados ADD COLUMN IF NOT EXISTS origen TEXT;
ALTER TABLE pruebas ADD COLUMN IF NOT EXISTS cid BIGINT;
ALTER TABLE pruebas ADD COLUMN IF NOT EXISTS creado_por TEXT;
ALTER TABLE pruebas ALTER COLUMN fecha DROP NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS pruebas_cid_idx ON pruebas (cid);
CREATE INDEX IF NOT EXISTS resultados_poli_idx ON resultados (poligrafista, origen);
DROP TABLE IF EXISTS google_tokens;
ALTER TABLE sesiones ADD COLUMN IF NOT EXISTS via TEXT;
CREATE TABLE IF NOT EXISTS codigos (
  usuario_id INTEGER PRIMARY KEY REFERENCES usuarios(id) ON DELETE CASCADE,
  hash TEXT NOT NULL,
  expira TIMESTAMPTZ NOT NULL,
  intentos INTEGER DEFAULT 0,
  enviado TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS repositorios (
  id SERIAL PRIMARY KEY,
  nombre TEXT NOT NULL,
  categoria TEXT NOT NULL,
  url TEXT NOT NULL,
  poligrafista TEXT,
  creado TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS planta (
  cedula TEXT PRIMARY KEY,
  datos JSONB NOT NULL DEFAULT '{}'::jsonb,
  actualizado TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS permisos (
  id SERIAL PRIMARY KEY,
  usuario TEXT NOT NULL,
  tipo TEXT NOT NULL,
  desde DATE NOT NULL,
  hasta DATE NOT NULL,
  hora_ini TIME,
  hora_fin TIME,
  motivo TEXT,
  estado TEXT DEFAULT 'pendiente',   -- pendiente, aprobado, rechazado, cancelado
  respuesta TEXT,
  resuelto_por TEXT,
  resuelto TIMESTAMPTZ,
  creado TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS mensajes (
  id SERIAL PRIMARY KEY,
  de TEXT NOT NULL,
  para TEXT NOT NULL,
  texto TEXT NOT NULL,
  leido BOOLEAN DEFAULT FALSE,
  creado TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS mensajes_para_idx ON mensajes (para, leido);
CREATE INDEX IF NOT EXISTS mensajes_par_idx ON mensajes (de, para, creado);
CREATE TABLE IF NOT EXISTS avisos (
  id SERIAL PRIMARY KEY,
  para TEXT NOT NULL,            -- correo del destinatario o 'rol:admin'
  tipo TEXT NOT NULL,            -- registro, acceso, ayuda, sistema
  titulo TEXT NOT NULL,
  texto TEXT,
  de TEXT,
  datos JSONB DEFAULT '{}'::jsonb,
  leido BOOLEAN DEFAULT FALSE,
  creado TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS en_vivo (
  id TEXT PRIMARY KEY,
  tipo TEXT NOT NULL,
  poligrafista TEXT,
  datos JSONB DEFAULT '{}'::jsonb,
  actualizado TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sesiones (
  token TEXT PRIMARY KEY,
  usuario_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
  expira TIMESTAMPTZ NOT NULL,
  creado TIMESTAMPTZ DEFAULT now()
);
`;

// Cuentas iniciales: mismas claves temporales de la demo (se migran a bcrypt al primer ingreso)
const USUARIOS_INICIALES = [
  ['administrador@suitepoligrafia.example', 'Administrador', 'admin', '5344d83702b731a3d8336e4e4793b0f9cef3704e28778258fc25891c2e3d9487'],
  ['analista@suitepoligrafia.example', 'Analista', 'analista', 'f3621b01f85df1566eddc124060e656aa0535c7f99dc36b41a1155e36e9e3b93'],
  ['poligrafista1@suitepoligrafia.example', 'Poligrafista 1', 'P1', 'a60b8edc0b9450c1c025f23305e3f5be2652a642f37de4277cd3ecd9dff757eb'],
  ['poligrafista2@suitepoligrafia.example', 'Poligrafista 2', 'P2', 'c83b9585e3b02ee08e54ab33f96ef9b1e641cc0af2c2dc60c774912b8e90d4a1'],
  ['poligrafista3@suitepoligrafia.example', 'Poligrafista 3', 'P3', '0dd25ef1602f18bdeaf996d7b698652717916f391ba5215de77ab041439531d9'],
  ['poligrafista4@suitepoligrafia.example', 'Poligrafista 4', 'P4', '00fe0a753459ac039ba5b777274928116252417836063ac001ca3c9128fe29a6'],
  ['talentohumano1@suitepoligrafia.example', 'Talento Humano 1', 'th', 'b702114775f8285a3e4b8f3b60ad5753a9ccdc4078b71ea753331b144a83b5a2'],
  ['talentohumano2@suitepoligrafia.example', 'Talento Humano 2', 'th', 'c4ede350be5210aa610789bdec3db724d2822e48e9cb64769411f2a4d11af0f0'],
  ['lidera@suitepoligrafia.example', 'Líder A', 'lider', '9e9ab1c3330678d3119c2f8687aa60243cdb8aebf95c9944e98b56438af84801'],
  ['liderb@suitepoligrafia.example', 'Líder B', 'lider', 'c97452f888810bd5d5b3af13c7d9347a2e8e376cf7cc893a4bd3771791480e43'],
  ['liderc@suitepoligrafia.example', 'Líder C', 'lider', 'e26cbb7ab6bb1d969dc0704ded9ab2a39888ca621e09b68f5cb165a2ae240079']
];

async function initDB() {
  if (!pool) { console.log('Sin DATABASE_URL: modo demo.'); return; }
  try {
    await pool.query(SCHEMA);
    for (const [usuario, nombre, rol, legado] of USUARIOS_INICIALES) {
      await pool.query(
        'INSERT INTO usuarios (usuario, nombre, rol, hash_legado, debe_cambiar) VALUES ($1,$2,$3,$4,TRUE) ON CONFLICT (usuario) DO NOTHING',
        [usuario, nombre, rol, legado]
      );
    }
    // Nombres reales de los poligrafistas iniciales (solo si conservan el nombre gen)
    for (const [n, real] of [[1, 'Durley Wilches'], [2, 'Carlos Castaño'], [3, 'Luis Vanegas'], [4, 'José Barbosa']]) {
      await pool.query('UPDATE usuarios SET nombre = $1 WHERE usuario = $2 AND nombre = $3', [real, 'poligrafista' + n + '@suitepoligrafia.example', 'Poligrafista ' + n]);
    }
    await pool.query('DELETE FROM sesiones WHERE expira < now()');
    await pool.query("DELETE FROM bitacora WHERE fecha < now() - interval '2 years'");
    await pool.query("DELETE FROM en_vivo WHERE actualizado < now() - interval '24 hours'");
    console.log('Base de datos lista.');
  }
  catch (e) { console.error('Error BD:', e.message); }
}

app.get('/api/salud', async (req, res) => {
  if (!pool) return res.json({ ok: true, db: 'sin configurar' });
  try {
    const r = await pool.query("SELECT table_name FROM information_schema.tables WHERE table_schema='public' ORDER BY 1");
    res.json({ ok: true, db: 'conectada', tablas: r.rows.map(x => x.table_name) });
  } catch (e) {
    res.status(500).json({ ok: false, db: 'error', detalle: e.message });
  }
});

// ===== Autenticación =====
app.use((req, res, next) => ['/api/planta', '/api/resultados/importar'].includes(req.path) ? next() : express.json({ limit: '1mb' })(req, res, next));

// ===== Bitácora de actividades (quién ingresó y qué hizo) =====
function bitacora(req, u, accion, detalle, resultado) {
  if (!pool) return;
  pool.query('INSERT INTO bitacora (usuario, nombre, rol, accion, detalle, resultado, ip, agente) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
    [u ? u.usuario : null, u ? u.nombre : null, u ? u.rol : null, String(accion).slice(0, 120), detalle ? String(detalle).slice(0, 400) : null,
     resultado || 'ok', req.ip || null, String(req.headers['user-agent'] || '').slice(0, 200)]).catch(e => console.error('bitacora:', e.message));
}
const quien = async id => { const r = pool ? (await pool.query('SELECT usuario, nombre FROM usuarios WHERE id = $1', [+id]).catch(() => ({ rows: [] }))).rows[0] : null; return r ? r.nombre + ' (' + r.usuario + ')' : '#' + id; };
// [método, ruta, acción, detalle(req)] — las rutas no listadas aquí registran desde su propio código o no se registran (consultas)
const REGLAS_BIT = [
  ['POST', /^\/api\/login$/, 'Ingreso con contraseña', r => r.body?.u],
  ['POST', /^\/api\/codigo\/enviar$/, 'Pidió código de ingreso al correo', r => r.body?.u],
  ['POST', /^\/api\/codigo\/verificar$/, 'Ingreso con código al correo', r => r.body?.u],
  ['POST', /^\/api\/logout$/, 'Cerró sesión'],
  ['POST', /^\/api\/clave$/, 'Cambió su contraseña'],
  ['POST', /^\/api\/usuarios$/, 'Creó usuario', r => [r.body?.nombre, r.body?.correo, r.body?.rol].filter(Boolean).join(' · ')],
  ['PUT', /^\/api\/usuarios\/(\d+)$/, r => r.body?.aprobar ? 'Aprobó solicitud de cuenta' : r.body?.activo === false ? 'Desactivó/editó usuario' : 'Editó usuario', r => r._obj],
  ['POST', /^\/api\/usuarios\/(\d+)\/clave$/, 'Restableció contraseña', r => r._obj],
  ['POST', /^\/api\/usuarios\/(\d+)\/desbloquear$/, 'Desbloqueó usuario', r => r._obj],
  ['DELETE', /^\/api\/usuarios\/(\d+)$/, 'Rechazó solicitud de cuenta', r => r._obj],
  ['POST', /^\/api\/registro$/, 'Solicitud de registro', r => [r.body?.nombre, r.body?.correo || r.body?.u].filter(Boolean).join(' · ')],
  ['POST', /^\/api\/ayuda-acceso$/, 'Reportó problema de acceso', r => r.body?.correo || r.body?.u],
  ['POST', /^\/api\/mensajes$/, 'Envió mensaje interno', r => 'para ' + (r.body?.para || '')],
  ['POST', /^\/api\/ayuda$/, 'Pidió ayuda al administrador'],
  ['POST', /^\/api\/permisos$/, 'Solicitó permiso o ausencia', r => [r.body?.tipo, r.body?.desde, r.body?.hasta].filter(Boolean).join(' · ')],
  ['POST', /^\/api\/permisos\/(\d+)\/resolver$/, r => r.body?.estado === 'aprobado' ? 'Aprobó permiso' : 'Rechazó permiso', r => 'solicitud #' + r._id],
  ['POST', /^\/api\/permisos\/(\d+)\/cancelar$/, 'Canceló permiso', r => 'solicitud #' + r._id],
  ['POST', /^\/api\/planta$/, 'Importó base de vencimientos', r => (Array.isArray(r.body?.filas) ? r.body.filas.length : 0) + ' registros'],
  ['DELETE', /^\/api\/planta$/, 'Borró base de vencimientos'],
  ['POST', /^\/api\/resultados\/importar$/, 'Importó base de resultados', r => [r.body?.poligrafista, (Array.isArray(r.body?.filas) ? r.body.filas.length : 0) + ' registros'].join(' · ')],
  ['POST', /^\/api\/repositorios$/, 'Agregó carpeta de Drive', r => r.body?.nombre],
  ['PUT', /^\/api\/repositorios\/(\d+)$/, 'Editó carpeta de Drive', r => r.body?.nombre],
  ['DELETE', /^\/api\/repositorios\/(\d+)$/, 'Quitó carpeta de Drive', r => '#' + r._id]
];
app.use('/api', async (req, res, next) => {
  if (req.method === 'GET') return next();
  const full = '/api' + req.path, regla = REGLAS_BIT.find(([m, re]) => m === req.method && re.test(full));
  if (!regla) return next();
  const m = full.match(regla[1]); req._id = m && m[1];
  if (req._id && /usuarios/.test(full)) req._obj = await quien(req._id);
  if (full === '/api/logout') req._u = await usuarioDeSesion(req).catch(() => null);
  res.on('finish', () => {
    const st = res.statusCode, u = req._u || null;
    let accion = typeof regla[2] === 'function' ? regla[2](req) : regla[2];
    let det = ''; try { det = regla[3] ? regla[3](req) || '' : ''; } catch (e) {}
    const esIngreso = /^\/api\/(login|codigo\/verificar)$/.test(full);
    if (st >= 400) {
      if (st === 401 && !esIngreso && !/\/clave$/.test(full)) return; // sesión vencida: no se registra
      accion = esIngreso ? (st === 423 ? 'Cuenta bloqueada por intentos fallidos' : 'Intento de ingreso fallido') : 'Acción rechazada: ' + accion.charAt(0).toLowerCase() + accion.slice(1);
    }
    bitacora(req, u, accion, det, st >= 400 ? 'fallido' : 'ok');
  });
  next();
});

const COOKIE = 'poli_sid';
const HORAS_SESION = 12;
const intentos = new Map(); // bloqueo simple: 5 fallos en 15 min

function leerCookie(req, nombre) {
  const c = req.headers.cookie || '';
  for (const p of c.split(';')) {
    const [k, ...v] = p.trim().split('=');
    if (k === nombre) return decodeURIComponent(v.join('='));
  }
  return null;
}
function ponerCookie(res, valor, maxAgeSeg) {
  const seguro = process.env.NODE_ENV === 'development' ? '' : '; Secure';
  res.setHeader('Set-Cookie', `${COOKIE}=${valor}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${maxAgeSeg}${seguro}`);
}
function igualLegado(correo, clave, legado) {
  const h = Buffer.from(crypto.createHash('sha256').update(correo + ':' + clave).digest('hex'));
  const l = Buffer.from(String(legado));
  return h.length === l.length && crypto.timingSafeEqual(h, l);
}
const publico = u => ({ usuario: u.usuario, nombre: u.nombre, rol: u.rol, debe_cambiar: u.debe_cambiar && !u.sin_claves && !['google', 'codigo'].includes(u.via_sesion), sin_claves: !!u.sin_claves, google: u.via_sesion === 'google', permisos: u.permisos || null });

async function usuarioDeSesion(req) {
  const t = leerCookie(req, COOKIE);
  if (!t || !pool) return null;
  const r = await pool.query(
    'SELECT u.*, s.via AS via_sesion FROM sesiones s JOIN usuarios u ON u.id = s.usuario_id WHERE s.token = $1 AND s.expira > now() AND u.activo',
    [t]
  );
  return r.rows[0] || null;
}
function sinBD(res) { return res.status(503).json({ ok: false, error: 'Base de datos no disponible.' }); }

app.post('/api/login', async (req, res) => {
  if (!pool) return sinBD(res);
  const correo = String(req.body?.u || '').trim().toLowerCase();
  const clave = String(req.body?.p || '');
  const k = correo + '|' + req.ip, ahora = Date.now();
  const reg = (intentos.get(k) || []).filter(t => ahora - t < 15 * 60e3);
  if (reg.length >= 5) return res.status(429).json({ ok: false, error: 'Demasiados intentos. Espera 15 minutos.' });
  try {
    const r = await pool.query('SELECT * FROM usuarios WHERE usuario = $1', [correo]);
    const u = r.rows[0];
    if (u && u.bloqueado_hasta && new Date(u.bloqueado_hasta) > new Date()) {
      const min = Math.ceil((new Date(u.bloqueado_hasta) - Date.now()) / 60000);
      return res.status(423).json({ ok: false, error: 'Cuenta bloqueada por intentos fallidos. Intenta en ' + min + ' min o pide al administrador que la desbloquee.' });
    }
    let ok = false;
    if (u && u.password_hash) ok = await bcrypt.compare(clave, u.password_hash);
    else if (u && u.hash_legado) {
      ok = igualLegado(correo, clave, u.hash_legado);
    }
    if (!ok) {
      reg.push(ahora); intentos.set(k, reg);
      if (u) {
        const n = (u.intentos || 0) + 1;
        if (n >= 5) {
          await pool.query("UPDATE usuarios SET intentos = 0, bloqueado_hasta = now() + interval '15 minutes' WHERE id = $1", [u.id]);
          await avisar('rol:admin', 'acceso', 'Cuenta bloqueada: ' + u.nombre, u.usuario + ' superó 5 intentos fallidos. Se desbloquea sola en 15 min, o puedes desbloquearla en Usuarios y roles.', u.usuario, { correo: u.usuario });
          return res.status(423).json({ ok: false, error: 'Cuenta bloqueada por 5 intentos fallidos. Intenta en 15 min o pide al administrador que la desbloquee.' });
        }
        await pool.query('UPDATE usuarios SET intentos = $1 WHERE id = $2', [n, u.id]);
        return res.status(401).json({ ok: false, error: 'Correo o contraseña incorrectos.' });
      }
      return res.status(401).json({ ok: false, error: 'Correo o contraseña incorrectos.' });
    }
    intentos.delete(k);
    if (u.estado === 'pendiente') return res.status(403).json({ ok: false, error: 'Tu solicitud de cuenta está pendiente. El administrador debe aprobarla antes de que puedas ingresar.' });
    if (!u.activo) return res.status(403).json({ ok: false, error: 'Tu cuenta está desactivada. Contacta al administrador.' });
    const previo = u.ultimo_ingreso;
    await pool.query('UPDATE usuarios SET intentos = 0, bloqueado_hasta = NULL, ultimo_ingreso = now() WHERE id = $1', [u.id]);
    u.previo = previo;
    const token = crypto.randomBytes(32).toString('hex');
    await pool.query("INSERT INTO sesiones (token, usuario_id, expira) VALUES ($1, $2, now() + interval '" + HORAS_SESION + " hours')", [token, u.id]);
    ponerCookie(res, token, HORAS_SESION * 3600); req._u = u;
    res.json({ ok: true, user: publico(u), bienvenida: { previo: u.previo || null } });
  } catch (e) { console.error('login:', e.message); res.status(500).json({ ok: false, error: 'Error del servidor.' }); }
});

// ===== Ingreso con código enviado al correo (Brevo) =====
// Variables en Railway: BREVO_API_KEY y BREVO_SENDER (correo remitente verificado en Brevo).
const BREVO_KEY = process.env.BREVO_API_KEY || '', BREVO_FROM = process.env.BREVO_SENDER || '';
const BREVO_URL = process.env.BREVO_API_URL || 'https://api.brevo.com/v3/smtp/email';
const PIMIENTA = process.env.CODIGO_SECRETO || crypto.randomBytes(24).toString('hex');
const hashCodigo = (id, c) => crypto.createHash('sha256').update(id + ':' + c + ':' + PIMIENTA).digest('hex');
async function enviarCorreo(para, asunto, html) {
  const r = await fetch(BREVO_URL, { method: 'POST', headers: { 'api-key': BREVO_KEY, 'Content-Type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ sender: { name: 'Seguridad y Riesgos · Polígrafías', email: BREVO_FROM }, to: [{ email: para }], subject: asunto, htmlContent: html }) });
  if (!r.ok) throw new Error('Brevo ' + r.status + ': ' + (await r.text()).slice(0, 200));
}
app.get('/api/codigo/estado', (req, res) => res.json({ ok: true, activo: !!(BREVO_KEY && BREVO_FROM) }));
app.post('/api/codigo/enviar', async (req, res) => {
  if (!pool) return sinBD(res);
  if (!BREVO_KEY || !BREVO_FROM) return res.status(400).json({ ok: false, error: 'El ingreso con código aún no está configurado.' });
  const correo = String(req.body?.u || '').trim().toLowerCase().slice(0, 120);
  if (!CORREO_RE.test(correo)) return res.status(400).json({ ok: false, error: 'Escribe un correo válido.' });
  const k = 'cod|' + req.ip, ahora = Date.now(), reg = (intentos.get(k) || []).filter(t => ahora - t < 15 * 60e3);
  if (reg.length >= 8) return res.status(429).json({ ok: false, error: 'Demasiadas solicitudes. Espera 15 minutos.' });
  reg.push(ahora); intentos.set(k, reg);
  const gen = { ok: true, msg: 'Si el correo está registrado, te llegó un código de 6 dígitos. Revisa también la carpeta de spam.' };
  try {
    const u = (await pool.query('SELECT * FROM usuarios WHERE (lower(usuario) = $1 OR lower(correo) = $1) AND activo ORDER BY (lower(usuario) = $1) DESC LIMIT 1', [correo])).rows[0];
    if (!u || u.estado === 'pendiente') return res.json(gen);
    const prev = (await pool.query("SELECT 1 FROM codigos WHERE usuario_id = $1 AND enviado > now() - interval '60 seconds'", [u.id])).rows[0];
    if (prev) return res.status(429).json({ ok: false, error: 'Ya te enviamos un código. Espera un minuto para pedir otro.' });
    const c = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    await pool.query("INSERT INTO codigos (usuario_id, hash, expira, intentos, enviado) VALUES ($1,$2, now() + interval '10 minutes', 0, now()) ON CONFLICT (usuario_id) DO UPDATE SET hash = EXCLUDED.hash, expira = EXCLUDED.expira, intentos = 0, enviado = now()", [u.id, hashCodigo(u.id, c)]);
    await enviarCorreo(correo, 'Tu código de ingreso: ' + c,
      '<div style="font-family:Arial,sans-serif;max-width:420px;margin:auto;padding:24px;color:#0f172a"><h2 style="margin:0 0 4px;color:#0b2a5b">Seguridad y Riesgos · Polígrafías</h2><p>Hola ' + u.nombre.replace(/[<>&]/g, '') + ', tu código para ingresar es:</p><p style="font-size:34px;font-weight:700;letter-spacing:8px;margin:16px 0;color:#0b2a5b">' + c + '</p><p style="color:#64748b;font-size:13px">Vence en 10 minutos. Si no lo pediste, ignora este correo.</p></div>');
    res.json(gen);
  } catch (e) { console.error('codigo:', e.message); res.status(500).json({ ok: false, error: 'No se pudo enviar el código. Intenta de nuevo.' }); }
});
app.post('/api/codigo/verificar', async (req, res) => {
  if (!pool) return sinBD(res);
  const correo = String(req.body?.u || '').trim().toLowerCase(), c = String(req.body?.c || '').replace(/\D/g, '');
  const malo = () => res.status(400).json({ ok: false, error: 'Código incorrecto o vencido.' });
  try {
    const u = (await pool.query('SELECT * FROM usuarios WHERE (lower(usuario) = $1 OR lower(correo) = $1) AND activo ORDER BY (lower(usuario) = $1) DESC LIMIT 1', [correo])).rows[0];
    if (!u || c.length !== 6) return malo();
    const k = (await pool.query('SELECT * FROM codigos WHERE usuario_id = $1 AND expira > now()', [u.id])).rows[0];
    if (!k) return malo();
    if (k.intentos >= 5) { await pool.query('DELETE FROM codigos WHERE usuario_id = $1', [u.id]); return res.status(429).json({ ok: false, error: 'Demasiados intentos. Pide un código nuevo.' }); }
    const a = Buffer.from(hashCodigo(u.id, c)), b = Buffer.from(k.hash);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) { await pool.query('UPDATE codigos SET intentos = intentos + 1 WHERE usuario_id = $1', [u.id]); return malo(); }
    await pool.query('DELETE FROM codigos WHERE usuario_id = $1', [u.id]);
    if (u.estado === 'pendiente') return res.status(403).json({ ok: false, error: 'Tu solicitud de cuenta está pendiente de aprobación.' });
    const previo = u.ultimo_ingreso;
    await pool.query('UPDATE usuarios SET intentos = 0, bloqueado_hasta = NULL, ultimo_ingreso = now() WHERE id = $1', [u.id]);
    const token = crypto.randomBytes(32).toString('hex');
    await pool.query("INSERT INTO sesiones (token, usuario_id, expira, via) VALUES ($1, $2, now() + interval '" + HORAS_SESION + " hours', 'codigo')", [token, u.id]);
    ponerCookie(res, token, HORAS_SESION * 3600);
    u.via_sesion = 'codigo'; req._u = u;
    res.json({ ok: true, user: publico(u), bienvenida: { previo: previo || null } });
  } catch (e) { console.error('codigo verificar:', e.message); res.status(500).json({ ok: false, error: 'Error del servidor.' }); }
});

app.get('/api/yo', async (req, res) => {
  if (!pool) return sinBD(res);
  try {
    const u = await usuarioDeSesion(req);
    if (!u) return res.status(401).json({ ok: false });
    res.json({ ok: true, user: publico(u) });
  } catch (e) { res.status(500).json({ ok: false }); }
});

app.post('/api/logout', async (req, res) => {
  const t = leerCookie(req, COOKIE);
  if (t && pool) await pool.query('DELETE FROM sesiones WHERE token = $1', [t]).catch(() => {});
  ponerCookie(res, '', 0);
  res.json({ ok: true });
});

app.post('/api/clave', async (req, res) => {
  if (!pool) return sinBD(res);
  try {
    const u = await usuarioDeSesion(req);
    if (!u) return res.status(401).json({ ok: false, error: 'Tu sesión expiró. Ingresa de nuevo.' });
    if (u.sin_claves) return res.status(403).json({ ok: false, error: 'Tu cuenta no tiene permiso para cambiar contraseñas.' });
    const a = String(req.body?.a || ''), n = String(req.body?.n || '');
    let actualOk = false;
    if (u.password_hash) actualOk = await bcrypt.compare(a, u.password_hash);
    else if (u.hash_legado) actualOk = igualLegado(u.usuario, a, u.hash_legado);
    if (!actualOk) return res.status(400).json({ ok: false, error: 'La clave actual no es correcta.' });
    if (n.length < 8 || !/[a-zA-Z]/.test(n) || !/[0-9]/.test(n)) return res.status(400).json({ ok: false, error: 'La nueva clave debe tener mínimo 8 caracteres, con letras y números.' });
    if (n === a) return res.status(400).json({ ok: false, error: 'La nueva clave debe ser distinta a la actual.' });
    const hash = await bcrypt.hash(n, 12);
    await pool.query('UPDATE usuarios SET password_hash = $1, hash_legado = NULL, debe_cambiar = FALSE WHERE id = $2', [hash, u.id]);
    await pool.query('DELETE FROM sesiones WHERE usuario_id = $1 AND token <> $2', [u.id, leerCookie(req, COOKIE)]);
    res.json({ ok: true });
  } catch (e) { console.error('clave:', e.message); res.status(500).json({ ok: false, error: 'Error del servidor.' }); }
});

const TIPO_VIVO = { poli: 'Poligrafía', val: 'Validación de cuentas', arq: 'Arqueo', cgm: 'Apoyo CGM' };
// ===== Seguimiento en vivo compartido =====
const VE_TODO = ['admin', 'analista'];
const esPoli = rol => /^P\d+$/.test(rol || '');
async function conSesion(req, res) {
  if (!pool) { sinBD(res); return null; }
  const u = await usuarioDeSesion(req).catch(() => null);
  if (!u) { res.status(401).json({ ok: false, error: 'Sesión expirada.' }); return null; }
  req._u = u;
  return u;
}
function puedeEscribir(u, poli) { return VE_TODO.includes(u.rol) || (esPoli(u.rol) && u.rol === poli); }

app.get('/api/vivo', async (req, res) => {
  const u = await conSesion(req, res); if (!u) return;
  // Limpieza: una poligrafía ya cerrada no puede seguir «en ejecución»
  await pool.query("DELETE FROM en_vivo v USING pruebas p WHERE v.tipo = 'poli' AND v.id = 'poli-' || p.cid AND p.estado NOT IN ('Programada', 'En curso')").catch(() => {});
  let r;
  if (VE_TODO.includes(u.rol)) r = await pool.query('SELECT id, tipo, poligrafista, datos FROM en_vivo ORDER BY id');
  else if (esPoli(u.rol)) r = await pool.query('SELECT id, tipo, poligrafista, datos FROM en_vivo WHERE poligrafista = $1 ORDER BY id', [u.rol]);
  else return res.json({ ok: true, items: [] });
  res.json({ ok: true, items: r.rows });
});

app.put('/api/vivo/:id', async (req, res) => {
  const u = await conSesion(req, res); if (!u) return;
  const id = String(req.params.id).slice(0, 60), tipo = String(req.body?.tipo || ''), datos = req.body?.datos || {};
  const poli = String(datos.p || '');
  if (!['poli', 'val', 'arq', 'cgm'].includes(tipo) || !/^(poli|act)-\d+$/.test(id)) return res.status(400).json({ ok: false });
  if (!puedeEscribir(u, poli)) return res.status(403).json({ ok: false, error: 'Sin permiso.' });
  const prev = await pool.query('SELECT poligrafista, datos FROM en_vivo WHERE id = $1', [id]);
  if (prev.rows[0] && !puedeEscribir(u, prev.rows[0].poligrafista)) return res.status(403).json({ ok: false, error: 'Sin permiso.' });
  if (!prev.rows[0]) bitacora(req, u, 'Inició ' + (TIPO_VIVO[tipo] || tipo).toLowerCase(), [poli, datos.ciudad || datos.of || ''].filter(Boolean).join(' · '));
  await pool.query(
    `INSERT INTO en_vivo (id, tipo, poligrafista, datos, actualizado) VALUES ($1,$2,$3,$4,now())
     ON CONFLICT (id) DO UPDATE SET tipo = EXCLUDED.tipo, poligrafista = EXCLUDED.poligrafista, datos = EXCLUDED.datos, actualizado = now()`,
    [id, tipo, poli, datos]
  );
  res.json({ ok: true });
});

app.delete('/api/vivo/:id', async (req, res) => {
  const u = await conSesion(req, res); if (!u) return;
  const prev = await pool.query('SELECT poligrafista, tipo, datos FROM en_vivo WHERE id = $1', [req.params.id]);
  if (prev.rows[0] && !puedeEscribir(u, prev.rows[0].poligrafista)) return res.status(403).json({ ok: false, error: 'Sin permiso.' });
  await pool.query('DELETE FROM en_vivo WHERE id = $1', [req.params.id]);
  if (prev.rows[0]) bitacora(req, u, 'Finalizó ' + (TIPO_VIVO[prev.rows[0].tipo] || 'actividad').toLowerCase(), [prev.rows[0].poligrafista, req.query.estado || ''].filter(Boolean).join(' · '));
  res.json({ ok: true });
});

// ===== Administración de usuarios (solo administrador) =====
const ROLES_OK = ['admin', 'analista', 'poli', 'th', 'lider'];
const VISTAS_OK = ['dash', 'cal', 'diaria', 'prog', 'res', 'resumen', 'venc', 'val', 'arq', 'cgm', 'form', 'usr', 'imp', 'clave', 'perm', 'repo', 'bit'];
const CORREO_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
function claveTemporal() {
  const a = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz', d = '23456789';
  let c = '';
  for (let i = 0; i < 6; i++) c += a[crypto.randomInt(a.length)];
  for (let i = 0; i < 3; i++) c += d[crypto.randomInt(d.length)];
  return 'Poli-' + c;
}
function limpiarPermisos(p) {
  if (p == null) return null;
  if (!Array.isArray(p)) return null;
  const v = [...new Set(p.map(String).filter(x => VISTAS_OK.includes(x)))];
  if (!v.includes('clave')) v.push('clave');
  return v;
}
async function soloAdmin(req, res) {
  const u = await conSesion(req, res); if (!u) return null;
  if (u.rol !== 'admin') { res.status(403).json({ ok: false, error: 'Solo el administrador puede hacer esto.' }); return null; }
  return u;
}
// Correo corporativo alterno (opcional): permite ingresar con código cuando difiere del usuario
async function gCorreoValido(v, id) {
  const c = String(v || '').trim().toLowerCase().slice(0, 120);
  if (!c) return { v: null };
  if (!CORREO_RE.test(c)) return { error: 'El correo corporativo no es válido.' };
  const r = await pool.query('SELECT 1 FROM usuarios WHERE id <> $2 AND (lower(usuario) = $1 OR lower(correo) = $1)', [c, id || 0]);
  if (r.rows.length) return { error: 'Ese correo corporativo ya está asignado a otro usuario.' };
  return { v: c };
}
const filaUsuario = r => ({ id: r.id, sin_claves: !!r.sin_claves, estado: r.estado || 'activo', bloqueado: !!(r.bloqueado_hasta && new Date(r.bloqueado_hasta) > new Date()), ultimo: r.ultimo_ingreso, usuario: r.usuario, gcorreo: r.correo && r.correo !== r.usuario ? r.correo : '', nombre: r.nombre, rol: r.rol, zona: r.zona, telefono: r.telefono, color: r.color,
  permisos: r.permisos || null, activo: r.activo, clave: r.debe_cambiar ? 'temporal' : 'personal' });

app.get('/api/usuarios', async (req, res) => {
  const u = await soloAdmin(req, res); if (!u) return;
  const r = await pool.query('SELECT * FROM usuarios ORDER BY id');
  res.json({ ok: true, usuarios: r.rows.map(filaUsuario) });
});

app.post('/api/usuarios', async (req, res) => {
  const u = await soloAdmin(req, res); if (!u) return;
  const b = req.body || {};
  const nombre = String(b.nombre || '').trim().slice(0, 80);
  const correo = String(b.correo || '').trim().toLowerCase().slice(0, 120);
  let rol = String(b.rol || '');
  if (!nombre) return res.status(400).json({ ok: false, error: 'Escribe el nombre.' });
  if (!CORREO_RE.test(correo)) return res.status(400).json({ ok: false, error: 'El correo no es válido.' });
  if (!ROLES_OK.includes(rol)) return res.status(400).json({ ok: false, error: 'Elige un rol.' });
  const ex = await pool.query('SELECT 1 FROM usuarios WHERE usuario = $1', [correo]);
  if (ex.rows.length) return res.status(400).json({ ok: false, error: 'Ya existe un usuario con ese correo.' });
  const gc = await gCorreoValido(b.gcorreo, 0); if (gc.error) return res.status(400).json({ ok: false, error: gc.error });
  if (rol === 'poli') {
    const m = await pool.query("SELECT COALESCE(MAX(substring(rol from 2)::int), 0) AS n FROM usuarios WHERE rol ~ '^P[0-9]+$'");
    rol = 'P' + (Math.max(4, m.rows[0].n) + 1);
  }
  const clave = claveTemporal();
  const hash = await bcrypt.hash(clave, 12);
  const r = await pool.query(
    `INSERT INTO usuarios (usuario, nombre, rol, correo, zona, telefono, color, permisos, password_hash, debe_cambiar)
     VALUES ($1,$2,$3,$9,$4,$5,$6,$7,$8,TRUE) RETURNING *`,
    [correo, nombre, rol, String(b.zona || '').slice(0, 60) || null, String(b.telefono || '').slice(0, 30) || null,
     /^#[0-9a-fA-F]{6}$/.test(b.color || '') ? b.color : null, JSON.stringify(limpiarPermisos(b.permisos)), hash, gc.v || correo]
  );
  res.json({ ok: true, usuario: filaUsuario(r.rows[0]), clave });
});

app.put('/api/usuarios/:id', async (req, res) => {
  const u = await soloAdmin(req, res); if (!u) return;
  const id = +req.params.id, b = req.body || {};
  const cur = (await pool.query('SELECT * FROM usuarios WHERE id = $1', [id])).rows[0];
  if (!cur) return res.status(404).json({ ok: false, error: 'Usuario no encontrado.' });
  if (cur.id === u.id && b.activo === false) return res.status(400).json({ ok: false, error: 'No puedes desactivar tu propia cuenta.' });
  const nombre = b.nombre !== undefined ? String(b.nombre).trim().slice(0, 80) : cur.nombre;
  if (!nombre) return res.status(400).json({ ok: false, error: 'Escribe el nombre.' });
  const permisos = b.permisos !== undefined ? limpiarPermisos(b.permisos) : cur.permisos;
  let rolNuevo = cur.rol, estado = cur.estado || 'activo', activo = b.activo !== undefined ? !!b.activo : cur.activo;
  if (estado === 'pendiente' && b.aprobar) {
    if (!ROLES_OK.includes(b.rol)) return res.status(400).json({ ok: false, error: 'Elige el rol para aprobar la solicitud.' });
    rolNuevo = b.rol;
    if (rolNuevo === 'poli') {
      const m = await pool.query("SELECT COALESCE(MAX(substring(rol from 2)::int), 0) AS n FROM usuarios WHERE rol ~ '^P[0-9]+$'");
      rolNuevo = 'P' + (Math.max(4, m.rows[0].n) + 1);
    }
    estado = 'activo'; activo = true;
  }
  const gc = b.gcorreo !== undefined ? await gCorreoValido(b.gcorreo, id) : { v: cur.correo };
  if (gc.error) return res.status(400).json({ ok: false, error: gc.error });
  if (b.sin_claves !== undefined && !!b.sin_claves !== !!cur.sin_claves && u.sin_claves) return res.status(403).json({ ok: false, error: 'Tu cuenta no puede cambiar el permiso de contraseñas.' });
  if (cur.id === u.id && b.sin_claves) return res.status(400).json({ ok: false, error: 'No puedes quitarte a ti mismo el permiso de contraseñas.' });
  const sinClaves = b.sin_claves !== undefined && !u.sin_claves ? !!b.sin_claves : !!cur.sin_claves;
  if (cur.id === u.id && permisos && !permisos.includes('usr')) return res.status(400).json({ ok: false, error: 'No puedes quitarte el acceso a Usuarios.' });
  const r = await pool.query(
    `UPDATE usuarios SET nombre=$1, zona=$2, telefono=$3, color=$4, permisos=$5, activo=$6, rol=$8, estado=$9, correo=$10, sin_claves=$11 WHERE id=$7 RETURNING *`,
    [nombre, b.zona !== undefined ? (String(b.zona).slice(0, 60) || null) : cur.zona,
     b.telefono !== undefined ? (String(b.telefono).slice(0, 30) || null) : cur.telefono,
     b.color !== undefined ? (/^#[0-9a-fA-F]{6}$/.test(b.color) ? b.color : null) : cur.color,
     JSON.stringify(permisos), activo, id, rolNuevo, estado, gc.v || cur.usuario, sinClaves]
  );
  if (b.activo === false) await pool.query('DELETE FROM sesiones WHERE usuario_id = $1', [id]);
  res.json({ ok: true, usuario: filaUsuario(r.rows[0]) });
});

app.post('/api/usuarios/:id/clave', async (req, res) => {
  const u = await soloAdmin(req, res); if (!u) return;
  if (u.sin_claves) return res.status(403).json({ ok: false, error: 'Tu cuenta no tiene permiso para restablecer contraseñas.' });
  const clave = claveTemporal();
  const r = await pool.query('UPDATE usuarios SET password_hash=$1, hash_legado=NULL, debe_cambiar=TRUE, intentos=0, bloqueado_hasta=NULL WHERE id=$2 RETURNING *',
    [await bcrypt.hash(clave, 12), +req.params.id]);
  if (!r.rows[0]) return res.status(404).json({ ok: false, error: 'Usuario no encontrado.' });
  await pool.query('DELETE FROM sesiones WHERE usuario_id = $1', [+req.params.id]);
  res.json({ ok: true, usuario: filaUsuario(r.rows[0]), clave });
});

app.post('/api/usuarios/:id/desbloquear', async (req, res) => {
  const u = await soloAdmin(req, res); if (!u) return;
  const r = await pool.query('UPDATE usuarios SET intentos=0, bloqueado_hasta=NULL, activo=TRUE WHERE id=$1 AND estado <> $2 RETURNING *', [+req.params.id, 'pendiente']);
  if (!r.rows[0]) return res.status(404).json({ ok: false, error: 'Usuario no encontrado.' });
  for (const k of [...intentos.keys()]) if (k.startsWith(r.rows[0].usuario + '|')) intentos.delete(k);
  res.json({ ok: true, usuario: filaUsuario(r.rows[0]) });
});

// Equipo de poligrafistas activos (para calendarios, dashboard y listas)
app.get('/api/equipo', async (req, res) => {
  const u = await conSesion(req, res); if (!u) return;
  const r = await pool.query("SELECT rol, nombre, zona, color FROM usuarios WHERE rol ~ '^P[0-9]+$' AND activo ORDER BY substring(rol from 2)::int");
  res.json({ ok: true, poligrafistas: r.rows });
});

// Rechazar (borrar) una solicitud pendiente
app.delete('/api/usuarios/:id', async (req, res) => {
  const u = await soloAdmin(req, res); if (!u) return;
  const r = await pool.query("DELETE FROM usuarios WHERE id = $1 AND estado = 'pendiente' RETURNING id", [+req.params.id]);
  if (!r.rows[0]) return res.status(400).json({ ok: false, error: 'Solo se pueden rechazar solicitudes pendientes.' });
  res.json({ ok: true });
});

// ===== Registro y ayuda desde la pantalla de ingreso (sin sesión) =====
const limitePublico = new Map();
function permitirPublico(req, max = 5) {
  const k = req.ip, ahora = Date.now();
  const reg = (limitePublico.get(k) || []).filter(t => ahora - t < 60 * 60e3);
  if (reg.length >= max) return false;
  reg.push(ahora); limitePublico.set(k, reg); return true;
}
async function avisar(para, tipo, titulo, texto, de, datos) {
  await pool.query('INSERT INTO avisos (para, tipo, titulo, texto, de, datos) VALUES ($1,$2,$3,$4,$5,$6)',
    [para, tipo, String(titulo).slice(0, 160), String(texto || '').slice(0, 2000), de || null, datos || {}]);
}

app.post('/api/registro', async (req, res) => {
  if (!pool) return sinBD(res);
  if (!permitirPublico(req)) return res.status(429).json({ ok: false, error: 'Demasiadas solicitudes. Intenta más tarde.' });
  const b = req.body || {};
  const nombre = String(b.nombre || '').trim().slice(0, 80), correo = String(b.correo || '').trim().toLowerCase().slice(0, 120);
  const clave = String(b.clave || ''), telefono = String(b.telefono || '').trim().slice(0, 30), cargo = String(b.cargo || '').trim().slice(0, 80);
  if (!nombre) return res.status(400).json({ ok: false, error: 'Escribe tu nombre completo.' });
  if (!CORREO_RE.test(correo)) return res.status(400).json({ ok: false, error: 'El correo no es válido.' });
  if (clave.length < 8 || !/[a-zA-Z]/.test(clave) || !/[0-9]/.test(clave)) return res.status(400).json({ ok: false, error: 'La clave debe tener mínimo 8 caracteres, con letras y números.' });
  const ex = await pool.query('SELECT 1 FROM usuarios WHERE usuario = $1', [correo]);
  if (ex.rows.length) return res.status(400).json({ ok: false, error: 'Ya existe una cuenta o una solicitud con ese correo. Si olvidaste tu clave, usa «¿Problemas de acceso?».' });
  await pool.query(
    `INSERT INTO usuarios (usuario, nombre, rol, correo, telefono, password_hash, debe_cambiar, activo, estado, zona)
     VALUES ($1,$2,'pendiente',$1,$3,$4,FALSE,FALSE,'pendiente',$5)`,
    [correo, nombre, telefono || null, await bcrypt.hash(clave, 12), null]
  );
  await avisar('rol:admin', 'registro', 'Nueva solicitud de cuenta: ' + nombre,
    nombre + ' (' + correo + ')' + (cargo ? ' · ' + cargo : '') + (telefono ? ' · Tel. ' + telefono : '') + ' pidió acceso. Apruébala y asígnale un rol en Usuarios y roles.', correo, { correo });
  res.json({ ok: true });
});

app.post('/api/ayuda-acceso', async (req, res) => {
  if (!pool) return sinBD(res);
  if (!permitirPublico(req)) return res.status(429).json({ ok: false, error: 'Demasiadas solicitudes. Intenta más tarde.' });
  const b = req.body || {};
  const correo = String(b.correo || '').trim().toLowerCase().slice(0, 120), nombre = String(b.nombre || '').trim().slice(0, 80);
  const motivo = String(b.motivo || 'Otro').slice(0, 60), mensaje = String(b.mensaje || '').trim().slice(0, 1500), telefono = String(b.telefono || '').trim().slice(0, 30);
  if (!CORREO_RE.test(correo)) return res.status(400).json({ ok: false, error: 'Escribe el correo con el que ingresas.' });
  if (!mensaje && motivo === 'Otro') return res.status(400).json({ ok: false, error: 'Cuéntanos qué problema tienes.' });
  await avisar('rol:admin', 'acceso', 'Problema de acceso: ' + motivo, (nombre ? nombre + ' · ' : '') + correo + (telefono ? ' · Tel. ' + telefono : '') + (mensaje ? '\n' + mensaje : ''), correo, { correo, motivo });
  res.json({ ok: true });
});

// ===== Avisos (campana) =====
app.get('/api/avisos', async (req, res) => {
  const u = await conSesion(req, res); if (!u) return;
  const r = await pool.query("SELECT id, tipo, titulo, texto, de, datos, leido, creado FROM avisos WHERE para = $1 OR para = $2 ORDER BY creado DESC LIMIT 60",
    [u.usuario, 'rol:' + (/^P\d+$/.test(u.rol) ? 'poli' : u.rol)]);
  res.json({ ok: true, avisos: r.rows, sinLeer: r.rows.filter(x => !x.leido).length });
});
app.post('/api/avisos/leidos', async (req, res) => {
  const u = await conSesion(req, res); if (!u) return;
  const ids = Array.isArray(req.body?.ids) ? req.body.ids.map(Number).filter(Boolean) : null;
  const rolp = 'rol:' + (/^P\d+$/.test(u.rol) ? 'poli' : u.rol);
  if (ids) await pool.query('UPDATE avisos SET leido = TRUE WHERE id = ANY($1) AND (para = $2 OR para = $3)', [ids, u.usuario, rolp]);
  else await pool.query('UPDATE avisos SET leido = TRUE WHERE para = $1 OR para = $2', [u.usuario, rolp]);
  res.json({ ok: true });
});

// ===== Mensajería interna =====
app.get('/api/contactos', async (req, res) => {
  const u = await conSesion(req, res); if (!u) return;
  const r = await pool.query(`
    SELECT x.usuario, x.nombre, x.rol,
      (SELECT COUNT(*)::int FROM mensajes m WHERE m.de = x.usuario AND m.para = $1 AND NOT m.leido) AS sin_leer,
      (SELECT json_build_object('texto', m.texto, 'creado', m.creado, 'mio', m.de = $1) FROM mensajes m
        WHERE (m.de = x.usuario AND m.para = $1) OR (m.de = $1 AND m.para = x.usuario) ORDER BY m.creado DESC LIMIT 1) AS ultimo
    FROM usuarios x WHERE x.activo AND COALESCE(x.estado,'activo') = 'activo' AND x.usuario <> $1`, [u.usuario]);
  const c = r.rows.sort((a, b) => ((b.ultimo && b.ultimo.creado) || '').localeCompare((a.ultimo && a.ultimo.creado) || '') || a.nombre.localeCompare(b.nombre));
  res.json({ ok: true, contactos: c, sinLeer: c.reduce((s, x) => s + x.sin_leer, 0) });
});

app.get('/api/mensajes/:con', async (req, res) => {
  const u = await conSesion(req, res); if (!u) return;
  const con = String(req.params.con).toLowerCase();
  const r = await pool.query(`SELECT id, de, texto, creado, leido FROM (
      SELECT * FROM mensajes WHERE (de = $1 AND para = $2) OR (de = $2 AND para = $1) ORDER BY creado DESC LIMIT 200) t ORDER BY creado`, [u.usuario, con]);
  await pool.query('UPDATE mensajes SET leido = TRUE WHERE de = $1 AND para = $2 AND NOT leido', [con, u.usuario]);
  res.json({ ok: true, mensajes: r.rows.map(m => ({ id: m.id, mio: m.de === u.usuario, texto: m.texto, creado: m.creado, leido: m.leido })) });
});

app.post('/api/mensajes', async (req, res) => {
  const u = await conSesion(req, res); if (!u) return;
  const para = String(req.body?.para || '').toLowerCase(), texto = String(req.body?.texto || '').trim().slice(0, 2000);
  if (!texto) return res.status(400).json({ ok: false, error: 'Escribe un mensaje.' });
  const d = await pool.query("SELECT 1 FROM usuarios WHERE usuario = $1 AND activo AND COALESCE(estado,'activo') = 'activo'", [para]);
  if (!d.rows.length || para === u.usuario) return res.status(400).json({ ok: false, error: 'Destinatario no válido.' });
  const r = await pool.query('INSERT INTO mensajes (de, para, texto) VALUES ($1,$2,$3) RETURNING id, creado', [u.usuario, para, texto]);
  res.json({ ok: true, id: r.rows[0].id, creado: r.rows[0].creado });
});

// Soporte: datos de contacto del administrador y solicitud de ayuda desde el asistente
app.get('/api/soporte', async (req, res) => {
  const u = await conSesion(req, res); if (!u) return;
  const r = await pool.query("SELECT usuario, nombre, telefono FROM usuarios WHERE rol = 'admin' AND activo ORDER BY id");
  res.json({ ok: true, admins: r.rows });
});
app.post('/api/ayuda', async (req, res) => {
  const u = await conSesion(req, res); if (!u) return;
  const texto = String(req.body?.texto || '').trim().slice(0, 1500);
  if (!texto) return res.status(400).json({ ok: false, error: 'Cuéntale al administrador en qué necesitas ayuda.' });
  const ad = await pool.query("SELECT usuario FROM usuarios WHERE rol = 'admin' AND activo AND usuario <> $1", [u.usuario]);
  for (const a of ad.rows) await pool.query('INSERT INTO mensajes (de, para, texto) VALUES ($1,$2,$3)', [u.usuario, a.usuario, '🛟 Solicitud de ayuda: ' + texto]);
  await avisar('rol:admin', 'ayuda', u.nombre + ' pide ayuda', texto, u.usuario, { correo: u.usuario });
  res.json({ ok: true });
});

// ===== Permisos y ausencias (compensatorios, citas médicas, vacaciones, otros) =====
const TIPOS_PERMISO = ['Compensatorio', 'Cita médica', 'Vacaciones', 'Calamidad doméstica', 'Licencia', 'Capacitación', 'Otro'];
const FECHA_RE = /^\d{4}-\d{2}-\d{2}$/, HORA_RE = /^\d{2}:\d{2}/;
const filaPermiso = r => ({ id: r.id, usuario: r.usuario, nombre: r.nombre, rol: r.rol, tipo: r.tipo, desde: r.desde_t, hasta: r.hasta_t,
  hora_ini: r.hora_ini ? String(r.hora_ini).slice(0, 5) : null, hora_fin: r.hora_fin ? String(r.hora_fin).slice(0, 5) : null,
  motivo: r.motivo, estado: r.estado, respuesta: r.respuesta, resuelto_por: r.resuelto_por, creado: r.creado });
const SQL_PERMISOS = `SELECT p.*, to_char(p.desde,'YYYY-MM-DD') AS desde_t, to_char(p.hasta,'YYYY-MM-DD') AS hasta_t, u.nombre, u.rol
  FROM permisos p LEFT JOIN usuarios u ON u.usuario = p.usuario`;

app.get('/api/permisos', async (req, res) => {
  const u = await conSesion(req, res); if (!u) return;
  const r = u.rol === 'admin'
    ? await pool.query(SQL_PERMISOS + ' ORDER BY (p.estado = $1) DESC, p.desde DESC LIMIT 300', ['pendiente'])
    : await pool.query(SQL_PERMISOS + ' WHERE p.usuario = $1 ORDER BY p.desde DESC LIMIT 200', [u.usuario]);
  res.json({ ok: true, permisos: r.rows.map(filaPermiso), tipos: TIPOS_PERMISO });
});

// Permisos aprobados de poligrafistas: bloquean la agenda
app.get('/api/permisos/agenda', async (req, res) => {
  const u = await conSesion(req, res); if (!u) return;
  const r = await pool.query(SQL_PERMISOS + " WHERE p.estado = 'aprobado' AND p.hasta >= CURRENT_DATE - 60 AND u.rol ~ '^P[0-9]+$'");
  res.json({ ok: true, permisos: r.rows.map(x => { const f = filaPermiso(x); delete f.motivo; delete f.respuesta; return f; }) });
});

app.post('/api/permisos', async (req, res) => {
  const u = await conSesion(req, res); if (!u) return;
  const b = req.body || {};
  const para = u.rol === 'admin' && b.usuario ? String(b.usuario).toLowerCase() : u.usuario;
  const tipo = TIPOS_PERMISO.includes(b.tipo) ? b.tipo : null;
  const desde = String(b.desde || ''), hasta = String(b.hasta || b.desde || '');
  const hi = HORA_RE.test(b.hora_ini || '') ? b.hora_ini.slice(0, 5) : null, hf = HORA_RE.test(b.hora_fin || '') ? b.hora_fin.slice(0, 5) : null;
  if (!tipo) return res.status(400).json({ ok: false, error: 'Elige el tipo de permiso.' });
  if (!FECHA_RE.test(desde) || !FECHA_RE.test(hasta) || hasta < desde) return res.status(400).json({ ok: false, error: 'Revisa las fechas (la final no puede ser antes de la inicial).' });
  if ((hi || hf) && (!hi || !hf || hf <= hi)) return res.status(400).json({ ok: false, error: 'Si es por horas, pon hora de inicio y de fin (la de fin después).' });
  if ((hi || hf) && desde !== hasta) return res.status(400).json({ ok: false, error: 'Un permiso por horas debe ser de un solo día.' });
  const dest = (await pool.query("SELECT usuario, nombre FROM usuarios WHERE usuario = $1 AND activo", [para])).rows[0];
  if (!dest) return res.status(400).json({ ok: false, error: 'Funcionario no válido.' });
  const directo = u.rol === 'admin';
  const r = await pool.query(
    `INSERT INTO permisos (usuario, tipo, desde, hasta, hora_ini, hora_fin, motivo, estado, resuelto_por, resuelto)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`,
    [para, tipo, desde, hasta, hi, hf, String(b.motivo || '').trim().slice(0, 600) || null, directo ? 'aprobado' : 'pendiente',
     directo ? u.nombre : null, directo ? new Date() : null]);
  const rango = desde === hasta ? desde + (hi ? ' de ' + hi + ' a ' + hf : '') : desde + ' a ' + hasta;
  if (directo) { if (para !== u.usuario) await avisar(para, 'permiso', 'Permiso registrado: ' + tipo, 'El administrador registró tu permiso (' + rango + ').', u.usuario, { id: r.rows[0].id }); }
  else await avisar('rol:admin', 'permiso', 'Solicitud de permiso: ' + dest.nombre, tipo + ' · ' + rango + (b.motivo ? '\n' + String(b.motivo).slice(0, 200) : ''), u.usuario, { id: r.rows[0].id });
  res.json({ ok: true, id: r.rows[0].id, estado: directo ? 'aprobado' : 'pendiente' });
});

app.post('/api/permisos/:id/resolver', async (req, res) => {
  const u = await soloAdmin(req, res); if (!u) return;
  const estado = req.body?.estado === 'aprobado' ? 'aprobado' : req.body?.estado === 'rechazado' ? 'rechazado' : null;
  if (!estado) return res.status(400).json({ ok: false });
  const r = await pool.query(`UPDATE permisos SET estado=$1, respuesta=$2, resuelto_por=$3, resuelto=now() WHERE id=$4 AND estado='pendiente'
    RETURNING usuario, tipo, to_char(desde,'YYYY-MM-DD') AS d, to_char(hasta,'YYYY-MM-DD') AS h`,
    [estado, String(req.body?.respuesta || '').slice(0, 400) || null, u.nombre, +req.params.id]);
  const p = r.rows[0]; if (!p) return res.status(400).json({ ok: false, error: 'Ese permiso ya fue resuelto.' });
  await avisar(p.usuario, 'permiso', 'Permiso ' + estado + ': ' + p.tipo, (p.d === p.h ? p.d : p.d + ' a ' + p.h) + (req.body?.respuesta ? '\n' + String(req.body.respuesta).slice(0, 300) : ''), u.usuario, { id: +req.params.id });
  res.json({ ok: true });
});

app.post('/api/permisos/:id/cancelar', async (req, res) => {
  const u = await conSesion(req, res); if (!u) return;
  const r = await pool.query("UPDATE permisos SET estado='cancelado' WHERE id=$1 AND (usuario=$2 OR $3) AND estado IN ('pendiente','aprobado') AND hasta >= CURRENT_DATE RETURNING id",
    [+req.params.id, u.usuario, u.rol === 'admin']);
  if (!r.rows[0]) return res.status(400).json({ ok: false, error: 'No se puede cancelar ese permiso.' });
  res.json({ ok: true });
});

// ===== Datos de planta (columnas de la base de vencimientos: CONTRATO, REGIONAL, CLIENTE, C.C, ...) =====
const LEEN_PLANTA = r => ['admin', 'analista', 'th'].includes(r) || /^P\d+$/.test(r || '');
app.get('/api/planta', async (req, res) => {
  const u = await conSesion(req, res); if (!u) return;
  if (!LEEN_PLANTA(u.rol)) return res.json({ ok: true, planta: {}, total: 0 });
  const r = await pool.query('SELECT cedula, datos FROM planta');
  const m = {}; r.rows.forEach(x => { m[x.cedula] = x.datos; });
  const t = await pool.query('SELECT max(actualizado) AS a FROM planta');
  res.json({ ok: true, planta: m, total: r.rows.length, actualizado: t.rows[0].a });
});
app.post('/api/planta', express.json({ limit: '8mb' }), async (req, res) => {
  const u = await conSesion(req, res); if (!u) return;
  if (!['admin', 'analista'].includes(u.rol)) return res.status(403).json({ ok: false, error: 'Solo administrador y analista pueden importar.' });
  const filas = Array.isArray(req.body?.filas) ? req.body.filas : [];
  const limpias = [];
  for (const f of filas.slice(0, 5000)) {
    const c = String(f?.c || '').replace(/\D/g, '').replace(/^0+/, '').slice(0, 20);
    if (!c || typeof f.d !== 'object' || !f.d) continue;
    const d = {};
    for (const [k, v] of Object.entries(f.d).slice(0, 70)) if (v !== null && v !== '' && v !== undefined) d[String(k).slice(0, 60)] = String(v).slice(0, 200);
    limpias.push({ c, d });
  }
  if (req.body?.reemplazar) await pool.query('DELETE FROM planta');
  if (limpias.length) await pool.query(
    `INSERT INTO planta (cedula, datos, actualizado) SELECT x.c, x.d, now() FROM jsonb_to_recordset($1::jsonb) AS x(c text, d jsonb)
     ON CONFLICT (cedula) DO UPDATE SET datos = EXCLUDED.datos, actualizado = now()`, [JSON.stringify(limpias)]);
  res.json({ ok: true, guardados: limpias.length });
});
app.delete('/api/planta', async (req, res) => {
  const u = await conSesion(req, res); if (!u) return;
  if (!['admin', 'analista'].includes(u.rol)) return res.status(403).json({ ok: false });
  await pool.query('DELETE FROM planta');
  res.json({ ok: true });
});

// ===== Base de resultados por poligrafista (HISTORICO / AUSENTISMO) =====
// ===== Historial del evaluado (todas las bases, por cédula) =====
app.get('/api/historial', async (req, res) => {
  const u = await conSesion(req, res); if (!u) return;
  const cc = String(req.query.cc || '').replace(/\D/g, '').slice(0, 15);
  if (cc.length < 5) return res.status(400).json({ ok: false, error: 'Cédula no válida.' });
  const q = `SELECT datos, 'app' AS o FROM pruebas WHERE regexp_replace(coalesce(cc,''), '\\D', '', 'g') = $1
             UNION ALL SELECT datos, 'excel' AS o FROM resultados WHERE origen = 'excel' AND regexp_replace(coalesce(cc,''), '\\D', '', 'g') = $1`;
  const r = await pool.query(q, [cc]);
  const vistos = new Set(), lista = [];
  for (const row of r.rows.sort((a, b) => (a.o === 'app' ? -1 : 1) - (b.o === 'app' ? -1 : 1))) {
    const d = row.datos || {}, k = [d.f, String(d.t || '').toLowerCase(), d.p].join('|');
    if (vistos.has(k)) continue; vistos.add(k);
    const lim = u.rol === 'lider' || (u.rol === 'th' && d.t !== 'Preempleo');
    lista.push({ f: d.f, h: d.h, t: d.t, p: d.p, n: d.n, e: d.e, cargo: d.cargo, ciudad: d.ciudad,
      r: lim ? '' : d.r || '', adm: lim ? '' : d.adm || '', obs: lim ? '' : d.obs || '', inf: lim ? '' : (d.drive && d.drive.inf) || d.pdf || '', oculto: lim });
  }
  lista.sort((a, b) => String(b.f || '').localeCompare(String(a.f || '')));
  bitacora(req, u, 'Consultó historial de evaluado', 'C.C. ' + cc + ' · ' + lista.length + ' registros');
  res.json({ ok: true, cc, pruebas: lista });
});

app.get('/api/resultados', async (req, res) => {
  const u = await conSesion(req, res); if (!u) return;
  let r;
  if (['admin', 'analista'].includes(u.rol)) r = await pool.query("SELECT datos FROM resultados WHERE origen = 'excel' ORDER BY fecha");
  else if (/^P\d+$/.test(u.rol)) r = await pool.query("SELECT datos FROM resultados WHERE origen = 'excel' AND poligrafista = $1 ORDER BY fecha", [u.rol]);
  else if (u.rol === 'th') r = await pool.query("SELECT datos FROM resultados WHERE origen = 'excel' AND datos->>'t' = 'Preempleo' ORDER BY fecha");
  else return res.json({ ok: true, pruebas: [], resumen: [] });
  const s = await pool.query("SELECT poligrafista, count(*)::int AS n, min(fecha) AS desde, max(fecha) AS hasta, max(creado) AS cargado FROM resultados WHERE origen = 'excel' GROUP BY poligrafista");
  // Última prueba realizada por cédula (sin resultado ni detalles) para que todos calculen igual los vencimientos
  const ul = await pool.query(`SELECT DISTINCT ON (cc) cc, to_char(fecha,'YYYY-MM-DD') AS f, datos->>'t' AS t, poligrafista AS p
    FROM resultados WHERE origen = 'excel' AND datos->>'e' = 'Realizada' ORDER BY cc, fecha DESC`);
  res.json({ ok: true, pruebas: r.rows.map(x => x.datos), resumen: s.rows, ultimas: ul.rows });
});
app.post('/api/resultados/importar', express.json({ limit: '10mb' }), async (req, res) => {
  const u = await conSesion(req, res); if (!u) return;
  const p = String(req.body?.poligrafista || '');
  if (!/^P\d+$/.test(p)) return res.status(400).json({ ok: false, error: 'Poligrafista no válido.' });
  const puede = ['admin', 'analista'].includes(u.rol) || u.rol === p;
  if (!puede) return res.status(403).json({ ok: false, error: 'Solo puedes cargar tu propia base de resultados.' });
  const filas = (Array.isArray(req.body?.filas) ? req.body.filas : []).slice(0, 20000).filter(x => x && typeof x === 'object' && /^\d{4}-\d{2}-\d{2}$/.test(x.f || ''));
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    if (req.body?.reemplazar) await client.query("DELETE FROM resultados WHERE origen = 'excel' AND poligrafista = $1", [p]);
    const limpias = filas.map(x => {
      const d = {};
      for (const k of ['n', 'doc', 'cargo', 'ciudad', 'f', 'h', 'hf', 't', 'e', 'r', 'adm', 'obs', 're', 'pdf', 'src', 'l'])
        if (x[k] !== undefined && x[k] !== null) d[k] = String(x[k]).slice(0, 600);
      d.p = p; d.imp = 1;
      return { p, cc: d.doc || '', r: d.r || d.e || '', f: d.f, d };
    });
    if (limpias.length) await client.query(
      `INSERT INTO resultados (poligrafista, cc, resultado, fecha, datos, origen)
       SELECT x.p, x.cc, x.r, x.f::date, x.d, 'excel' FROM jsonb_to_recordset($1::jsonb) AS x(p text, cc text, r text, f text, d jsonb)`,
      [JSON.stringify(limpias)]);
    await client.query('COMMIT');
    res.json({ ok: true, guardados: limpias.length });
  } catch (e) { await client.query('ROLLBACK').catch(() => {}); console.error('resultados:', e.message); res.status(500).json({ ok: false, error: 'No se pudieron guardar los resultados.' }); }
  finally { client.release(); }
});

// ===== Repositorios en Google Drive (carpetas para PDF, gráficas y evidencias) =====
const CAT_REPO = ['PDF Control', 'PDF Preempleo', 'Gráficas del polígrafo', 'Autorizaciones firmadas', 'Evidencias (validaciones, arqueos, CGM)', 'Formatos', 'Otro'];
const URL_DRIVE = /^https:\/\/(drive|docs)\.google\.com\//i;
app.get('/api/repositorios', async (req, res) => {
  const u = await conSesion(req, res); if (!u) return;
  const r = /^P\d+$/.test(u.rol)
    ? await pool.query('SELECT * FROM repositorios WHERE poligrafista IS NULL OR poligrafista = $1 ORDER BY categoria, nombre', [u.rol])
    : u.rol === 'lider' ? { rows: [] }
    : await pool.query('SELECT * FROM repositorios ORDER BY categoria, poligrafista NULLS FIRST, nombre');
  res.json({ ok: true, repositorios: r.rows, categorias: CAT_REPO });
});
function datosRepo(b) {
  const nombre = String(b.nombre || '').trim().slice(0, 100), categoria = CAT_REPO.includes(b.categoria) ? b.categoria : null;
  const url = String(b.url || '').trim().slice(0, 500), p = /^P\d+$/.test(b.poligrafista || '') ? b.poligrafista : null;
  if (!nombre) return { error: 'Escribe un nombre para la carpeta.' };
  if (!categoria) return { error: 'Elige la categoría.' };
  if (!URL_DRIVE.test(url)) return { error: 'Pega el enlace de la carpeta de Google Drive (empieza por https://drive.google.com/).' };
  return { nombre, categoria, url, p };
}
app.post('/api/repositorios', async (req, res) => {
  const u = await soloAdmin(req, res); if (!u) return;
  const d = datosRepo(req.body || {}); if (d.error) return res.status(400).json({ ok: false, error: d.error });
  const r = await pool.query('INSERT INTO repositorios (nombre, categoria, url, poligrafista) VALUES ($1,$2,$3,$4) RETURNING id', [d.nombre, d.categoria, d.url, d.p]);
  res.json({ ok: true, id: r.rows[0].id });
});
app.put('/api/repositorios/:id', async (req, res) => {
  const u = await soloAdmin(req, res); if (!u) return;
  const d = datosRepo(req.body || {}); if (d.error) return res.status(400).json({ ok: false, error: d.error });
  await pool.query('UPDATE repositorios SET nombre=$1, categoria=$2, url=$3, poligrafista=$4 WHERE id=$5', [d.nombre, d.categoria, d.url, d.p, +req.params.id]);
  res.json({ ok: true });
});
app.delete('/api/repositorios/:id', async (req, res) => {
  const u = await soloAdmin(req, res); if (!u) return;
  await pool.query('DELETE FROM repositorios WHERE id=$1', [+req.params.id]);
  res.json({ ok: true });
});

// ===== Sin conexión con Google Workspace =====
// La app no se conecta a Google (ni Drive, ni Chat, ni ingreso con Google). Los archivos se suben
// directamente en Drive por cada usuario y en la app solo se guarda el enlace.

// ===== Pruebas agendadas desde la app (compartidas entre todos los usuarios) =====
const CAMPOS_BLOQ = ['r', 'e', 'adm', 'obs', 'f', 'h', 'p', 'n', 'doc', 't'];
const NOM_CAMPO = { r: 'Resultado', e: 'Estado', adm: 'Admisiones', obs: 'Observaciones', f: 'Fecha', h: 'Hora', p: 'Poligrafista', n: 'Evaluado', doc: 'Documento', t: 'Tipo' };
const CAMPOS_AGENDA = ['id', 'f', 'h', 'n', 'doc', 'cargo', 't', 'p', 'ciudad', 'of', 'oficina', 'l', 'lm', 'e', 'app', 'u'];
app.get('/api/pruebas', async (req, res) => {
  const u = await conSesion(req, res); if (!u) return;
  const base = 'SELECT datos FROM pruebas WHERE cid IS NOT NULL';
  let r;
  if (['admin', 'analista'].includes(u.rol)) r = await pool.query(base + ' ORDER BY fecha');
  else if (/^P\d+$/.test(u.rol)) r = await pool.query(base + ' AND poligrafista = $1 ORDER BY fecha', [u.rol]);
  else if (u.rol === 'th') r = await pool.query(base + " AND (tipo = 'Preempleo' OR creado_por = $1) ORDER BY fecha", [u.usuario]);
  else if (u.rol === 'lider') r = await pool.query(base + " AND (datos->>'lm') ILIKE $1 ORDER BY fecha", ['%' + u.usuario + '%']);
  else return res.json({ ok: true, pruebas: [] });
  // Mínimo acceso: el líder solo ve la agenda (sin resultado, admisiones, observaciones ni informes);
  // Talento Humano solo ve resultados de preempleo.
  const sinResultado = d => { const o = {}; for (const k of CAMPOS_AGENDA) if (d[k] !== undefined) o[k] = d[k]; o.r = ''; o.adm = ''; o.obs = ''; if (o.e && !['Programada', 'En curso', 'Realizada', 'Reprogramar', 'Ausente', 'Suspendida'].includes(o.e)) delete o.e; return o; };
  res.json({ ok: true, pruebas: r.rows.map(x => u.rol === 'lider' || (u.rol === 'th' && x.datos.t !== 'Preempleo') ? sinResultado(x.datos) : x.datos) });
});
app.post('/api/pruebas/guardar', async (req, res) => {
  const u = await conSesion(req, res); if (!u) return;
  const lista = (Array.isArray(req.body?.pruebas) ? req.body.pruebas : []).slice(0, 200);
  let ok = 0; const rechazadas = [];
  for (const x of lista) {
    const cid = Number(x && x.id); if (!Number.isSafeInteger(cid) || cid <= 0) continue;
    const p = String(x.p || ''), f = /^\d{4}-\d{2}-\d{2}$/.test(x.f || '') ? x.f : null;
    const prev = (await pool.query('SELECT poligrafista, creado_por, tipo, estado, fecha::text AS f, hora::text AS h, evaluado, datos FROM pruebas WHERE cid = $1', [cid])).rows[0];
    const puede = ['admin', 'analista'].includes(u.rol) || (/^P\d+$/.test(u.rol) && p === u.rol && (!prev || prev.poligrafista === u.rol))
      || (u.rol === 'th' && (!prev || prev.tipo === 'Preempleo'));
    if (!puede) continue;
    const d = {};
    for (const [k, v] of Object.entries(x)) if (k !== 'corr' && k !== 'hist' && JSON.stringify(v).length < 4000) d[k] = v;
    // Integridad: una prueba realizada queda bloqueada; solo el administrador la corrige, con motivo, y queda historial
    const pd = (prev && prev.datos) || {};
    if (pd.hist) d.hist = pd.hist;
    if (prev && prev.estado === 'Realizada') {
      const val = v => v === undefined || v === null ? '' : typeof v === 'object' ? JSON.stringify(v) : String(v);
      const cambios = CAMPOS_BLOQ.filter(k => val(x[k]) !== val(pd[k]));
      if (cambios.length) {
        const motivo = String((x.corr && x.corr.motivo) || '').trim().slice(0, 300);
        if (u.rol !== 'admin' || motivo.length < 10) {
          rechazadas.push(cid);
          bitacora(req, u, 'Intento de modificar prueba cerrada', [pd.t, pd.n, pd.f, cambios.join(', ')].filter(Boolean).join(' · '), 'fallido');
          continue;
        }
        const det = cambios.map(k => ({ campo: NOM_CAMPO[k] || k, antes: val(pd[k]).slice(0, 300), despues: val(x[k]).slice(0, 300) }));
        d.hist = (Array.isArray(pd.hist) ? pd.hist : []).concat({ at: new Date().toISOString(), por: u.nombre, usuario: u.usuario, motivo, cambios: det }).slice(-30);
        bitacora(req, u, 'Corrigió prueba cerrada', [pd.t, pd.n, pd.f].filter(Boolean).join(' · ') + ' · ' + det.map(c => c.campo + ': «' + c.antes.slice(0, 40) + '» → «' + c.despues.slice(0, 40) + '»').join('; ') + ' · Motivo: ' + motivo);
      }
    }
    d.app = 1; d.u = Date.now();
    await pool.query(
      `INSERT INTO pruebas (cid, fecha, hora, poligrafista, evaluado, cc, tipo, estado, datos, creado_por, actualizado)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,now())
       ON CONFLICT (cid) DO UPDATE SET fecha=$2, hora=$3, poligrafista=$4, evaluado=$5, cc=$6, tipo=$7, estado=$8, datos=$9, actualizado=now()`,
      [cid, f, /^\d{1,2}:\d{2}/.test(x.h || '') ? x.h : null, p, String(x.n || '').slice(0, 120), String(x.doc || '').slice(0, 30), String(x.t || '').slice(0, 40), String(x.e || '').slice(0, 30), d, u.usuario]);
    ok++;
    if (!['Programada', 'En curso'].includes(String(x.e || ''))) await pool.query('DELETE FROM en_vivo WHERE id = $1', ['poli-' + cid]).catch(() => {});
    const est = String(x.e || ''), hh = String(x.h || '').slice(0, 5), det = [x.t, x.n, f, hh, p].filter(Boolean).join(' · ');
    if (!prev) bitacora(req, u, 'Agendó prueba', det);
    else if (est && est !== prev.estado) bitacora(req, u, 'Cambió estado de prueba a «' + est + '»', det);
    else if (f !== prev.f || hh !== String(prev.h || '').slice(0, 5) || p !== prev.poligrafista) bitacora(req, u, 'Reprogramó prueba', det);
    // Política de inasistencia: 2 o más ausencias del mismo funcionario en 12 meses → aviso al administrador y analista
    if (est === 'Ausente' && (!prev || prev.estado !== 'Ausente') && String(x.doc || '').replace(/\D/g, '')) {
      const cc = String(x.doc).replace(/\D/g, '');
      const n = (await pool.query("SELECT count(*)::int AS n FROM pruebas WHERE estado = 'Ausente' AND regexp_replace(cc, '\\D', '', 'g') = $1 AND fecha >= current_date - 365", [cc]).catch(() => ({ rows: [{ n: 0 }] }))).rows[0].n;
      if (n >= 2) {
        const t = 'Inasistencia reiterada: ' + String(x.n || '').slice(0, 80);
        const tx = 'C.C. ' + cc + ' no asistió a la prueba ' + n + ' veces en los últimos 12 meses' + (x.l ? '. Líder: ' + String(x.l).slice(0, 80) : '') + '. Según la política, escala con su líder y la jefatura.';
        for (const r of ['rol:admin', 'rol:analista']) await avisar(r, 'alerta', t, tx, u.usuario, { cc }).catch(() => {});
        bitacora(req, u, 'Alerta de inasistencia reiterada', 'C.C. ' + cc + ' · ' + n + ' ausencias');
      }
    }
  }
  res.json({ ok: true, guardadas: ok, rechazadas });
});

app.get('/api/bitacora', async (req, res) => {
  const u = await soloAdmin(req, res); if (!u) return;
  if (Array.isArray(u.permisos) && !u.permisos.includes('bit') && !u.permisos.includes('usr')) return res.status(403).json({ ok: false, error: 'No tienes acceso a la bitácora.' });
  const q = req.query, w = [], v = [];
  if (/^\d{4}-\d{2}-\d{2}$/.test(q.desde || '')) { v.push(q.desde); w.push(`fecha >= ($${v.length}::date::timestamp AT TIME ZONE 'America/Bogota')`); }
  if (/^\d{4}-\d{2}-\d{2}$/.test(q.hasta || '')) { v.push(q.hasta); w.push(`fecha < (($${v.length}::date + 1)::timestamp AT TIME ZONE 'America/Bogota')`); }
  if (q.usuario) { v.push(String(q.usuario).toLowerCase()); w.push(`lower(usuario) = $${v.length}`); }
  if (q.tipo === 'ingresos') w.push("(accion ILIKE 'ingreso%' OR accion ILIKE '%ingreso%' OR accion ILIKE 'cerró sesión' OR accion ILIKE 'cuenta bloqueada%')");
  if (q.tipo === 'fallidos') w.push("resultado = 'fallido'");
  if (q.texto) { v.push('%' + String(q.texto).slice(0, 60) + '%'); w.push(`(accion ILIKE $${v.length} OR detalle ILIKE $${v.length} OR nombre ILIKE $${v.length} OR usuario ILIKE $${v.length})`); }
  const lim = Math.min(Math.max(+q.limite || 300, 1), 5000);
  const r = await pool.query(`SELECT id, fecha, usuario, nombre, rol, accion, detalle, resultado, ip, agente FROM bitacora ${w.length ? 'WHERE ' + w.join(' AND ') : ''} ORDER BY fecha DESC LIMIT ${lim}`, v);
  res.json({ ok: true, filas: r.rows });
});

app.use(express.static(__dirname, { index: 'index.html', extensions: ['html'] }));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// Red de seguridad: un error inesperado en una petición no debe tumbar el servidor
process.on('unhandledRejection', e => console.error('Error no controlado:', e && e.message ? e.message : e));
initDB().finally(() => app.listen(PORT, () => console.log('Servidor en puerto ' + PORT)));
