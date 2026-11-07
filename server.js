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
ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS intentos INTEGER DEFAULT 0;
ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS bloqueado_hasta TIMESTAMPTZ;
ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS ultimo_ingreso TIMESTAMPTZ;
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
    // Nombres reales de los poligrafistas iniciales (solo si conservan el nombre genérico)
    for (const [n, real] of [[1, 'Durley Wilches'], [2, 'Carlos Castaño'], [3, 'Luis Vanegas'], [4, 'José Barbosa']]) {
      await pool.query('UPDATE usuarios SET nombre = $1 WHERE usuario = $2 AND nombre = $3', [real, 'poligrafista' + n + '@suitepoligrafia.example', 'Poligrafista ' + n]);
    }
    await pool.query('DELETE FROM sesiones WHERE expira < now()');
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
app.use((req, res, next) => req.path === '/api/planta' ? next() : express.json({ limit: '1mb' })(req, res, next));

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
const publico = u => ({ usuario: u.usuario, nombre: u.nombre, rol: u.rol, debe_cambiar: u.debe_cambiar, permisos: u.permisos || null });

async function usuarioDeSesion(req) {
  const t = leerCookie(req, COOKIE);
  if (!t || !pool) return null;
  const r = await pool.query(
    'SELECT u.* FROM sesiones s JOIN usuarios u ON u.id = s.usuario_id WHERE s.token = $1 AND s.expira > now() AND u.activo',
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
    ponerCookie(res, token, HORAS_SESION * 3600);
    res.json({ ok: true, user: publico(u), bienvenida: { previo: u.previo || null } });
  } catch (e) { console.error('login:', e.message); res.status(500).json({ ok: false, error: 'Error del servidor.' }); }
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

// ===== Seguimiento en vivo compartido =====
const VE_TODO = ['admin', 'analista'];
const esPoli = rol => /^P\d+$/.test(rol || '');
async function conSesion(req, res) {
  if (!pool) { sinBD(res); return null; }
  const u = await usuarioDeSesion(req).catch(() => null);
  if (!u) { res.status(401).json({ ok: false, error: 'Sesión expirada.' }); return null; }
  return u;
}
function puedeEscribir(u, poli) { return VE_TODO.includes(u.rol) || (esPoli(u.rol) && u.rol === poli); }

app.get('/api/vivo', async (req, res) => {
  const u = await conSesion(req, res); if (!u) return;
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
  const prev = await pool.query('SELECT poligrafista FROM en_vivo WHERE id = $1', [id]);
  if (prev.rows[0] && !puedeEscribir(u, prev.rows[0].poligrafista)) return res.status(403).json({ ok: false, error: 'Sin permiso.' });
  await pool.query(
    `INSERT INTO en_vivo (id, tipo, poligrafista, datos, actualizado) VALUES ($1,$2,$3,$4,now())
     ON CONFLICT (id) DO UPDATE SET tipo = EXCLUDED.tipo, poligrafista = EXCLUDED.poligrafista, datos = EXCLUDED.datos, actualizado = now()`,
    [id, tipo, poli, datos]
  );
  res.json({ ok: true });
});

app.delete('/api/vivo/:id', async (req, res) => {
  const u = await conSesion(req, res); if (!u) return;
  const prev = await pool.query('SELECT poligrafista FROM en_vivo WHERE id = $1', [req.params.id]);
  if (prev.rows[0] && !puedeEscribir(u, prev.rows[0].poligrafista)) return res.status(403).json({ ok: false, error: 'Sin permiso.' });
  await pool.query('DELETE FROM en_vivo WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
});

// ===== Administración de usuarios (solo administrador) =====
const ROLES_OK = ['admin', 'analista', 'poli', 'th', 'lider'];
const VISTAS_OK = ['dash', 'cal', 'diaria', 'prog', 'res', 'resumen', 'venc', 'val', 'arq', 'cgm', 'form', 'usr', 'imp', 'clave', 'perm'];
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
const filaUsuario = r => ({ id: r.id, estado: r.estado || 'activo', bloqueado: !!(r.bloqueado_hasta && new Date(r.bloqueado_hasta) > new Date()), ultimo: r.ultimo_ingreso, usuario: r.usuario, nombre: r.nombre, rol: r.rol, zona: r.zona, telefono: r.telefono, color: r.color,
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
  if (rol === 'poli') {
    const m = await pool.query("SELECT COALESCE(MAX(substring(rol from 2)::int), 0) AS n FROM usuarios WHERE rol ~ '^P[0-9]+$'");
    rol = 'P' + (Math.max(4, m.rows[0].n) + 1);
  }
  const clave = claveTemporal();
  const hash = await bcrypt.hash(clave, 12);
  const r = await pool.query(
    `INSERT INTO usuarios (usuario, nombre, rol, correo, zona, telefono, color, permisos, password_hash, debe_cambiar)
     VALUES ($1,$2,$3,$1,$4,$5,$6,$7,$8,TRUE) RETURNING *`,
    [correo, nombre, rol, String(b.zona || '').slice(0, 60) || null, String(b.telefono || '').slice(0, 30) || null,
     /^#[0-9a-fA-F]{6}$/.test(b.color || '') ? b.color : null, JSON.stringify(limpiarPermisos(b.permisos)), hash]
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
  if (cur.id === u.id && permisos && !permisos.includes('usr')) return res.status(400).json({ ok: false, error: 'No puedes quitarte el acceso a Usuarios.' });
  const r = await pool.query(
    `UPDATE usuarios SET nombre=$1, zona=$2, telefono=$3, color=$4, permisos=$5, activo=$6, rol=$8, estado=$9 WHERE id=$7 RETURNING *`,
    [nombre, b.zona !== undefined ? (String(b.zona).slice(0, 60) || null) : cur.zona,
     b.telefono !== undefined ? (String(b.telefono).slice(0, 30) || null) : cur.telefono,
     b.color !== undefined ? (/^#[0-9a-fA-F]{6}$/.test(b.color) ? b.color : null) : cur.color,
     JSON.stringify(permisos), activo, id, rolNuevo, estado]
  );
  if (b.activo === false) await pool.query('DELETE FROM sesiones WHERE usuario_id = $1', [id]);
  res.json({ ok: true, usuario: filaUsuario(r.rows[0]) });
});

app.post('/api/usuarios/:id/clave', async (req, res) => {
  const u = await soloAdmin(req, res); if (!u) return;
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
    for (const [k, v] of Object.entries(f.d).slice(0, 40)) if (v !== null && v !== '' && v !== undefined) d[String(k).slice(0, 60)] = String(v).slice(0, 200);
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

app.use(express.static(__dirname, { index: 'index.html', extensions: ['html'] }));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

initDB().finally(() => app.listen(PORT, () => console.log('Servidor en puerto ' + PORT)));
