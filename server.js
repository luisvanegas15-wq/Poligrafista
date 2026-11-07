// Seguridad y Riesgos · Polígrafías — servidor
const path = require('path');
const express = require('express');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

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
`;

async function initDB() {
  if (!pool) { console.log('Sin DATABASE_URL: modo demo.'); return; }
  try { await pool.query(SCHEMA); console.log('Base de datos lista.'); }
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

app.use(express.static(__dirname, { index: 'index.html', extensions: ['html'] }));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

initDB().finally(() => app.listen(PORT, () => console.log('Servidor en puerto ' + PORT)));
