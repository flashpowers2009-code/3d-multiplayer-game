const express = require('express');
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { promisify } = require('util');
const { Server } = require('socket.io');

const scrypt = promisify(crypto.scrypt);
const app = express();
app.set('trust proxy', 1);
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json({ limit: '2kb' }));
app.use(express.static(path.join(__dirname, 'public')));

/* ---------- Storage: Postgres if DATABASE_URL is set, else a local JSON file ---------- */
let store;
if (process.env.DATABASE_URL) {
  const { Pool } = require('pg');
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.PGSSL === 'disable' ? false : { rejectUnauthorized: false },
  });
  store = {
    async init() {
      await pool.query(`create table if not exists users(
        key text primary key, username text not null, pass text not null,
        color integer not null default 3900150, created timestamptz default now())`);
    },
    async get(key) {
      const r = await pool.query('select username, pass, color from users where key=$1', [key]);
      return r.rows[0] || null;
    },
    async create(key, username, pass, color) {
      try {
        await pool.query('insert into users(key, username, pass, color) values($1,$2,$3,$4)', [key, username, pass, color]);
        return true;
      } catch (e) {
        if (e.code === '23505') return false; // username already taken
        throw e;
      }
    },
    async setColor(key, color) {
      await pool.query('update users set color=$2 where key=$1', [key, color]);
    },
  };
} else {
  console.warn('WARNING: DATABASE_URL not set. Accounts are saved to ./data/users.json, which is erased on hosts with temporary disks (like Render free).');
  const FILE = path.join(__dirname, 'data', 'users.json');
  let db = {};
  try { db = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch (_) {}
  const save = () => { fs.mkdirSync(path.dirname(FILE), { recursive: true }); fs.writeFileSync(FILE, JSON.stringify(db)); };
  store = {
    async init() {},
    async get(key) { return db[key] || null; },
    async create(key, username, pass, color) { if (db[key]) return false; db[key] = { username, pass, color }; save(); return true; },
    async setColor(key, color) { if (db[key]) { db[key].color = color; save(); } },
  };
}

/* ---------- Passwords & sessions ---------- */
async function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  const h = await scrypt(pw, salt, 64);
  return salt.toString('hex') + ':' + h.toString('hex');
}
async function checkPw(pw, stored) {
  const [s, h] = stored.split(':');
  const calc = await scrypt(pw, Buffer.from(s, 'hex'), 64);
  const a = Buffer.from(h, 'hex');
  return a.length === calc.length && crypto.timingSafeEqual(a, calc);
}
// Set SESSION_SECRET in your host's environment, or everyone is signed out on every restart.
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.SESSION_SECRET) console.warn('WARNING: SESSION_SECRET not set; logins reset whenever the server restarts.');
const mac = (p) => crypto.createHmac('sha256', SECRET).update(p).digest('base64url');
function sign(key) {
  const p = Buffer.from(JSON.stringify({ u: key, exp: Date.now() + 30 * 864e5 })).toString('base64url');
  return p + '.' + mac(p);
}
function verify(t) {
  if (typeof t !== 'string') return null;
  const [p, sig] = t.split('.');
  if (!p || !sig) return null;
  const a = Buffer.from(sig), b = Buffer.from(mac(p));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const d = JSON.parse(Buffer.from(p, 'base64url').toString());
    return d.exp > Date.now() ? d.u : null;
  } catch (_) { return null; }
}

/* ---------- API ---------- */
const NAME_RE = /^[A-Za-z0-9_]{3,16}$/;
const colorOk = (c) => Number.isInteger(c) && c >= 0 && c <= 0xffffff;

const hits = new Map();
function limiter(req, res, next) {
  const now = Date.now();
  const h = hits.get(req.ip) || { n: 0, reset: now + 60000 };
  if (now > h.reset) { h.n = 0; h.reset = now + 60000; }
  if (++h.n > 10) return res.status(429).json({ error: 'Too many attempts. Try again in a minute.' });
  hits.set(req.ip, h);
  next();
}
setInterval(() => { const n = Date.now(); for (const [k, v] of hits) if (n > v.reset) hits.delete(k); }, 60000).unref();

const wrap = (fn) => (req, res) => fn(req, res).catch((e) => { console.error(e); res.status(500).json({ error: 'Server error.' }); });

async function auth(req, res, next) {
  const key = verify((req.headers.authorization || '').replace(/^Bearer /, ''));
  const user = key && (await store.get(key).catch(() => null));
  if (!user) return res.status(401).json({ error: 'Please log in again.' });
  req.key = key; req.user = user;
  next();
}

app.get('/api/status', (req, res) => res.json({ persistent: !!process.env.DATABASE_URL, secretSet: !!process.env.SESSION_SECRET }));

app.post('/api/register', limiter, wrap(async (req, res) => {
  const { username, password, color } = req.body || {};
  if (typeof username !== 'string' || !NAME_RE.test(username))
    return res.status(400).json({ error: 'Username must be 3-16 letters, numbers or underscores.' });
  if (typeof password !== 'string' || password.length < 8 || password.length > 72)
    return res.status(400).json({ error: 'Password must be 8-72 characters.' });
  const c = colorOk(color) ? color : 0x3b82f6;
  const key = username.toLowerCase(); // names are unique regardless of capitalization
  if (!(await store.create(key, username, await hashPw(password), c)))
    return res.status(409).json({ error: 'That username is taken.' });
  res.json({ token: sign(key), username, color: c });
}));

app.post('/api/login', limiter, wrap(async (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string' || password.length > 72)
    return res.status(400).json({ error: 'Enter your username and password.' });
  const key = username.toLowerCase();
  const user = await store.get(key);
  const ok = user ? await checkPw(password, user.pass) : (await scrypt(password, 'x', 64), false);
  if (!ok) return res.status(401).json({ error: 'Wrong username or password.' });
  res.json({ token: sign(key), username: user.username, color: user.color });
}));

app.get('/api/me', auth, wrap(async (req, res) => res.json({ username: req.user.username, color: req.user.color })));

app.post('/api/color', auth, wrap(async (req, res) => {
  const c = req.body && req.body.color;
  if (!colorOk(c)) return res.status(400).json({ error: 'Invalid color.' });
  await store.setColor(req.key, c);
  res.json({ color: c });
}));

/* ---------- Multiplayer ---------- */
const players = {};   // socket.id -> { x, y, z, r, c, n }
const online = new Map(); // account key -> socket
// ---- Shared reactor core: one temperature everyone sees and controls ----
// The core always cools by exactly 1 degree C per second. Each heater key that is on adds +1 C/s
// and each cooler key that is on removes another 1 C/s, so one heater holds it steady.
const core = { temp: 600, cl: [false, false, false, false], ht: [false, false, false, false], by: '' };
const resetCore = () => {
  core.temp = 600; core.cl = [false, false, false, false]; core.ht = [false, false, false, false]; core.by = '';
};
const NATURAL_COOLING = 1;  // degrees C lost per second with everything off
const HEATER_POWER = 1;     // degrees C per second added by each heater
const COOLER_POWER = 1;     // degrees C per second removed by each cooler
setInterval(() => {
  if (!online.size) { resetCore(); return; }
  const dt = 0.1;
  const rate = -NATURAL_COOLING
    + core.ht.filter(Boolean).length * HEATER_POWER
    - core.cl.filter(Boolean).length * COOLER_POWER;
  core.temp = Math.max(300, Math.min(1200, core.temp + rate * dt));
}, 100);
const coreMsg = () => ({ t: Math.round(core.temp), cl: core.cl, ht: core.ht, by: core.by });
setInterval(() => { if (online.size) io.emit('core', coreMsg()); }, 250);
const num = (v) => (typeof v === 'number' && isFinite(v) ? v : 0);

io.use(async (socket, next) => {
  try {
    const key = verify(socket.handshake.auth && socket.handshake.auth.token);
    const user = key && (await store.get(key));
    if (!user) return next(new Error('auth'));
    socket.account = { key, username: user.username, color: user.color };
    next();
  } catch (_) { next(new Error('auth')); }
});

io.on('connection', (socket) => {
  const { key, username } = socket.account;
  let color = socket.account.color;
  let lastColorChange = 0;
  // One session per account: a new login replaces the old one
  const prev = online.get(key);
  if (prev) { prev.emit('kicked'); prev.disconnect(true); }
  online.set(key, socket);

  socket.emit('currentPlayers', players);
  socket.emit('core', coreMsg());

  socket.on('playerMovement', (d) => {
    if (!d || typeof d !== 'object') return;
    // Name and color always come from the account, never from the client
    players[socket.id] = {
      x: Math.max(-100, Math.min(100, num(d.x))),
      y: Math.max(0, Math.min(50, num(d.y))),
      z: Math.max(-100, Math.min(100, num(d.z))),
      r: num(d.r),
      c: color,
      n: username,
    };
    socket.broadcast.emit('serverUpdate', socket.id, players[socket.id]);
  });

  // Press a cooler/heater button in the core hall (toggles it for everyone)
  let lastPress = 0;
  socket.on('pressButton', (d) => {
    const now = Date.now();
    if (!d || now - lastPress < 120) return;
    if ((d.type !== 'cool' && d.type !== 'heat') || !Number.isInteger(d.i) || d.i < 0 || d.i > 3) return;
    lastPress = now;
    const arr = d.type === 'cool' ? core.cl : core.ht;
    arr[d.i] = !arr[d.i];
    core.by = username;
    io.emit('core', coreMsg());
  });

  // Change shirt color any time; saved to the account and shown to everyone
  socket.on('setColor', async (c) => {
    const now = Date.now();
    if (!colorOk(c) || now - lastColorChange < 200) return;
    lastColorChange = now;
    color = c;
    if (players[socket.id]) {
      players[socket.id].c = c;
      socket.broadcast.emit('serverUpdate', socket.id, players[socket.id]);
    }
    try { await store.setColor(key, c); } catch (e) { console.error(e); }
  });

  socket.on('disconnect', () => {
    delete players[socket.id];
    if (online.get(key) === socket) online.delete(key);
    io.emit('playerLeft', socket.id);
  });
});

const PORT = process.env.PORT || 3000;
store.init().then(() => {
  server.listen(PORT, () => console.log('Listening on ' + PORT));
}).catch((e) => { console.error('Database setup failed:', e); process.exit(1); });
