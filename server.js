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
// always revalidate so phones don't keep showing an old copy of the game
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders: (res) => res.setHeader('Cache-Control', 'no-cache'),
}));

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
// The core starts at 0 C and always cools by exactly 1 C per second. Each heater key that is on adds +2 C/s and
// each cooler key that is on removes 2 C/s. The net rate is always odd (-1, +1, -3, +3...), so it can never
// hold steady. Reaching CODE BLACK (2500 C) blows up the facility; it is rebuilt after 45 seconds.
const EXPLODE_AT = 2500;
const EVAC_MS = 30000;      // time to evacuate once CODE BLACK is reached
const REBUILD_MS = 45000;
const core = { temp: 0, cl: [false, false, false, false], ht: [false, false, false, false], by: '', ex: false, melt: false, meltAt: 0, pm: [true, true, true, true] };
let exTimer = null, evacTimer = null;
const resetCore = () => {
  clearTimeout(exTimer); exTimer = null; clearTimeout(evacTimer); evacTimer = null; core.melt = false;
  core.temp = 0; core.cl = [false, false, false, false]; core.ht = [false, false, false, false]; core.by = ''; core.ex = false; core.pm = [true, true, true, true];
};
const NATURAL_COOLING = 1;  // degrees C lost per second with everything off
const HEATER_POWER = 2;     // degrees C per second added by each heater
const COOLER_POWER = 2;     // degrees C per second removed by each cooler
setInterval(() => {
  if (!online.size) { resetCore(); return; }
  if (core.ex || core.melt) return; // evacuation countdown or exploded: the simulation is paused
  const dt = 0.1;
  const rate = -NATURAL_COOLING
    + core.ht.filter(Boolean).length * HEATER_POWER
    - core.cl.filter((on, i) => on && core.pm[i]).length * COOLER_POWER; // a cooler only works while its pump is on
  core.temp = Math.max(0, Math.min(EXPLODE_AT, core.temp + rate * dt));
  if (core.temp >= EXPLODE_AT) {
    // CODE BLACK: the meltdown can't be stopped. Players get EVAC_MS to get out, then the facility explodes.
    core.melt = true;
    core.meltAt = Date.now() + EVAC_MS;
    io.emit('core', coreMsg());
    evacTimer = setTimeout(() => {
      core.melt = false;
      core.ex = true;
      io.emit('core', coreMsg());
      exTimer = setTimeout(() => { resetCore(); io.emit('core', coreMsg()); }, REBUILD_MS);
    }, EVAC_MS);
  }
}, 100);
const coreMsg = () => ({ t: Math.round(core.temp), cl: core.cl, ht: core.ht, by: core.by, pm: core.pm, ex: core.ex, cd: core.melt ? Math.max(0, Math.ceil((core.meltAt - Date.now()) / 1000)) : 0 });
setInterval(() => { if (online.size) io.emit('core', coreMsg()); }, 250);
// ---- Pistols (PvP) ----
const GUN = { DMG: 20, HEAD: 40, RANGE: 150, COOLDOWN: 180, SPAWN_PROTECTION: 3000 };
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
  socket.hp = 100; socket.dead = false; socket.protUntil = 0; socket.lastShot = 0;

  socket.emit('currentPlayers', players);
  socket.emit('core', coreMsg());

  socket.on('playerMovement', (d) => {
    if (!d || typeof d !== 'object') return;
    if (d.dd) socket.dead = true; // stays dead until the client reports 'respawned'
    // Name and color always come from the account, never from the client
    players[socket.id] = {
      x: Math.max(-100, Math.min(100, num(d.x))),
      y: Math.max(0, Math.min(50, num(d.y))),
      z: Math.max(-100, Math.min(100, num(d.z))),
      r: num(d.r),
      dd: d.dd ? 1 : 0, // 1 while the player is dead (others hide their body)
      // while dead, the dying player streams their ragdoll pose: [x, y, z, rotX, rotY, rotZ, landed]
      rg: d.dd && Array.isArray(d.rg) && d.rg.length === 7
        ? d.rg.map((v, i) => (i < 3 ? Math.max(-150, Math.min(150, num(v))) : num(v)))
        : undefined,
      c: color,
      n: username,
    };
    socket.broadcast.emit('serverUpdate', socket.id, players[socket.id]);
  });

  // Shooting: the shooter's client says what it hit; the server checks it and applies the damage
  const vec3 = (a) => Array.isArray(a) && a.length === 3 ? a.map(num) : null;
  socket.on('shoot', (d) => {
    const now = Date.now();
    if (!d || socket.dead || now - socket.lastShot < GUN.COOLDOWN) return;
    socket.lastShot = now;
    const o = vec3(d.o), dir = vec3(d.d);
    if (o && dir) socket.broadcast.volatile.emit('shot', socket.id, o, dir);
    if (typeof d.hit !== 'string') return;
    const target = io.sockets.sockets.get(d.hit);
    if (!target || target === socket || target.dead || now < target.protUntil) return;
    const sp = players[socket.id], tp = players[d.hit];
    if (!sp || !tp || Math.hypot(sp.x - tp.x, sp.z - tp.z) > GUN.RANGE) return;
    target.hp -= d.head ? GUN.HEAD : GUN.DMG;
    const dx = tp.x - sp.x, dz = tp.z - sp.z;
    const dead = target.hp <= 0;
    target.emit('hurt', { hp: Math.max(0, target.hp) });
    socket.emit('hitmark', { kill: dead });
    if (dead) {
      target.dead = true;
      target.emit('killed', { by: username, dx, dz });
      io.emit('feed', { k: username, v: target.account.username });
    }
  });
  socket.on('respawned', () => {
    socket.hp = 100; socket.dead = false; socket.protUntil = Date.now() + GUN.SPAWN_PROTECTION;
    socket.emit('hp', 100);
  });

  // Press a cooler/heater key on the core computer, or a cooling pump switch in the cooling room (toggles it for everyone)
  let lastPress = 0;
  socket.on('pressButton', (d) => {
    const now = Date.now();
    if (!d || core.ex || core.melt || now - lastPress < 120) return;
    if (!['cool', 'heat', 'pump'].includes(d.type) || !Number.isInteger(d.i) || d.i < 0 || d.i > 3) return;
    lastPress = now;
    if (d.type === 'pump') {
      core.pm[d.i] = !core.pm[d.i];
      if (!core.pm[d.i]) core.cl[d.i] = false; // switching a pump off shuts its cooler off too
    } else if (d.type === 'cool') {
      if (!core.pm[d.i]) return; // pump is off: this cooler can't be used
      core.cl[d.i] = !core.cl[d.i];
    } else {
      core.ht[d.i] = !core.ht[d.i];
    }
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
