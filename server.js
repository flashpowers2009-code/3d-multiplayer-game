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

/* ---------- Multiplayer: three separate servers ---------- */
// Players are placed in one of three independent worlds, each with its own players and its own reactor core.
// The client is never told which one it is in. Dying bans you from the world you died in, and you respawn
// in one of the others at random. (If you are ever banned from all three, the bans are cleared.)
const SHARDS = 3;
const EXPLODE_AT = 2500;    // reaching CODE BLACK blows up the facility...
const EVAC_MS = 30000;      // ...after this long to evacuate
const REBUILD_MS = 45000;   // the facility is rebuilt this long after the explosion
const BAN_MS = 15 * 60 * 1000;    // dying bans you from that world for 15 minutes
const CORPSE_MS = 15 * 60 * 1000; // a dead body stays for 15 minutes
const NATURAL_COOLING = 1;  // degrees C lost per second with everything off
const HEATER_POWER = 2;     // degrees C per second added by each heater
const COOLER_POWER = 2;     // degrees C per second removed by each cooler
const GUN = { DMG: 20, HEAD: 40, RANGE: 150, COOLDOWN: 180, SPAWN_PROTECTION: 3000, PUNCH: 10, PUNCH_COOLDOWN: 400, PUNCH_RANGE: 4 };
// the security room (where pistols are handed out): world coordinates, a little generous
const MAX_SLOTS = 10;
const SEC = { x0: -51, x1: -29, z0: -36, z1: -22 };
const num = (v) => (typeof v === 'number' && isFinite(v) ? v : 0);

// The reactor core starts at 0 C and always cools by exactly 1 C per second. Each heater key that is on adds
// +2 C/s and each cooler key that is on removes 2 C/s, so the net rate is always odd and can never hold steady.
const newCore = () => ({ temp: 0, cl: [false, false, false, false], ht: [false, false, false, false], by: '', ex: false, melt: false, meltAt: 0, pm: [true, true, true, true], lights: true });
const shards = Array.from({ length: SHARDS }, (_, i) => ({
  id: i, room: 'shard' + i, players: {}, sockets: new Set(), core: newCore(), exTimer: null, evacTimer: null, dirty: false, corpses: [],
}));
const online = new Map(); // account key -> socket (one session per account)
const bans = new Map();   // account key -> Map of shard id -> time the ban ends

const coreMsg = (sh) => {
  const c = sh.core;
  return { t: Math.round(c.temp), cl: c.cl, ht: c.ht, by: c.by, pm: c.pm, lt: c.lights, ex: c.ex, cd: c.melt ? Math.max(0, Math.ceil((c.meltAt - Date.now()) / 1000)) : 0 };
};
const emitCore = (sh) => io.to(sh.room).emit('core', coreMsg(sh));
const resetCore = (sh) => {
  clearTimeout(sh.exTimer); clearTimeout(sh.evacTimer); sh.exTimer = sh.evacTimer = null;
  sh.core = newCore();
};

function simulate(sh) {
  if (!sh.sockets.size) { if (sh.dirty) { resetCore(sh); sh.dirty = false; } return; } // empty world: reset
  const core = sh.core;
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
    emitCore(sh);
    sh.evacTimer = setTimeout(() => {
      core.melt = false;
      core.ex = true;
      blastCorpses(sh);
      killInsideFacility(sh);
      emitCore(sh);
      sh.exTimer = setTimeout(() => { resetCore(sh); emitCore(sh); }, REBUILD_MS);
    }, EVAC_MS);
  }
}
setInterval(() => { for (const sh of shards) simulate(sh); }, 100);
setInterval(() => { for (const sh of shards) if (sh.sockets.size) emitCore(sh); }, 250);

// pick a random world the player is allowed in (not one they died in, and never the one they just died in)
function pickShard(key, avoid) {
  const m = bans.get(key) || new Map();
  const now = Date.now();
  for (const [id, until] of m) if (until <= now) m.delete(id); // bans run out after 15 minutes
  let options = shards.filter((s) => !m.has(s.id) && s.id !== avoid);
  if (!options.length) { bans.delete(key); options = shards.filter((s) => s.id !== avoid); } // banned everywhere: start over
  return options[Math.floor(Math.random() * options.length)];
}
let nextCorpseId = 1, nextItemId = 1;
function createCorpse(socket, sh, info) {
  const pl = sh && sh.players[socket.id];
  if (!pl) return;
  let seed = 0; for (const ch of String(socket.id)) seed = (seed * 31 + ch.charCodeAt(0)) >>> 0; // same hash the clients use
  const rnd = (n) => ((seed >>> n) % 1000) / 1000;
  // work out the ragdoll's fall here, so every player sees the same body land in the same place
  const G = 22, y0 = pl.y + 1.1;
  let vx, vz, vy;
  if (info.blast) { // thrown outward by the explosion
    const dx = pl.x, dz = pl.z + 45, d = Math.hypot(dx, dz) || 1, sp = 12 + rnd(0) * 8;
    vx = dx / d * sp; vz = dz / d * sp; vy = 9 + rnd(3) * 6;
  } else { // knocked back along the shot or punch
    const d = Math.hypot(info.dx, info.dz) || 1, sp = 3 + rnd(0) * 2;
    vx = info.dx / d * sp; vz = info.dz / d * sp; vy = 2 + rnd(3) * 2;
  }
  const dur = (vy + Math.sqrt(vy * vy + 2 * G * (y0 - 0.25))) / G; // time until it hits the ground
  const clamp = (v) => Math.max(-95, Math.min(95, v));
  const from = [pl.x, y0, pl.z, 0, pl.r || 0, 0];
  const rg = [clamp(pl.x + vx * dur), 0.22, clamp(pl.z + vz * dur), ((seed >> 5) % 2 ? 1 : -1) * Math.PI / 2, (pl.r || 0) + ((seed % 628) / 100), ((seed % 13) - 6) / 20, 1];
  // everything they carried drops with them, as separate items: each pistol, and their ID card(s)
  const items = [];
  for (let i = 0; i < socket.guns; i++) items.push({ id: nextItemId++, kind: 'pistol' });
  for (const card of socket.cards) items.push({ id: nextItemId++, kind: 'card', card: { ...card } });
  const c = { id: nextCorpseId++, owner: socket.id, from, rg, vy, dur, c: pl.c, seed, items, born: Date.now(), until: Date.now() + CORPSE_MS };
  sh.corpses.push(c);
  socket.guns = 0; socket.cards = [];
  io.to(sh.room).emit('corpse', { ...c, age: 0 });
}
// a player dies: the body (with all their stuff) appears right away, whether or not their browser is open
function killOnServer(target, info) {
  const sh = target.shard;
  if (!sh || target.dead) return;
  target.dead = true; target.diedIn = sh.id; target.diedAt = Date.now();
  createCorpse(target, sh, info);
  delete sh.players[target.id];
  io.to(sh.room).emit('playerLeft', target.id); // their living body disappears for everyone
  target.emit('killed', info.blast ? { blast: true } : { by: info.by, dx: info.dx, dz: info.dz });
}
// anyone still inside the facility when it explodes dies, even if they're away from the keyboard
function killInsideFacility(sh) {
  for (const sk of [...sh.sockets]) {
    const p = sh.players[sk.id];
    if (p && !sk.dead && p.x > -51 && p.x < 31 && Math.abs(p.z + 45) < 23) killOnServer(sk, { blast: true });
  }
}
// the core explosion throws nearby bodies far across the map
function blastCorpses(sh) {
  const CX = 0, CZ = -45, clamp = (v) => Math.max(-95, Math.min(95, v));
  const moved = [];
  for (const c of sh.corpses) {
    const dx = c.rg[0] - CX, dz = c.rg[2] - CZ, d = Math.hypot(dx, dz);
    if (d > 60) continue;
    const ang = d > 0.5 ? Math.atan2(dz, dx) : (c.seed % 628) / 100;
    const dist = 22 + (c.seed % 17);
    const from = c.rg.slice();
    c.rg = [clamp(c.rg[0] + Math.cos(ang) * dist), 0.22, clamp(c.rg[2] + Math.sin(ang) * dist),
      ((c.seed >> 3) % 2 ? 1 : -1) * Math.PI / 2, (c.seed % 628) / 100, ((c.seed % 13) - 6) / 20, 1];
    moved.push({ id: c.id, from, rg: c.rg });
  }
  if (moved.length) io.to(sh.room).emit('corpseBlast', moved);
}
// remove bodies that have been lying around for 15 minutes
setInterval(() => {
  const now = Date.now();
  for (const sh of shards) {
    for (let i = sh.corpses.length - 1; i >= 0; i--) {
      if (sh.corpses[i].until <= now) { io.to(sh.room).emit('corpseGone', sh.corpses[i].id); sh.corpses.splice(i, 1); }
    }
  }
}, 10000);
function leaveShard(socket) {
  const sh = socket.shard;
  if (!sh) return;
  sh.sockets.delete(socket);
  delete sh.players[socket.id];
  socket.leave(sh.room);
  io.to(sh.room).emit('playerLeft', socket.id);
  socket.shard = null;
}
function joinShard(socket, sh) {
  socket.shard = sh;
  sh.sockets.add(socket);
  sh.dirty = true;
  socket.join(sh.room);
  socket.emit('shardReset'); // the client forgets the previous world
  socket.emit('currentPlayers', sh.players);
  socket.emit('corpses', sh.corpses.map((c) => ({ ...c, age: Date.now() - c.born })));
  socket.emit('core', coreMsg(sh));
}

io.use(async (socket, next) => {
  try {
    const key = verify(socket.handshake.auth && socket.handshake.auth.token);
    const user = key && (await store.get(key));
    if (!user) return next(new Error('auth'));
    // team comes from the lobby: 0 = facility worker, 1 = rebel
    const team = socket.handshake.auth && socket.handshake.auth.team === 1 ? 1 : 0;
    socket.account = { key, username: user.username, color: user.color, team };
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
  socket.hp = 100; socket.dead = false; socket.guns = 0; socket.cards = [{ n: username, t: socket.account.team, c: color }]; socket.diedIn = null; socket.protUntil = 0; socket.lastShot = 0; socket.lastPunch = 0;
  socket.shard = null;
  const sendInv = () => socket.emit('inv', { guns: socket.guns, cards: socket.cards });
  joinShard(socket, pickShard(key, -1)); // a random world; the player is never told which
  sendInv();

  socket.on('playerMovement', (d) => {
    const sh = socket.shard;
    if (!sh || !d || typeof d !== 'object') return;
    if (socket.dead) return; // the dead don't move
    // Name and color always come from the account, never from the client
    sh.players[socket.id] = {
      x: Math.max(-100, Math.min(100, num(d.x))),
      y: Math.max(0, Math.min(50, num(d.y))),
      z: Math.max(-100, Math.min(100, num(d.z))),
      r: num(d.r),
      dd: d.dd ? 1 : 0, // 1 while the player is dead (others hide their body)
      tm: socket.account.team,
      gn: socket.guns > 0 ? 1 : 0, // whether they carry a pistol
      idc: socket.cards[Number.isInteger(d.ic) && d.ic >= 0 && d.ic < socket.cards.length ? d.ic : 0], // the ID card they are holding up
      sl: Number.isInteger(d.sl) && d.sl >= 0 && d.sl <= 2 ? d.sl : 0, // which hotbar slot they're holding
      // while dead, the dying player streams their ragdoll pose: [x, y, z, rotX, rotY, rotZ, landed]
      rg: d.dd && Array.isArray(d.rg) && d.rg.length === 7
        ? d.rg.map((v, i) => (i < 3 ? Math.max(-150, Math.min(150, num(v))) : num(v)))
        : undefined,
      c: color,
      n: username,
    };
    socket.to(sh.room).emit('serverUpdate', socket.id, sh.players[socket.id]);
  });

  // Shooting and punching: the attacker's client says what it hit; the server checks it and applies the damage
  const vec3 = (a) => Array.isArray(a) && a.length === 3 ? a.map(num) : null;
  const targetOf = (id, maxDist, now) => {
    const sh = socket.shard;
    if (!sh || typeof id !== 'string') return null;
    const target = io.sockets.sockets.get(id);
    if (!target || target === socket || target.shard !== sh || target.dead || now < target.protUntil) return null;
    const sp = sh.players[socket.id], tp = sh.players[id];
    if (!sp || !tp || Math.hypot(sp.x - tp.x, sp.z - tp.z) > maxDist) return null;
    return { target, dx: tp.x - sp.x, dz: tp.z - sp.z };
  };
  const damage = (hit, dmg) => {
    const target = hit.target;
    target.hp -= dmg;
    const dead = target.hp <= 0;
    target.emit('hurt', { hp: Math.max(0, target.hp) });
    socket.emit('hitmark', { kill: dead });
    if (dead) killOnServer(target, { by: username, dx: hit.dx, dz: hit.dz });
  };
  socket.on('shoot', (d) => {
    const now = Date.now();
    if (!socket.shard || !d || socket.dead || socket.guns <= 0 || now - socket.lastShot < GUN.COOLDOWN) return;
    socket.lastShot = now;
    const o = vec3(d.o), dir = vec3(d.d);
    const end = vec3(d.e); // where the bullet stopped (a wall, a player, or the end of its range)
    if (o && dir) socket.to(socket.shard.room).volatile.emit('shot', socket.id, o, dir, end);
    const hit = targetOf(d.hit, GUN.RANGE, now);
    if (hit) damage(hit, d.head ? GUN.HEAD : GUN.DMG);
  });
  socket.on('punch', (d) => {
    const now = Date.now();
    if (!socket.shard || !d || socket.dead || now - socket.lastPunch < GUN.PUNCH_COOLDOWN) return;
    socket.lastPunch = now;
    socket.to(socket.shard.room).volatile.emit('punched', socket.id);
    const hit = targetOf(d.hit, GUN.PUNCH_RANGE, now);
    if (hit) damage(hit, GUN.PUNCH);
  });
  // Everyone spawns without a pistol. The locker in the security room hands out as many as you like, and takes them back.
  // hotbar cap: pistols + hands + ID cards can never take more than 10 slots
  const slotsUsed = () => socket.guns + 1 + socket.cards.length;
  const inSecurity = () => {
    const sh = socket.shard, p = sh && sh.players[socket.id];
    return !!p && !socket.dead && !sh.core.ex && p.x >= SEC.x0 && p.x <= SEC.x1 && p.z >= SEC.z0 && p.z <= SEC.z1;
  };
  socket.on('getGun', () => {
    if (!inSecurity()) return;
    if (slotsUsed() >= MAX_SLOTS) { socket.emit('full'); return; } // hotbar is full
    socket.guns++;
    sendInv();
  });
  socket.on('putGun', () => {
    if (!inSecurity() || socket.guns <= 0) return;
    socket.guns--;
    sendInv();
  });
  // Loot: pick up ONE item (a pistol or an ID card) from a dead body
  socket.on('loot', (d) => {
    const sh = socket.shard, p = sh && sh.players[socket.id];
    if (!p || socket.dead || !d) return;
    const c = sh.corpses.find((x) => x.id === d.id);
    if (!c || Math.hypot(p.x - c.rg[0], p.z - c.rg[2]) > 4.5) return;
    const i = c.items.findIndex((it) => it.id === d.item);
    if (i < 0) return;
    if (slotsUsed() >= MAX_SLOTS) { socket.emit('full'); return; } // hotbar is full
    const it = c.items.splice(i, 1)[0];
    if (it.kind === 'pistol') socket.guns++; else socket.cards.push(it.card);
    sendInv();
    io.to(sh.room).emit('corpseUpdate', { id: c.id, items: c.items });
  });
  socket.on('respawned', () => {
    if (!socket.dead || Date.now() - (socket.diedAt || 0) < 5500) return; // you must wait out the 6 seconds first
    socket.guns = 0; // a new life starts without a pistol, with a fresh ID card
    socket.cards = [{ n: username, t: socket.account.team, c: color }];
    socket.hp = 100; socket.dead = false; socket.protUntil = Date.now() + GUN.SPAWN_PROTECTION;
    if (socket.diedIn !== null && socket.shard) {
      // you can't go back to the world you died in: ban it for 15 minutes and respawn in another one at random
      const died = socket.diedIn;
      const m = bans.get(key) || new Map();
      m.set(died, Date.now() + BAN_MS);
      bans.set(key, m);
      socket.diedIn = null;
      const next = pickShard(key, died);
      leaveShard(socket);
      joinShard(socket, next);
    }
    sendInv();
    socket.emit('hp', 100);
  });

  // Press a cooler/heater key on the core computer, or a cooling pump switch in the cooling room (toggles it for everyone in this world)
  let lastPress = 0;
  socket.on('pressButton', (d) => {
    const now = Date.now();
    const sh = socket.shard;
    if (!sh || !d || sh.core.ex || sh.core.melt || now - lastPress < 120) return;
    if (!['cool', 'heat', 'pump', 'lights'].includes(d.type) || !Number.isInteger(d.i) || d.i < 0 || d.i > 3) return;
    lastPress = now;
    const core = sh.core;
    if (d.type === 'pump') {
      core.pm[d.i] = !core.pm[d.i];
      if (!core.pm[d.i]) core.cl[d.i] = false; // switching a pump off shuts its cooler off too
    } else if (d.type === 'cool') {
      if (!core.pm[d.i]) return; // pump is off: this cooler can't be used
      core.cl[d.i] = !core.cl[d.i];
    } else if (d.type === 'lights') {
      core.lights = !core.lights; // the breaker in the power room: sabotage the lights, or switch them back on
    } else {
      core.ht[d.i] = !core.ht[d.i];
    }
    core.by = username;
    emitCore(sh);
  });

  // Change shirt color any time; saved to the account and shown to everyone
  socket.on('setColor', async (c) => {
    const now = Date.now();
    if (!colorOk(c) || now - lastColorChange < 200) return;
    lastColorChange = now;
    color = c;
    for (const cd of socket.cards) if (cd.n === username) cd.c = c; // your own ID card follows your shirt color
    const sh = socket.shard;
    if (sh && sh.players[socket.id]) {
      sh.players[socket.id].c = c;
      socket.to(sh.room).emit('serverUpdate', socket.id, sh.players[socket.id]);
    }
    try { await store.setColor(key, c); } catch (e) { console.error(e); }
  });

  socket.on('disconnect', () => {
    leaveShard(socket);
    if (online.get(key) === socket) online.delete(key);
  });
});

// Everyone who is alive heals 1 HP per second
setInterval(() => {
  for (const s of io.sockets.sockets.values()) {
    if (!s.account || s.dead || s.hp >= 100) continue;
    s.hp = Math.min(100, s.hp + 1);
    s.emit('hp', s.hp);
  }
}, 1000);

const PORT = process.env.PORT || 3000;
store.init().then(() => {
  server.listen(PORT, () => console.log('Listening on ' + PORT));
}).catch((e) => { console.error('Database setup failed:', e); process.exit(1); });
