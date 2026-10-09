const express = require('express');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.static(__dirname + '/public'));

const players = {}; // socket.id -> { x, y, z, r, c, n }
const cleanName = (v) =>
  (typeof v === 'string' ? v.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 16) : '') || 'Player';
const num = (v) => (typeof v === 'number' && isFinite(v) ? v : 0);

io.on('connection', (socket) => {
  // Send everyone already here to the new player
  socket.emit('currentPlayers', players);

  socket.on('playerMovement', (d) => {
    if (!d || typeof d !== 'object') return;
    players[socket.id] = {
      x: Math.max(-100, Math.min(100, num(d.x))),
      y: Math.max(0, Math.min(50, num(d.y))),
      z: Math.max(-100, Math.min(100, num(d.z))),
      r: num(d.r),
      c: Math.max(0, Math.min(0xffffff, Math.floor(num(d.c)))),
      n: cleanName(d.n),
    };
    socket.broadcast.emit('serverUpdate', socket.id, players[socket.id]);
  });

  socket.on('disconnect', () => {
    delete players[socket.id];
    io.emit('playerLeft', socket.id);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log('Listening on ' + PORT));
