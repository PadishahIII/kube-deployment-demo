// demo-apps/analytics/server.js — a trivial JSON web server (no deps, no file writes).
const http = require('http');
const PORT = Number(process.env.PORT || 9090);

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ app: 'analytics', port: PORT, ok: true, path: req.url }));
});

server.listen(PORT, () => {
  console.log(`analytics listening on :${PORT}`);
});
