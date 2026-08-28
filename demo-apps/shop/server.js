// demo-apps/shop/server.js — a trivial JSON web server (no deps, no file writes).
// Runs with a read-only root filesystem; logs go to stdout only.
const http = require('http');
const PORT = Number(process.env.PORT || 8080);

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ app: 'shop', port: PORT, ok: true, path: req.url }));
});

server.listen(PORT, () => {
  console.log(`shop listening on :${PORT}`);
});
