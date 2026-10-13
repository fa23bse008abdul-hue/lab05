// Serves evil.html and cors-demo.html on port 4000 (localhost only).
const http = require('http'), fs = require('fs'), path = require('path');
http.createServer((req, res) => {
  const f = path.join(__dirname, req.url === '/' ? 'evil.html' : path.basename(req.url));
  fs.readFile(f, (e, d) => (e ? (res.writeHead(404), res.end('nf')) : (res.writeHead(200, { 'Content-Type': 'text/html' }), res.end(d))));
}).listen(4000, '127.0.0.1', () => console.log('Evil page on http://127.0.0.1:4000'));
