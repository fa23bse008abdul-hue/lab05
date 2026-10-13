const $ = (id) => document.getElementById(id);
const show = (m, u, r, t) => { $('out').textContent = `${m} ${u}\nHTTP ${r.status}\n\n${t}`; };

async function call(method, url, body, useToken) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (useToken && $('token').value) headers.Authorization = 'Bearer ' + $('token').value.trim();
  try {
    const r = await fetch(url, { method, headers, body, credentials: 'same-origin' });
    const t = await r.text();
    show(method, url, r, t);
    try { const j = JSON.parse(t); if (j.token) $('token').value = j.token; } catch (e) { /* not JSON */ }
    return r;
  } catch (e) { $('out').textContent = 'Network error: ' + e; }
}
const q = encodeURIComponent;

$('btnLogin').onclick = () => call('POST', '/login', JSON.stringify({ email: $('email').value, password: $('password').value }));
$('btnRaw').onclick = () => call('POST', '/login', $('rawLogin').value);
$('btnSqli').onclick = () => { $('rawLogin').value = JSON.stringify({ email: "' OR '1'='1' --", password: 'x' }); };
$('btnReg').onclick = () => call('POST', '/register', $('regBody').value);
$('btnSearch').onclick = () => window.open('/products?search=' + q($('search').value));
$('btnReview').onclick = () => call('POST', '/reviews', JSON.stringify({ productId: Number($('pid').value), text: $('rtext').value }));
$('btnViewRev').onclick = () => window.open(`/products/${q($('pid').value)}/reviews`);
$('btnOrder').onclick = () => call('GET', '/orders/' + q($('oid').value), undefined, true);
$('btnPay').onclick = () => window.open(`/orders/${q($('oid').value)}/pay-form`);
$('btnHpp').onclick = () => call('GET', '/echo?amount=10&amount=1000');
$('btnAdmin').onclick = () => call('GET', '/admin/users', undefined, true);
$('btnLoop').onclick = async () => {
  let log = '';
  for (let i = 1; i <= 7; i++) {
    const r = await fetch('/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'ali@shop.test', password: 'wrong' + i }) });
    log += `attempt ${i}: HTTP ${r.status}\n`;
  }
  $('out').textContent = log;
};
