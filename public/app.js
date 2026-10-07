// Access token is kept in a JS variable only (never localStorage) -> not persisted, not readable after tab close.
let accessToken = null;
const $ = (id) => document.getElementById(id);
const out = $('out');

const log = (title, status, body) => {
  out.textContent = `${new Date().toLocaleTimeString()}  ${title}  ->  HTTP ${status}\n${JSON.stringify(body, null, 2)}\n\n` + out.textContent;
};

const setWho = (user) => {
  $('who').textContent = user ? `Signed in: ${user.email} (${user.role})` : 'Not signed in';
};

async function call(method, url, body) {
  const headers = { 'Content-Type': 'application/json' };
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
  const res = await fetch(url, {
    method,
    headers,
    credentials: 'same-origin',
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = {};
  try { data = await res.json(); } catch (e) { /* no body */ }
  log(`${method} ${url}`, res.status, data);
  return { res, data };
}

async function refresh(silent) {
  const { res, data } = await call('POST', '/api/v1/auth/refresh');
  if (res.ok) { accessToken = data.accessToken; setWho(data.user); }
  else if (!silent) { accessToken = null; setWho(null); }
  return res.ok;
}

// Authenticated call that transparently refreshes once on expiry
async function authed(method, url, body) {
  let r = await call(method, url, body);
  if (r.res.status === 401 && r.data.code === 'TOKEN_EXPIRED' && (await refresh())) {
    r = await call(method, url, body);
  }
  return r;
}

$('login').addEventListener('click', async () => {
  const { res, data } = await call('POST', '/api/v1/auth/login', { email: $('email').value, password: $('password').value });
  if (res.ok) { accessToken = data.accessToken; setWho(data.user); }
});
$('register').addEventListener('click', () =>
  call('POST', '/api/v1/auth/register', { email: $('email').value, password: $('password').value }));
$('refresh').addEventListener('click', () => refresh(false));
$('logout').addEventListener('click', async () => { await call('POST', '/api/v1/auth/logout'); accessToken = null; setWho(null); });
$('profile').addEventListener('click', () => authed('GET', '/api/v1/employee/profile'));
$('payroll').addEventListener('click', () => authed('POST', '/api/v1/payroll/approve', {}));
$('del').addEventListener('click', () => authed('DELETE', `/api/v1/users/${encodeURIComponent($('uid').value)}`));

// After an OAuth redirect (or page reload) the httpOnly cookie lets us silently obtain an access token
refresh(true).then((ok) => { if (ok) log('Session restored via refresh cookie', 200, { restored: true }); });
if (new URLSearchParams(location.search).get('error')) log('OAuth', 401, { message: 'OAuth login failed' });
