const request = require('supertest');
const jwt = require('jsonwebtoken');
const { createApp } = require('../src/app');

const cfg = { secure: true, jwtSecret: 'test-jwt-secret-0123456789', sessionSecret: 'test-session-secret-0123', allowedOrigins: ['http://localhost:4000'] };
const PW = 'Passw0rd!123';
const login = (app, email = 'ali@shop.test', password = PW) => request(app).post('/login').send({ email, password });

describe('Part D - BOLA', () => {
  test("Ali requesting Sara's order returns 403", async () => {
    const app = createApp(cfg);
    const { body } = await login(app);
    expect((await request(app).get('/orders/2').set('Authorization', `Bearer ${body.token}`)).status).toBe(403);
    expect((await request(app).get('/orders/1').set('Authorization', `Bearer ${body.token}`)).status).toBe(200);
  });
});

describe('Part C - injection', () => {
  test.each([
    ['SQL', { email: "' OR '1'='1' --", password: 'x' }],
    ['SQL in password', { email: 'ali@shop.test', password: "' OR '1'='1" }],
    ['NoSQL operator', { email: 'ali@shop.test', password: { $ne: null } }],
  ])('%s payload returns 401', async (_n, payload) => {
    const app = createApp(cfg);
    expect((await request(app).post('/login').send(payload)).status).toBe(401);
  });
});

describe('Part E - validation, rate limit, HPP', () => {
  const good = { email: 'new@shop.test', password: 'Str0ngPass!', phone: '03001234567', cnic: '12345-1234567-1' };
  test('valid registration succeeds', async () => {
    expect((await request(createApp(cfg)).post('/register').send(good)).status).toBe(201);
  });
  test.each([
    ['bad phone', { ...good, phone: '04001234567' }],
    ['wrong type', { ...good, phone: 3001234567 }],
    ['short password', { ...good, password: 'short' }],
    ['bad CNIC', { ...good, cnic: '1234512345671' }],
    ['extra field', { ...good, role: 'admin' }],
    ['missing field', { email: good.email, password: good.password, phone: good.phone }],
  ])('register with %s returns 400', async (_n, payload) => {
    expect((await request(createApp(cfg)).post('/register').send(payload)).status).toBe(400);
  });
  test('6th login attempt within 15 minutes returns 429', async () => {
    const app = createApp(cfg);
    for (let i = 0; i < 5; i++) expect((await login(app, 'ali@shop.test', 'wrong-pass')).status).toBe(401);
    expect((await login(app)).status).toBe(429);
  });
  test('HPP: duplicate query params collapse to one value', async () => {
    const r = await request(createApp(cfg)).get('/echo?amount=10&amount=1000');
    expect(r.body).toEqual({ received: '1000', isArray: false });
  });
});

describe('Part B - CSRF', () => {
  test('payment without CSRF token returns 403', async () => {
    const app = createApp(cfg);
    const agent = request.agent(app);
    await agent.post('/login').send({ email: 'ali@shop.test', password: PW });
    expect((await agent.post('/orders/1/pay')).status).toBe(403);
  });
  test('payment with valid CSRF token works', async () => {
    const agent = request.agent(createApp(cfg));
    await agent.post('/login').send({ email: 'ali@shop.test', password: PW });
    const { body } = await agent.get('/csrf-token');
    const r = await agent.post('/orders/1/pay').set('x-csrf-token', body.token);
    expect(r.status).toBe(200);
  });
});

describe('Part F - JWT', () => {
  test('tampered JWT returns 401', async () => {
    const app = createApp(cfg);
    const { body } = await login(app);
    const [h, , s] = body.token.split('.');
    const forged = Buffer.from(JSON.stringify({ sub: 101, role: 'admin' })).toString('base64url');
    const r = await request(app).get('/admin/users').set('Authorization', `Bearer ${h}.${forged}.${s}`);
    expect(r.status).toBe(401);
  });
  test('expired JWT returns 401', async () => {
    const app = createApp(cfg);
    const old = jwt.sign({ sub: 101, role: 'user' }, cfg.jwtSecret, { expiresIn: -10 });
    expect((await request(app).get('/orders/1').set('Authorization', `Bearer ${old}`)).status).toBe(401);
  });
  test('token lifetime is 15 minutes', async () => {
    const { body } = await login(createApp(cfg));
    const p = jwt.decode(body.token);
    expect(p.exp - p.iat).toBe(900);
  });
});

describe('Part A - XSS', () => {
  const xss = "<img src=x onerror=alert('XSS')>";
  test('reflected payload is encoded and CSP header is present', async () => {
    const r = await request(createApp(cfg)).get('/products').query({ search: xss });
    expect(r.text).not.toContain('<img');
    expect(r.headers['content-security-policy']).toContain("script-src 'self'");
  });
  test('stored payload is encoded', async () => {
    const app = createApp(cfg);
    await request(app).post('/reviews').send({ productId: 1, text: xss });
    expect((await request(app).get('/products/1/reviews')).text).not.toContain('<img');
  });
});
