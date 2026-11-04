import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { generateKeyPairSync, createPrivateKey, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { configuration, identity, domainAllowed, createGateway } from './gateway.mjs';

const pair = generateKeyPairSync('ed25519');
const pub = pair.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
const config = configuration({ REGISTRY_PUBLIC_KEY: pub, REGISTRY_READERS: 'reader,writer', REGISTRY_PUBLISHERS: 'writer' });
function token(user, changes = {}, key = pair.privateKey, alg = 'EdDSA') {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg, typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ iss: 'mcp-registry', iat: now, nbf: now, exp: now + 300,
    auth_method: 'github-at', auth_method_sub: user,
    permissions: [{ action: 'publish', resource: `io.github.${user}/*` }], ...changes })).toString('base64url');
  return `${header}.${payload}.${sign(null, Buffer.from(`${header}.${payload}`), key).toString('base64url')}`;
}

test('valid Ed25519 GitHub registry token', () => assert.equal(identity(token('Writer'), config), 'writer'));
for (const [label, changes] of Object.entries({ expired: { exp: 1 }, future: { nbf: 9999999999 },
  'missing expiry': { exp: undefined }, 'missing issued-at': { iat: undefined },
  'wrong issuer': { iss: 'other' }, anonymous: { auth_method: 'none' },
  'GitHub Actions identity': { auth_method: 'github-oidc' }, 'DNS identity': { auth_method: 'dns' },
  'missing identity': { auth_method_sub: undefined } })) {
  test(`reject ${label}`, () => assert.throws(() => identity(token('writer', changes), config)));
}
test('reject signature from another registry', () => assert.throws(() => identity(token('writer', {}, generateKeyPairSync('ed25519').privateKey), config)));
test('reject algorithm confusion', () => assert.throws(() => identity(token('writer', {}, pair.privateKey, 'HS256'), config)));
test('empty access lists deny by default', () => {
  const empty = configuration({ REGISTRY_PUBLIC_KEY: pub });
  assert.equal(empty.readers.size + empty.publishers.size, 0);
});

const remote = url => ({ remotes: [{ type: 'streamable-http', url }] });
for (const [url, allowed] of [
  ['https://anse.example/mcp', true], ['https://tools.anse.example/mcp', true],
  ['https://notanse.example/mcp', false], ['https://anse.example.evil.test/mcp', false],
  ['https://anse.example@evil.test/mcp', false], ['http://anse.example/mcp', false],
  ['https://anse.example:8443/mcp', false], ['https://anse.example./mcp', false],
]) test(`domain policy ${url}`, () => assert.equal(domainAllowed(remote(url), ['anse.example']), allowed));
test('domain policy rejects packages and absent remotes', () => {
  assert.equal(domainAllowed({ packages: [{}] }, ['anse.example']), false);
  assert.equal(domainAllowed({ ...remote('https://anse.example/mcp'), packages: [{}] }, ['anse.example']), false);
  assert.equal(domainAllowed({ remotes: [] }, ['anse.example']), false);
});
test('every remote must satisfy domain policy', () => assert.equal(domainAllowed({ remotes: [
  ...remote('https://anse.example/mcp').remotes, ...remote('https://evil.test/mcp').remotes,
] }, ['anse.example']), false));

async function listen(server) {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return `http://127.0.0.1:${server.address().port}`;
}
async function close(server) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }

test('HTTP gateway policy with isolated upstream fixture', async t => {
  let calls = 0;
  let observedHeaders;
  const backend = http.createServer(async (req, res) => {
    calls++;
    observedHeaders = req.headers;
    if (req.url === '/v0.1/auth/github-at') {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const user = JSON.parse(Buffer.concat(chunks)).github_token;
      res.end(JSON.stringify({ registry_token: token(user) }));
    } else res.end(JSON.stringify({ servers: [] }));
  });
  const upstream = await listen(backend);
  const gateway = createGateway({ ...config, upstream });
  const base = await listen(gateway);
  t.after(async () => { await close(gateway); await close(backend); });
  const request = (path, user, method = 'GET', body, extra = {}) => fetch(base + path, {
    method, headers: { ...(user ? { Authorization: `Bearer ${token(user)}` } : {}),
      ...(body ? { 'Content-Type': 'application/json' } : {}), ...extra },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  for (const [label, user, method, path, expected] of [
    ['anonymous read', null, 'GET', '/v0.1/servers', 401],
    ['reader lists', 'reader', 'GET', '/v0.1/servers', 200],
    ['outsider reads', 'outsider', 'GET', '/v0.1/servers', 403],
    ['reader publishes', 'reader', 'POST', '/v0.1/publish', 403],
    ['writer publishes', 'writer', 'POST', '/v0.1/publish', 200],
    ['outsider publishes', 'outsider', 'POST', '/v0.1/publish', 403],
    ['official publisher anonymous denied', null, 'POST', '/v0/publish', 401],
    ['official publisher reader denied', 'reader', 'POST', '/v0/publish', 403],
    ['official publisher outsider denied', 'outsider', 'POST', '/v0/publish', 403],
    ['official publisher writer allowed', 'writer', 'POST', '/v0/publish', 200],
    ['anonymous individual entry', null, 'GET', '/v0.1/servers/io.github.writer%2Fdemo/versions/latest', 401],
    ['reader individual entry', 'reader', 'GET', '/v0.1/servers/io.github.writer%2Fdemo/versions/latest', 200],
    ['v0 alias', 'writer', 'GET', '/v0/servers', 404],
    ['metrics', 'writer', 'GET', '/metrics', 404],
    ['web UI', null, 'GET', '/', 404],
    ['anonymous token endpoint', 'writer', 'POST', '/v0.1/auth/none', 404],
    ['OIDC endpoint', 'writer', 'POST', '/v0.1/auth/github-oidc', 404],
    ['admin edit endpoint', 'writer', 'PUT', '/v0.1/servers/io.github.writer%2Fdemo/versions/1.0.0', 404],
    ['HEAD denied', 'writer', 'HEAD', '/v0.1/servers', 404],
    ['double encoded path', 'writer', 'GET', '/v0.1/servers/a%252Fb/versions/latest', 400],
  ]) await t.test(label, async () => {
    const before = calls;
    const r = await request(path, user, method, method === 'POST' || method === 'PUT' ? {} : undefined);
    assert.equal(r.status, expected);
    if (expected !== 200) assert.equal(calls, before, 'Denied request must never reach upstream');
    await r.arrayBuffer();
  });
  await t.test('forged identity headers cannot authorize', async () => {
    const r = await request('/v0.1/servers', null, 'GET', undefined, { 'X-Forwarded-User': 'writer', 'X-Auth-Request-User': 'writer' });
    assert.equal(r.status, 401); await r.arrayBuffer();
  });
  await t.test('identity headers stripped before forwarding', async () => {
    const r = await request('/v0.1/servers', 'reader', 'GET', undefined, { 'X-Forwarded-User': 'writer' });
    assert.equal(r.status, 200); assert.equal(observedHeaders['x-forwarded-user'], undefined); await r.arrayBuffer();
  });
  for (const [user, expected] of [['reader', 200], ['writer', 200], ['outsider', 403]]) {
    await t.test(`login allowlist: ${user}`, async () => {
      const r = await request('/v0.1/auth/github-at', null, 'POST', { github_token: user });
      assert.equal(r.status, expected); const result = await r.json();
      if (expected === 403) assert.equal(result.registry_token, undefined);
    });
    await t.test(`official publisher login allowlist: ${user}`, async () => {
      const r = await request('/v0/auth/github-at', null, 'POST', { github_token: user });
      assert.equal(r.status, expected); const result = await r.json();
      if (expected === 403) assert.equal(result.registry_token, undefined);
    });
  }
});

// Opt-in integration against the actual local Compose stack. These fixtures are
// signed by the operator, not authenticated with GitHub. Real GitHub tests are
// documented separately. This test creates a new metadata version each run.
test('live registry integration using signed identity fixtures', { skip: process.env.RUN_REGISTRY_TESTS !== '1' }, async t => {
  const env = Object.fromEntries(readFileSync(new URL('.env', import.meta.url), 'utf8').trim().split('\n').map(line => {
    const i = line.indexOf('='); return [line.slice(0, i), line.slice(i + 1)];
  }));
  const key = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'),
    Buffer.from(env.REGISTRY_SIGNING_SEED, 'hex')]), format: 'der', type: 'pkcs8' });
  const base = 'http://127.0.0.1:8081';
  const fixture = JSON.parse(readFileSync(new URL('server.json', import.meta.url)));
  const version = `0.0.${Date.now()}`;
  const call = async (path, user, method = 'GET', body, changes = {}) => {
    const r = await fetch(base + path, { method,
      headers: { ...(user ? { Authorization: `Bearer ${token(user, changes, key)}` } : {}),
        ...(body ? { 'Content-Type': 'application/json' } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    return { status: r.status, body: await r.text() };
  };
  for (const [label, user, expected, claims] of [
    ['anonymous denied', null, 401, {}], ['approved account reads', 'risha-parveen', 200, {}],
    ['outsider denied', 'anse-test-outsider', 403, {}],
    ['expired token denied', 'risha-parveen', 401, { exp: 1 }],
    ['anonymous method denied', 'risha-parveen', 401, { auth_method: 'none' }],
  ]) await t.test(label, async () => assert.equal((await call('/v0.1/servers', user, 'GET', undefined, claims)).status, expected));
  await t.test('approved publisher registers', async () => {
    const r = await call('/v0.1/publish', 'risha-parveen', 'POST', { ...fixture, version });
    assert.equal(r.status, 200, r.body);
  });
  await t.test('individual registered entry is discoverable', async () => {
    const path = `/v0.1/servers/${encodeURIComponent(fixture.name)}/versions/${version}`;
    assert.equal((await call(path, null)).status, 401);
    const r = await call(path, 'risha-parveen');
    assert.equal(r.status, 200, r.body); assert.equal(JSON.parse(r.body).server.version, version);
  });
  await t.test('outsider cannot publish', async () => assert.equal((await call('/v0.1/publish', 'anse-test-outsider', 'POST', fixture)).status, 403));
  await t.test('backend rejects another namespace', async () => {
    const r = await call('/v0.1/publish', 'risha-parveen', 'POST', { ...fixture, name: 'io.github.someone-else/demo', version });
    assert.equal(r.status, 403, r.body); assert.match(r.body, /permission/);
  });
  await t.test('schema validation still active', async () => assert.equal((await call('/v0.1/publish', 'risha-parveen', 'POST', { ...fixture, description: 'x'.repeat(101) })).status, 422));
  await t.test('alternate API version remains inaccessible', async () => assert.equal((await call('/v0/servers', 'risha-parveen')).status, 404));
});
