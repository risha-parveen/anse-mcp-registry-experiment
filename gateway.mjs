import http from 'node:http';
import { createPublicKey, verify } from 'node:crypto';
import { pathToFileURL } from 'node:url';

// Experimental policy boundary around the unmodified official MCP Registry.
// Only the public verification key belongs here; never the signing seed.
export function configuration(env = process.env) {
  const names = value => new Set((value || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean));
  const rawKey = Buffer.from(env.REGISTRY_PUBLIC_KEY || '', 'hex');
  if (rawKey.length !== 32) throw new Error('REGISTRY_PUBLIC_KEY must contain a 32-byte Ed25519 public key');
  const upstream = new URL(env.REGISTRY_UPSTREAM || 'http://registry:8080');
  if (!['http:', 'https:'].includes(upstream.protocol) || upstream.username || upstream.password || upstream.pathname !== '/') {
    throw new Error('REGISTRY_UPSTREAM must be an HTTP(S) origin');
  }
  const domains = [...names(env.ALLOWED_REMOTE_DOMAINS)];
  if (domains.some(d => !/^[a-z0-9]+(?:[a-z0-9.-]*[a-z0-9])?$/.test(d) || !d.includes('.') || d.includes('..'))) {
    throw new Error('ALLOWED_REMOTE_DOMAINS must contain plain DNS names');
  }
  return {
    upstream: upstream.origin,
    publicKey: createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), rawKey]), format: 'der', type: 'spki' }),
    readers: names(env.REGISTRY_READERS), publishers: names(env.REGISTRY_PUBLISHERS), domains,
    githubClientId: env.GITHUB_CLIENT_ID || '',
  };
}

export function identity(token, config, now = Date.now() / 1000) {
  if (typeof token !== 'string' || token.length > 16384) throw new Error('Invalid token');
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some(p => !/^[A-Za-z0-9_-]+$/.test(p))) throw new Error('Invalid token');
  const header = JSON.parse(Buffer.from(parts[0], 'base64url'));
  if (header.alg !== 'EdDSA' || header.crit) throw new Error('Unsupported token');
  if (!verify(null, Buffer.from(parts.slice(0, 2).join('.')), config.publicKey, Buffer.from(parts[2], 'base64url'))) {
    throw new Error('Invalid signature');
  }
  const claims = JSON.parse(Buffer.from(parts[1], 'base64url'));
  if (claims.iss !== 'mcp-registry' || !Number.isFinite(claims.exp) || claims.exp <= now ||
      !Number.isFinite(claims.iat) || claims.iat > now ||
      (claims.nbf !== undefined && (!Number.isFinite(claims.nbf) || claims.nbf > now)) ||
      claims.auth_method !== 'github-at' || typeof claims.auth_method_sub !== 'string' ||
      !/^[a-zA-Z0-9-]+$/.test(claims.auth_method_sub)) throw new Error('Invalid claims');
  return claims.auth_method_sub.toLowerCase();
}

export function domainAllowed(body, domains) {
  if (!domains.length) return true;
  // This optional policy covers remote-only registrations. Packages cannot
  // establish a server's hosting domain, so reject them in this mode.
  if (!body || !Array.isArray(body.remotes) || !body.remotes.length || (body.packages?.length ?? 0) !== 0) return false;
  return body.remotes.every(remote => {
    try {
      const url = new URL(remote.url);
      const host = url.hostname.toLowerCase();
      return url.protocol === 'https:' && !url.username && !url.password &&
        (!url.port || url.port === '443') && !url.hash &&
        domains.some(domain => host === domain || host.endsWith('.' + domain));
    } catch { return false; }
  });
}

class HTTPError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

async function readBody(req) {
  if (req.headers['transfer-encoding']) throw new HTTPError(400, 'Chunked requests are not supported');
  const length = Number(req.headers['content-length'] || 0);
  if (!Number.isSafeInteger(length) || length < 0 || length > 1024 * 1024) throw new HTTPError(413, 'Request too large');
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 1024 * 1024) throw new HTTPError(413, 'Request too large');
    chunks.push(chunk);
  }
  if (size !== length) throw new HTTPError(400, 'Invalid request length');
  return Buffer.concat(chunks);
}

function send(res, status, body, contentType = 'application/json') {
  res.writeHead(status, { 'Content-Type': contentType, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}

export function createGateway(config) {
  const server = http.createServer(async (req, res) => {
    try {
      // Check the raw path before parsing or forwarding: deny aliases and path
      // normalization tricks. Only reviewed routes are exposed.
      const rawPath = (req.url || '').split('?')[0];
      if (!rawPath.startsWith('/') || rawPath.startsWith('//') || /[\\\x00-\x20]/.test(rawPath)) throw new HTTPError(400, 'Invalid path');
      const url = new URL(req.url, 'http://gateway');
      if (url.pathname !== rawPath || /%(?:2e|5c|25)/i.test(rawPath)) throw new HTTPError(400, 'Invalid path');

      // The official publisher uses these v0 routes. Translate only its login
      // bootstrap, token exchange, and publish paths; apply the same policy.
      const path = ({
        '/v0/health': '/v0.1/health',
        '/v0/auth/github-at': '/v0.1/auth/github-at',
        '/v0/publish': '/v0.1/publish',
      })[rawPath] || rawPath;
      url.pathname = path;

      // Login bootstrap only. No registry metadata is exposed here.
      if (req.method === 'GET' && path === '/v0.1/health') {
        return send(res, 200, { status: 'gateway-running', github_client_id: config.githubClientId });
      }

      const login = req.method === 'POST' && path === '/v0.1/auth/github-at';
      const read = req.method === 'GET' && (path === '/v0.1/servers' ||
        /^\/v0\.1\/servers\/[^/]+\/versions(?:\/[^/]+)?$/.test(path));
      const publish = req.method === 'POST' && path === '/v0.1/publish';
      if (!login && !read && !publish) throw new HTTPError(404, 'Route not exposed');

      if (!login) {
        const auth = req.headers.authorization;
        if (typeof auth !== 'string' || !/^Bearer \S+$/i.test(auth)) throw new HTTPError(401, 'Registry bearer token required');
        let user;
        try { user = identity(auth.slice(7), config); } catch { throw new HTTPError(401, 'Invalid or expired registry token'); }
        if (!(publish ? config.publishers : config.readers).has(user)) throw new HTTPError(403, 'Account is not allowed for this operation');
      }

      const body = req.method === 'POST' ? await readBody(req) : undefined;
      if (req.method === 'POST') {
        if (!/^application\/json(?:;|$)/i.test(req.headers['content-type'] || '')) throw new HTTPError(415, 'JSON required');
        let json;
        try { json = JSON.parse(body); } catch { throw new HTTPError(400, 'Invalid JSON'); }
        if (publish && !domainAllowed(json, config.domains)) throw new HTTPError(403, 'Remote domain policy rejected this registration');
      }

      // Do not trust user-supplied identity headers or follow upstream redirects.
      const upstream = await fetch(config.upstream + url.pathname + url.search, {
        method: req.method, redirect: 'error', signal: AbortSignal.timeout(15000),
        headers: { Accept: 'application/json', ...(body ? { 'Content-Type': 'application/json' } : {}),
          ...(!login ? { Authorization: req.headers.authorization } : {}) }, body,
      });
      const output = Buffer.from(await upstream.arrayBuffer());
      if (login && upstream.ok) {
        let user;
        try { user = identity(JSON.parse(output).registry_token, config); }
        catch { throw new HTTPError(502, 'Invalid registry login response'); }
        if (!config.readers.has(user) && !config.publishers.has(user)) throw new HTTPError(403, 'Account is not allowed');
      }
      return send(res, upstream.status, output, upstream.headers.get('content-type') || 'application/json');
    } catch (error) {
      send(res, error instanceof HTTPError ? error.status : 502,
        { error: error instanceof HTTPError ? error.message : 'Registry unavailable' });
    }
  });
  server.requestTimeout = 20000;
  server.headersTimeout = 10000;
  server.timeout = 20000;
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  createGateway(configuration()).listen(Number(process.env.PORT || 8081), process.env.BIND_ADDRESS || '0.0.0.0',
    () => console.log('ANSE experimental registry gateway listening'));
}
