import { readFile } from 'node:fs/promises';
import { createInterface } from 'node:readline/promises';
import { pathToFileURL } from 'node:url';

// Small experiment client: credentials remain in memory and are never printed.
// GitHub device authorization uses the registry's configured development app.
async function jsonRequest(url, body, token) {
  const r = await fetch(url, { method: body === undefined ? 'GET' : 'POST', redirect: 'error',
    signal: AbortSignal.timeout(20000),
    headers: { Accept: 'application/json', ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  const result = await r.json();
  if (!r.ok) throw new Error(`HTTP ${r.status}: ${result.error || result.detail || result.title || 'request failed'}`);
  return result;
}

export async function exchange(base, githubToken) {
  return (await jsonRequest(base + '/v0.1/auth/github-at', { github_token: githubToken })).registry_token;
}

export async function registryRequest(base, githubToken, operation, version) {
  const token = await exchange(base, githubToken);
  if (operation === 'list') return jsonRequest(base + '/v0.1/servers', undefined, token);
  if (operation === 'publish') {
    if (!version || !/^\d+\.\d+\.\d+$/.test(version)) throw new Error('Use: publish 1.0.1 (choose a new version)');
    const server = JSON.parse(await readFile(new URL('./server.json', import.meta.url)));
    server.version = version;
    return jsonRequest(base + '/v0.1/publish', server, token);
  }
  throw new Error('Use list, publish <version>, or quit');
}

async function main() {
  const target = new URL(process.env.REGISTRY_URL || 'http://127.0.0.1:8081');
  if (target.username || target.password || target.search || target.hash || target.pathname !== '/' ||
      !(target.protocol === 'https:' || (target.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(target.hostname)))) {
    throw new Error('REGISTRY_URL must be an HTTPS origin or local loopback HTTP origin');
  }
  const base = target.origin;
  const health = await jsonRequest(base + '/v0.1/health');
  if (!health.github_client_id) throw new Error('Registry has no GitHub device-flow client ID');
  const device = await jsonRequest('https://github.com/login/device/code', { client_id: health.github_client_id });
  if (!device.device_code || !device.user_code || device.verification_uri !== 'https://github.com/login/device') {
    throw new Error('GitHub device authorization is unavailable');
  }
  console.log(`Registry: ${base}\nOpen ${device.verification_uri}\nEnter code: ${device.user_code}\nReview the GitHub application before authorizing.`);
  const deadline = Date.now() + Math.min(device.expires_in || 900, 900) * 1000;
  let interval = Math.max(5, Math.min(device.interval || 5, 60));
  let githubToken;
  while (Date.now() < deadline) {
    await new Promise(resolve => setTimeout(resolve, interval * 1000));
    const response = await jsonRequest('https://github.com/login/oauth/access_token', {
      client_id: health.github_client_id, device_code: device.device_code,
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
    });
    if (response.access_token) { githubToken = response.access_token; break; }
    if (response.error === 'slow_down') interval = Math.min(interval + 5, 60);
    else if (response.error !== 'authorization_pending') throw new Error('GitHub authorization failed: ' + response.error);
  }
  if (!githubToken) throw new Error('GitHub device code expired; run the client again');
  await exchange(base, githubToken);
  console.log('Authenticated. Commands: list | publish 1.0.1 | quit');
  const terminal = createInterface({ input: process.stdin, output: process.stdout });
  try {
    for (;;) {
      const [operation, version] = (await terminal.question('registry> ')).trim().split(/\s+/);
      if (operation === 'quit') break;
      try { console.log(JSON.stringify(await registryRequest(base, githubToken, operation, version), null, 2)); }
      catch (error) { console.log(error.message); }
    }
  } finally { terminal.close(); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}
