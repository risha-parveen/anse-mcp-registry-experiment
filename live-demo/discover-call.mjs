import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';

// Receives the official publisher's token file on stdin; never prints credentials.
const session = JSON.parse(readFileSync(0, 'utf8'));
assert.ok(['http://gateway:8081', 'http://127.0.0.1:8081'].includes(session.registry),
  'Use the private experiment registry');
// Host and container logins identify the same deployment. From this container,
// use its Docker service address rather than the host's loopback address.
const registry = 'http://gateway:8081';
const name = 'io.github.risha-parveen/anse-live-demo';
const listingURL = `${registry}/v0.1/servers?search=${encodeURIComponent(name)}`;
const unauthenticated = await fetch(listingURL);
assert.equal(unauthenticated.status, 401, 'Catalogue must reject logged-out access');
console.log('PASS: registry discovery without login is denied (401).');
const listed = await fetch(listingURL, { headers: { Authorization: `Bearer ${session.token}` } });
assert.equal(listed.status, 200, 'Approved GitHub account must be able to discover the server');
const entries = (await listed.json()).servers;
const entry = entries.find(item => item.server.name === name && item.server.version === '1.0.0');
assert.ok(entry, 'The server published by the standard publisher must be listed');
const remote = entry.server.remotes.find(item => item.type === 'streamable-http');
assert.ok(remote, 'Registry entry must provide a Streamable HTTP endpoint');
// The address comes from the registry. This assertion limits the test client to
// its intended local service; no registry credentials are sent to the MCP server.
assert.equal(remote.url, 'https://mcp-demo.internal:8443/mcp');
console.log(`PASS: discovered ${entry.server.name}@${entry.server.version}.`);
console.log(`Endpoint read from registry: ${remote.url}`);

const client = new Client({ name: 'anse-registry-discovery-test', version: '1.0.0' }, {
  versionNegotiation: { mode: { pin: '2026-07-28' } },
});
try {
  await client.connect(new StreamableHTTPClientTransport(new URL(remote.url)));
  assert.ok(client.getDiscoverResult(), 'Require modern MCP discovery, with no legacy fallback');
  console.log('PASS: connected over HTTPS with MCP 2026-07-28 pinned.');
  const tools = await client.listTools();
  assert.ok(tools.tools.some(tool => tool.name === 'add'));
  console.log('PASS: tools/list returned the add operation.');
  const result = await client.callTool({ name: 'add', arguments: { a: 7, b: 5 } });
  assert.notEqual(result.isError, true);
  assert.deepEqual(result.structuredContent, { sum: 12 });
  console.log('PASS: tools/call add(7, 5) returned 12.');
  // Send through the SDK's request path so the wire envelope is valid and the
  // server's input validation, rather than a client-side shortcut, is exercised.
  const invalid = await client.request({
    method: 'tools/call', params: { name: 'add', arguments: { a: 'seven', b: 5 } },
  });
  assert.equal(invalid.isError, true, 'Invalid input must be rejected by the server');
  assert.match(invalid.content[0].text, /expected number, received string/);
  console.log('PASS: server rejected a non-numeric argument.');
} finally { await client.close(); }
