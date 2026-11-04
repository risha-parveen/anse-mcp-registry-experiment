import { createServer } from 'node:https';
import { readFileSync } from 'node:fs';
import { McpServer, createMcpHandler } from '@modelcontextprotocol/server';
import { hostHeaderValidation, originValidation, toNodeHandler } from '@modelcontextprotocol/node';
import * as z from 'zod/v4';

// Deliberately small, real MCP server for the registry-to-invocation experiment.
// Private Docker network only. ANSE OAuth/tool permissions are a separate test.
const handler = createMcpHandler(() => {
  const server = new McpServer({ name: 'anse-live-demo', version: '1.0.0' });
  server.registerTool('add', {
    description: 'Add two numbers to demonstrate a real MCP tool call.',
    inputSchema: z.object({ a: z.number().finite(), b: z.number().finite() }),
    outputSchema: z.object({ sum: z.number() }),
  }, async ({ a, b }) => ({
    content: [{ type: 'text', text: `${a} + ${b} = ${a + b}` }],
    structuredContent: { sum: a + b },
  }));
  return server;
}, { responseMode: 'json', legacy: 'reject' });
const nodeHandler = toNodeHandler(handler);
const validHost = hostHeaderValidation(['mcp-demo.internal']);
const validOrigin = originValidation(['mcp-demo.internal']);
const server = createServer({
  key: readFileSync('/tls/server.key'),
  cert: readFileSync('/tls/server.crt'),
}, async (req, res) => {
  if (!validHost(req, res) || !validOrigin(req, res)) return;
  if (req.url !== '/mcp') { res.writeHead(404); res.end(); return; }
  try { await nodeHandler(req, res); }
  catch {
    if (!res.headersSent) res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'MCP request failed' }));
  }
});
server.requestTimeout = 15000;
server.headersTimeout = 10000;
server.listen(8443, '0.0.0.0', () => console.log('Live MCP demo listening on https://mcp-demo.internal:8443/mcp'));
process.on('SIGTERM', () => server.close(async () => { await handler.close(); process.exit(0); }));
