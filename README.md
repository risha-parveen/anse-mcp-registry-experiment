# ANSE MCP registry experiment

A local MCP Registry with GitHub login, separate publisher and reader lists, and a small MCP server with an `add` tool. Docker runs the registry, PostgreSQL database, access gateway and demo server.

## Requirements

- Docker with Docker Compose, running.
- Node.js 24 and OpenSSL 3.
- A GitHub account and an internet connection for login and downloads.

Run the commands below from this folder. The example account is `risha-parveen`.

## 1. Create local settings

Run once to generate the database password and registry signing keys. The command refuses to overwrite an existing `.env` file.

```sh
node --input-type=module <<'JS'
import { randomBytes, createPrivateKey, createPublicKey } from 'node:crypto';
import { writeFileSync } from 'node:fs';
const seed = randomBytes(32);
const key = createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
  format: 'der', type: 'pkcs8'
});
const publicKey = createPublicKey(key).export({ format: 'der', type: 'spki' })
  .subarray(-32).toString('hex');
writeFileSync('.env', [
  `POSTGRES_PASSWORD=${randomBytes(24).toString('hex')}`,
  `REGISTRY_SIGNING_SEED=${seed.toString('hex')}`,
  `REGISTRY_PUBLIC_KEY=${publicKey}`,
  'REGISTRY_READERS=risha-parveen',
  'REGISTRY_PUBLISHERS=risha-parveen',
  'ALLOWED_REMOTE_DOMAINS=', ''
].join('\n'), { flag: 'wx', mode: 0o600 });
JS
```

For a different GitHub account, replace `risha-parveen` in the two `.env` lists, both `server.json` files and the server name in `live-demo/discover-call.mjs`.

Create the local HTTPS certificate for the demo server:

```sh
mkdir -p live-demo/tls
openssl req -x509 -newkey rsa:2048 -sha256 -days 30 -nodes \
  -keyout live-demo/tls/server.key -out live-demo/tls/server.crt \
  -subj '/CN=mcp-demo.internal' -addext 'subjectAltName=DNS:mcp-demo.internal'
chmod 600 live-demo/tls/server.key
```

The certificate lasts 30 days. To renew, repeat the certificate commands and run `docker compose restart mcp-demo`. Keep `.env` and the private key local; Git ignores both.

## 2. Start and sign in

```sh
docker compose up -d --build
docker compose ps
node client.mjs
```

Follow the displayed GitHub login instructions. At the `registry>` prompt:

```text
list
publish 1.0.1
list
quit
```

This registers example metadata, not a working tool. Choose an unused version when publishing again. The gateway is at `http://127.0.0.1:8081`; there is no browser catalogue.

## 3. Register and call the real demo server

Install the official [mcp-publisher v1.8.7](https://github.com/modelcontextprotocol/registry/releases/tag/v1.8.7) binary for the operating system and put it on `PATH`. Then run:

```sh
mcp-publisher login github --registry http://127.0.0.1:8081
mcp-publisher publish live-demo/server.json
cat "$HOME/.config/mcp-publisher/token.json" | docker compose exec -T mcp-demo node discover-call.mjs
```

The last command passes the login token directly to the client without printing it. Run soon after login; the token lasts five minutes. If version `1.0.0` is already registered, skip publishing and run the last command after login.

Expected result: the client finds the server through the private registry, connects to the server, and `add(7, 5)` returns `12`. Invalid input and logged-out registry reading are rejected. The demo address works inside Docker only.

## Change access or stop

Edit `.env`: `REGISTRY_READERS` controls reading and `REGISTRY_PUBLISHERS` controls registration. Separate usernames with commas; an empty list allows nobody. Apply changes with:

```sh
docker compose up -d --no-build gateway
```

To stop while keeping registrations:

```sh
docker compose stop
```

Restart with `docker compose up -d`. Do not use `docker compose down -v` unless deleting the database is intended.

## Scope

Access uses manual GitHub account lists and the registry project's development login app. ANSE team checks, KERKIS and shared authorization are not connected. The demo does not enforce tool permissions. The custom gateway needs review before operational use; the official registry does not offer self-hosting support.
