import { createConnection, createServer, type Socket } from 'node:net';
import { networkInterfaces } from 'node:os';

const PORT = Number(process.env.KEYFLAP_DEMO_MCP_PORT ?? 8765);

function relay(client: Socket): void {
  const upstream = createConnection({ host: '127.0.0.1', port: PORT });
  const end = () => {
    client.destroy();
    upstream.destroy();
  };
  client.on('error', end);
  upstream.on('error', end);
  client.pipe(upstream);
  upstream.pipe(client);
}

const addresses = Object.values(networkInterfaces())
  .flat()
  .filter((a) => a !== undefined && !a.internal)
  .map((a) => (a as { address: string }).address)
  .filter((a) => !a.toLowerCase().startsWith('fe80:'));

if (addresses.length === 0) {
  process.stderr.write('mcp-relay: no non-loopback interface; only in-container clients\n');
}
for (const address of addresses) {
  const server = createServer(relay);
  server.on('error', (err) => {
    process.stderr.write(`mcp-relay: cannot listen on ${address}:${PORT}: ${err.message}\n`);
  });
  server.listen(PORT, address);
}
