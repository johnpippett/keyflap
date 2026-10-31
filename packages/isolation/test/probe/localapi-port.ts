const LOCALAPI = '/opt/keyflap/app/packages/signer/src/tailscale-localapi.ts';
const { readLocalApiServeConfig } = (await import(
  LOCALAPI
)) as typeof import('../../../signer/src/tailscale-localapi.ts');

const r = await readLocalApiServeConfig(process.argv[2] ?? '', {
  checkOwners: true,
  timeoutMs: 2_000,
  maxBytes: 65_536,
});
process.stdout.write(`${JSON.stringify(r)}\n`);
