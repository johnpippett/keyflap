const repo = process.env.REPO;
if (!repo) throw new Error('REPO is not set');
const { startTestRp } = await import(`${repo}/packages/test-rp/src/index.ts`);
const rp = await startTestRp({
  host: 'rp.localhost',
  port: 0,
  users: [
    { username: 'alice', password: 'correct horse battery staple', totpSecret: 'JBSWY3DPEHPK3PXP' },
  ],
});
console.log(JSON.stringify({ url: rp.url, origin: rp.origin }));
const users = [
  { username: 'alice', password: 'correct horse battery staple', totpSecret: 'JBSWY3DPEHPK3PXP' },
];
const extra = {};
for (const [key, mode] of [
  ['waf', 'aws-waf'],
  ['cf', 'cloudflare'],
  ['text', 'text-only'],
]) {
  extra[key] = await startTestRp({ host: `${key}.rp.localhost`, port: 0, users, challenge: mode });
}
extra.hc = await startTestRp({
  host: 'waf.hc.localhost',
  port: 0,
  users: [{ username: 'alice', password: 'correct horse battery staple' }],
  challenge: 'aws-waf',
});
extra.gate = await startTestRp({
  host: 'gate.hc.localhost',
  port: 0,
  users: [{ username: 'alice', password: 'correct horse battery staple' }],
  challenge: 'aws-waf',
  challengeAt: 'login-page',
});
console.log(
  JSON.stringify({
    challenge: Object.fromEntries(Object.entries(extra).map(([k, r]) => [k, r.url])),
  }),
);
process.on('SIGTERM', () =>
  Promise.all([rp.close(), ...Object.values(extra).map((r) => r.close())]).finally(() =>
    process.exit(0),
  ),
);
setInterval(() => {}, 1 << 30);
