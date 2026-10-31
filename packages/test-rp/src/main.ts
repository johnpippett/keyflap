import { startTestRp } from './server.ts';

const rp = await startTestRp({
  port: Number(process.env.PORT ?? 3000),
  users: [
    { username: 'alice', password: 'correct horse battery staple', totpSecret: 'JBSWY3DPEHPK3PXP' },
  ],
});
const port = new URL(rp.origin).port;
console.log(`test RP listening at ${rp.url} (rpId ${rp.rpId})`);
console.log('seeded user: alice / "correct horse battery staple", TOTP secret JBSWY3DPEHPK3PXP');
console.log(
  `password + TOTP sign-in: http://rp.localhost:${port}/password/login (store it with \`keyflap password add rp.localhost --username alice --totp\`)`,
);
