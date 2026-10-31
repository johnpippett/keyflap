import { startTestRp } from '@aab/test-rp';

const [host = 'rp.localhost', port = '3000'] = process.argv.slice(2);
const rp = await startTestRp({ host, port: Number(port), userVerification: 'required' });
process.stdout.write(`ready ${rp.url}\n`);
process.on('SIGTERM', () => void rp.close().then(() => process.exit(0)));
