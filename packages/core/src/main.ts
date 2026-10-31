import { mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { ApproverKey, TerminalApprover } from '@aab/approver';
import { startDaemon } from './daemon.ts';

const { values } = parseArgs({
  options: {
    url: { type: 'string' },
    intent: { type: 'string' },
    'data-dir': { type: 'string', default: join(homedir(), '.keyflap') },
    headless: { type: 'boolean', default: false },
  },
});

const passphrase = process.env.KEYFLAP_DEV_PASSPHRASE;
if (!passphrase) {
  console.error('Set KEYFLAP_DEV_PASSPHRASE to unlock the dev key store.');
  process.exit(2);
}
if (!values.intent) {
  console.error(
    'Pass --intent "<what you asked the agent to do>". Requests without a live intent are denied.',
  );
  process.exit(2);
}

const dataDir = values['data-dir'] as string;
mkdirSync(dataDir, { recursive: true, mode: 0o700 });
const approverKey = ApproverKey.loadOrCreate(join(dataDir, 'approver-key.json'));
const runtime = await startDaemon({
  dataDir,
  passphrase,
  approver: new TerminalApprover({ key: approverKey }),
  trustedApproverKeys: approverKey.trustEntry(),
  headless: values.headless,
  onSignerLog: (line) => console.error(line),
});
const agent =
  runtime.registry.list().find((a) => a.name === 'dev-agent' && a.revokedAt === null) ??
  runtime.registry.add('dev-agent');
runtime.broker.intents.record(agent.id, values.intent);

const session = await runtime.sessions.get(agent);
const page = await session.newPage();
if (values.url) await page.goto(values.url);
console.error(`broker running; data dir ${dataDir}. Ctrl-C to stop.`);

const stop = async () => {
  await runtime.stop();
  process.exit(0);
};
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
