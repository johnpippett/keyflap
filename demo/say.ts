import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { Readable } from 'node:stream';
import { runClaudeCodeHook } from '../packages/cli/src/hook-claude-code.ts';

const dataDir = join(homedir(), '.keyflap');
const args = process.argv.slice(2);
const hookMode = args[0] === '--claude-code-hook';

function agentId(): string {
  return readFileSync(join(dataDir, 'demo-agent-id'), 'utf8').trim();
}

async function readWords(): Promise<string> {
  if (args.length > 0) return args.join(' ');
  if (!process.stdin.isTTY) {
    process.stderr.write('usage: say "what you asked your agent to do"\n');
    process.exit(2);
  }
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  const line = await new Promise<string>((resolve) =>
    rl.question('What did you ask your agent to do? ', resolve),
  );
  rl.close();
  return line;
}

if (hookMode) {
  process.stdout.write = (() => true) as typeof process.stdout.write;
  try {
    await runClaudeCodeHook({
      dataDir,
      agentId: agentId(),
      stdin: process.stdin,
      log: (line) => process.stderr.write(`${line}\n`),
    });
  } catch {
    process.stderr.write('say: intent not recorded (is the demo running?)\n');
  }
  process.exit(0);
}

const words = (await readWords()).trim();
if (words.length === 0) {
  process.stderr.write('say: nothing to record\n');
  process.exit(2);
}
const errors: string[] = [];
const outcome = await runClaudeCodeHook({
  dataDir,
  agentId: agentId(),
  stdin: Readable.from([JSON.stringify({ hook_event_name: 'UserPromptSubmit', prompt: words })]),
  log: (line) => errors.push(line),
});
if (outcome === 'recorded') {
  process.stdout.write(
    `Recorded. For the next 10 minutes the approval prompt will show:\n  "${words}"\n`,
  );
} else {
  process.stderr.write(`${errors.join('\n') || 'say: intent not recorded'}\n`);
  process.exit(1);
}
