import type { TermStyle } from '@aab/approver';
import { type Command, parseCli } from '../args.ts';
import { formatReport } from '../doctor.ts';
import { choose, confirm, PromptAborted } from '../setup/prompt.ts';
import { doctorSummary, type SetupContext } from '../setup/steps.ts';
import type { ScreenUi } from '../setup/ui.ts';
import { AGENTS } from './listings.ts';
import {
  type Action,
  type Answer,
  type Answers,
  type Argv,
  type Change,
  type Choice,
  type Field,
  SECTIONS,
  type Section,
} from './menu.ts';
import { type AddressWords, overview, parseStatus, type Snapshot } from './overview.ts';

export const CONSOLE_COMMANDS: ReadonlySet<Command['kind']> = new Set<Command['kind']>([
  'status',
  'audit-verify',
  'audit-tail',
  'password-list',
  'password-remove',
  'password-source-trust',
  'password-source-remove',
  'agent-list',
  'agent-revoke',
  'approver-list',
  'approver-remove',
  'policy-list',
  'policy-set',
  'policy-remove',
  'sessions-list',
  'sessions-clear',
  'sessions-keep',
  'sessions-unkeep',
]);

export class ConsoleRefused extends Error {}

export function consoleCommand(argv: Argv): Command {
  const cmd = parseCli(argv);
  if (!CONSOLE_COMMANDS.has(cmd.kind)) {
    throw new ConsoleRefused(`the console does not run keyflap ${argv.slice(0, 2).join(' ')}`);
  }
  return cmd;
}

export type Dispatch = (cmd: Command, out: (text: string) => void) => Promise<void>;

export interface ConsoleIo {
  ui: ScreenUi;
  ctx: SetupContext;
  dispatch: Dispatch;
  style: TermStyle;
  snapshot(): Promise<Snapshot>;
  settle?(): Promise<void>;
}

export async function statusSnapshot(dispatch: Dispatch, words: AddressWords): Promise<Snapshot> {
  let text = '';
  await dispatch(consoleCommand(['status', '--json']), (t) => {
    text += t;
  });
  return parseStatus(text, words);
}

class CommandFailed extends Error {
  readonly output: string;
  constructor(message: string, output: string) {
    super(message);
    this.output = output;
  }
}

interface State {
  snap: Snapshot | null;
  error: string | null;
}

const SHOW_LINES = 12;
const CLIP = 72;
const PICK_MAX = 9;

const clip = (s: string) => (Array.from(s).length > CLIP ? `${s.slice(0, CLIP - 1)}…` : s);

async function command(io: ConsoleIo, cmd: Command): Promise<string> {
  let text = '';
  try {
    await io.ui.wait('Asking Keyflap', () =>
      io.dispatch(cmd, (t) => {
        text += t;
      }),
    );
  } catch (err) {
    throw new CommandFailed((err as Error).message, text);
  }
  return text;
}

async function json(io: ConsoleIo, argv: Argv): Promise<unknown> {
  const text = await command(io, consoleCommand(argv));
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`unexpected output from keyflap ${argv.slice(0, 2).join(' ')}`);
  }
}

function show(ui: ScreenUi, text: string): void {
  const lines = text.replace(/\n+$/, '').split('\n');
  if (lines.length <= SHOW_LINES) {
    ui.out(text);
    return;
  }
  const head = lines.slice(0, SHOW_LINES - 1).map(clip);
  ui.brief(
    `${head.join('\n')}\nand ${lines.length - head.length} more: Tab shows them all.`,
    text,
    { log: false },
  );
}

async function refresh(io: ConsoleIo, state: State): Promise<void> {
  try {
    state.snap = await io.ui.wait('Reading the status', () => io.snapshot());
    state.error = null;
  } catch (err) {
    state.snap = null;
    state.error = err instanceof Error ? err.message : 'failed';
  }
}

async function change(io: ConsoleIo, c: Change) {
  const cmd = consoleCommand(c.argv);
  if (!(await confirm(io.ctx.prompt, c.confirm, false))) {
    io.ui.out('Nothing changed.');
    return;
  }
  io.ui.out(`✓ ${(await command(io, cmd)).trim()}`);
}

async function pickOne(io: ConsoleIo, choices: Choice[]): Promise<Choice> {
  let shown = choices;
  while (shown.length > PICK_MAX) {
    const q = (await io.ctx.prompt.ask(`${shown.length} to choose from. Type part of its name`))
      .trim()
      .toLowerCase();
    const found = choices.filter((c) => c.label.toLowerCase().includes(q));
    if (found.length === 0) io.ui.out('Nothing matches that.');
    else shown = found;
  }
  const k = await choose(
    io.ctx.prompt,
    'Which one?',
    shown.map((c, i) => [String(i), c.label] as const),
    '0',
    io.ui.out,
  );
  return shown[Number(k)] as Choice;
}

async function askField(io: ConsoleIo, f: Field): Promise<Answer> {
  const p = io.ctx.prompt;
  switch (f.kind) {
    case 'text':
      for (;;) {
        const v = (await p.ask(f.question)).trim();
        if (v !== '' || !f.required) return { value: v, words: v };
      }
    case 'choice': {
      const v = await choose(p, f.question, f.options, f.options[0]?.[0] ?? '', io.ui.out);
      return { value: v, words: f.options.find(([k]) => k === v)?.[1] ?? v };
    }
    case 'agent': {
      const agents = AGENTS.parse(await json(io, AGENTS.argv)).filter((a) => a.revokedAt === null);
      if (agents.length === 0) return { value: '', words: 'every agent' };
      const v = await choose(
        p,
        f.question,
        [['', 'Every agent'] as const, ...agents.map((a) => [a.id, a.name] as const)],
        '',
        io.ui.out,
      );
      const name = agents.find((a) => a.id === v)?.name;
      return { value: v, words: name === undefined ? 'every agent' : `agent "${name}"` };
    }
  }
}

async function fill(io: ConsoleIo, a: Extract<Action, { kind: 'form' }>): Promise<Answers> {
  const answers: Record<string, Answer> = {};
  for (const f of a.fields) {
    if (a.when && !a.when(f.key, answers)) continue;
    answers[f.key] = await askField(io, f);
  }
  return answers;
}

async function perform(io: ConsoleIo, a: Action): Promise<void> {
  switch (a.kind) {
    case 'show':
      show(io.ui, await command(io, consoleCommand(a.argv)));
      return;
    case 'list': {
      const rows = a.rows(await json(io, a.argv));
      show(io.ui, rows.length === 0 ? a.none : rows.join('\n'));
      return;
    }
    case 'pick': {
      const choices = a.choices(await json(io, a.argv));
      if (choices.length === 0) {
        io.ui.out(a.none);
        return;
      }
      await change(io, await pickOne(io, choices));
      return;
    }
    case 'form': {
      await change(io, a.build(await fill(io, a)));
      return;
    }
    case 'flow':
      await a.flow(io.ctx);
      return;
    case 'doctor': {
      const report = await io.ui.wait('Running the checks', () => io.ctx.doctor());
      io.ui.brief(doctorSummary(report), formatReport(report, io.style), { log: false });
      return;
    }
  }
}

async function home(
  io: ConsoleIo,
  state: State,
  sections: readonly Section[],
  at: number,
): Promise<number | null> {
  io.ui.place(null);
  if (state.snap) {
    const o = overview(state.snap);
    io.ui.brief(o.short, o.full, { log: false });
  } else {
    io.ui.out(`✗ ${state.error ?? 'no status'}`);
  }
  try {
    const k = await choose(
      io.ctx.prompt,
      'What do you want to manage?',
      [...sections.map((s, i) => [String(i), s.title] as const), ['quit', 'Quit'] as const],
      String(at),
      io.ui.out,
    );
    return k === 'quit' ? null : Number(k);
  } catch (err) {
    if (err instanceof PromptAborted) return null;
    throw err;
  }
}

async function settle(io: ConsoleIo): Promise<void> {
  try {
    await io.settle?.();
  } catch (err) {
    io.ui.out(`✗ ${(err as Error).message}`);
  }
}

async function section(io: ConsoleIo, state: State, sections: readonly Section[], i: number) {
  const s = sections[i] as Section;
  let at = '0';
  for (;;) {
    io.ui.place({ n: i + 1, of: sections.length, title: s.title });
    const intro = state.snap ? s.intro(state.snap) : '';
    if (intro !== '') io.ui.out(intro);
    try {
      at = await choose(
        io.ctx.prompt,
        'What now?',
        s.actions.map((a, j) => [String(j), a.label] as const),
        at,
        io.ui.out,
      );
    } catch (err) {
      if (err instanceof PromptAborted) return;
      throw err;
    }
    const action = s.actions[Number(at)] as Action;
    await io.ui.page(action.label, 'replace');
    try {
      await perform(io, action);
    } catch (err) {
      if (err instanceof PromptAborted) continue;
      if (err instanceof CommandFailed && err.output.trim() !== '') show(io.ui, err.output);
      io.ui.out(`✗ ${(err as Error).message}`);
    }
    await settle(io);
    await refresh(io, state);
    try {
      await io.ui.hold('Press Enter to go back');
    } catch (err) {
      if (!(err instanceof PromptAborted)) throw err;
    }
  }
}

export async function runConsole(
  io: ConsoleIo,
  sections: readonly Section[] = SECTIONS,
): Promise<void> {
  const state: State = { snap: null, error: null };
  let at = 0;
  try {
    for (;;) {
      await refresh(io, state);
      const next = await home(io, state, sections, at);
      if (next === null) break;
      at = next;
      await section(io, state, sections, next);
    }
    io.ui.place(null);
  } finally {
    try {
      await io.settle?.();
    } finally {
      io.ui.leave();
    }
  }
}
