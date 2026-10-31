import type { TermStyle } from '@aab/approver';
import { runSetupFlow } from '../src/setup/run.ts';
import { type Frame, type Key, type Painted, paint, type Size } from '../src/setup/screen.ts';
import { type Keys, type Screen, ScreenUi, SetupLog } from '../src/setup/ui.ts';
import { type Platform, type Scenario, type ScenarioName, scenario } from './setup-scenarios.ts';

export interface Shot {
  caption: string;
  painted: Painted;
  frame: Frame;
}

export interface Capture {
  shots: Shot[];
  log: string;
  after: string;
  run: Scenario;
}

const clone = (f: Frame): Frame => structuredClone(f);

function caption(f: Frame, what: string): string {
  const where = f.step ? `${f.step.n}. ${f.step.title}` : 'Welcome';
  return `${where}${f.page ? ` · ${f.page}` : ''}: ${what}`;
}

export async function capture(
  name: ScenarioName,
  o: { size: Size; style: TermStyle; platform?: Platform },
): Promise<Capture> {
  const shots: Shot[] = [];
  let last: { painted: Painted; frame: Frame } | null = null;
  let lastStatus: string | null = null;
  let lastDetails = '';
  const shoot = (what: string, f: Frame, painted: Painted) => {
    shots.push({ caption: caption(f, what), painted, frame: clone(f) });
  };
  const screen: Screen = {
    size: () => o.size,
    enter: () => {},
    restore: () => {},
    draw(p, f) {
      last = { painted: p, frame: clone(f) };
      const label = f.status?.label ?? null;
      if (label !== null && label !== lastStatus) shoot(label, f, p);
      lastStatus = label;
    },
  };
  let run: Scenario | null = null;
  const queue: Key[] = [];
  let inputSeen: object | null = null;
  const keys: Keys = {
    open() {},
    async next(f) {
      const input = f.input;
      if (!input) throw new Error('capture: asked for a key with no input on screen');
      if (input !== inputSeen) {
        inputSeen = input;
        queue.length = 0;
        if (input.kind === 'continue') {
          queue.push({ kind: 'enter' });
        } else {
          const answers = (run as Scenario).answers;
          const next = answers.shift();
          if (!next?.q.test(input.label)) {
            throw new Error(`capture: no canned answer for "${input.label}" (next: ${next?.q})`);
          }
          if (input.kind === 'menu') {
            if (next.a !== '') queue.push({ kind: 'char', ch: next.a });
          } else {
            for (const ch of next.a) queue.push({ kind: 'char', ch });
          }
          queue.push({ kind: 'enter' });
        }
      }
      const k = queue.shift() as Key;
      if (k.kind === 'enter' && last) {
        const what = input.label;
        const details = f.details.join('\n');
        shoot(what, last.frame, last.painted);
        if (details !== '' && details !== lastDetails) {
          lastDetails = details;
          const d = { ...clone(last.frame), view: 'details' as const, scroll: 0 };
          shoot('Tab: details', d, paint(d, o.size, o.style));
        }
      }
      return k;
    },
    flush() {},
    close() {},
  };
  let after = '';
  const log = new SetupLog('2026-10-30T09:00:00.000Z');
  const ui = new ScreenUi({
    screen,
    keys,
    style: o.style,
    mode: 'service mode',
    log,
    afterLeave: (t) => {
      after += t;
    },
    fallbackPrompt: {
      ask: () => Promise.reject(new Error('capture: prompt after leaving the screen')),
      secret: () => Promise.reject(new Error('capture: prompt after leaving the screen')),
    },
  });
  run = scenario(name, { ui, ...(o.platform ? { platform: o.platform } : {}) });
  await runSetupFlow(run.ctx, { mode: run.mode });
  if (run.answers.length > 0) {
    throw new Error(
      `capture: ${run.answers.length} canned answers left over (${run.answers[0]?.q})`,
    );
  }
  const logPath = `${run.backend.stateDir}/setup.log`;
  return { shots, log: run.sys.text(logPath) ?? '', after, run };
}
