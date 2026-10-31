import { CONNECTED } from './listings.ts';
import { type Action, type Answers, SECTIONS, type Section } from './menu.ts';

const PROBE: Answers = {
  tool: { value: 'pass-cli', words: 'pass-cli' },
};

function fullInstallOnly(a: Action): boolean {
  if (a.kind === 'pick') return a.argv === CONNECTED.argv;
  if (a.kind !== 'form') return false;
  try {
    return a.build(PROBE).argv[0] === 'password-source';
  } catch {
    return false;
  }
}

export function devSections(sections: readonly Section[] = SECTIONS): readonly Section[] {
  return sections.map((s) => ({ ...s, actions: s.actions.filter((a) => !fullInstallOnly(a)) }));
}
