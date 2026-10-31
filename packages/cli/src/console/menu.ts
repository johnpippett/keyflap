import { SOURCES } from '../service/password-source.ts';
import { importExport } from '../setup/import-step.ts';
import type { SetupContext } from '../setup/steps.ts';
import { addPassword, agentStep, onePassword, pairStep, protonPass } from '../setup/steps.ts';
import {
  AGENTS,
  agentWords,
  CONNECTED,
  KEPT,
  type Listing,
  PASSWORDS,
  PHONES,
  passwordWords,
  phoneWords,
  RULES,
  ruleWords,
  SESSIONS,
  scopeArgs,
} from './listings.ts';
import { type Snapshot, sourceName } from './overview.ts';

export type Argv = readonly string[];

export interface Change {
  argv: Argv;
  confirm: string;
}

export interface Choice extends Change {
  label: string;
}

export type Field =
  | { kind: 'text'; key: string; question: string; required: boolean }
  | {
      kind: 'choice';
      key: string;
      question: string;
      options: readonly (readonly [string, string])[];
    }
  | { kind: 'agent'; key: string; question: string };

export interface Answer {
  value: string;
  words: string;
}

export type Answers = Readonly<Record<string, Answer>>;

export type Action =
  | { kind: 'show'; label: string; argv: Argv }
  | { kind: 'list'; label: string; argv: Argv; none: string; rows(json: unknown): string[] }
  | {
      kind: 'pick';
      label: string;
      argv: Argv;
      none: string;
      choices(json: unknown): Choice[];
    }
  | {
      kind: 'form';
      label: string;
      fields: readonly Field[];
      when?: (key: string, a: Answers) => boolean;
      build(a: Answers): Change;
    }
  | { kind: 'flow'; label: string; flow(ctx: SetupContext): Promise<unknown> }
  | { kind: 'doctor'; label: string };

export interface Section {
  title: string;
  intro(s: Snapshot): string;
  actions: readonly Action[];
}

function list<T>(label: string, l: Listing<T>, keep: (t: T) => boolean = () => true): Action {
  return {
    kind: 'list',
    label,
    argv: l.argv,
    none: l.none,
    rows: (json) => l.parse(json).filter(keep).map(l.label),
  };
}

function pick<T>(
  label: string,
  l: Listing<T>,
  o: {
    keep?: (t: T) => boolean;
    none?: string;
    argv: (t: T) => Argv;
    confirm: (t: T) => string;
  },
): Action {
  return {
    kind: 'pick',
    label,
    argv: l.argv,
    none: o.none ?? l.none,
    choices: (json) =>
      l
        .parse(json)
        .filter(o.keep ?? (() => true))
        .map((t) => ({
          label: l.label(t),
          argv: o.argv(t),
          confirm: o.confirm(t),
        })),
  };
}

const flow = (label: string, run: (ctx: SetupContext) => Promise<unknown>): Action => ({
  kind: 'flow',
  label,
  flow: run,
});

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

const SITE: Field = {
  kind: 'text',
  key: 'site',
  question: 'Site (a domain such as example.com, or https://app.example.com)',
  required: true,
};

const MODES = [
  ['ask', 'Ask every time (the default)'],
  ['ask-strong', 'Ask on the phone with Face ID or a PIN'],
  ['allow-for', 'After one approval, no prompts for a while'],
  ['deny', 'Never sign in here'],
] as const;

const MODE_WORDS: Record<string, string> = {
  ask: 'ask every time',
  'ask-strong': 'ask with Face ID or a PIN',
  'allow-for': 'skip the prompt after an approval',
  deny: 'never sign in',
};

const active = (a: { revokedAt: number | null }) => a.revokedAt === null;

export const SECTIONS: readonly Section[] = [
  {
    title: 'Passwords',
    intro: (s) => `${plural(s.passwords, 'password')} stored.`,
    actions: [
      list('See them', PASSWORDS),
      flow('Add one', addPassword),
      flow('Import a CSV export', importExport),
      pick('Remove one', PASSWORDS, {
        keep: (p) => p.source === 'native',
        none: "No password stored in Keyflap itself. A password manager's logins are removed there.",
        argv: (p) => ['password', 'remove', p.id],
        confirm: (p) => `Remove the password for ${passwordWords(p)}?`,
      }),
    ],
  },
  {
    title: 'Password managers',
    intro: (s) =>
      s.passwordSource
        ? `${sourceName(s.passwordSource)} is connected. Keyflap uses one at a time: connecting another replaces it.`
        : 'None is connected: agents get the passwords stored in Keyflap itself.',
    actions: [
      flow('Connect Proton Pass', protonPass),
      flow('Connect 1Password', onePassword),
      {
        kind: 'form',
        label: 'Trust an updated tool',
        fields: [
          {
            kind: 'choice',
            key: 'tool',
            question: 'Which tool did you update?',
            options: [
              ['pass-cli', 'pass-cli (Proton Pass)'],
              ['op', 'op (1Password)'],
            ],
          },
        ],
        build: (a) => ({
          argv: ['password-source', 'trust', a.tool?.value ?? ''],
          confirm: `Trust the ${a.tool?.value} on this computer as it is now? Check it is genuine first.`,
        }),
      },
      pick('Disconnect', CONNECTED, {
        none: 'No password manager is connected.',
        argv: () => ['password-source', 'remove'],
        confirm: (k) => {
          const def = SOURCES[k];
          return `Disconnect ${def.name}? Agents stop using its logins. ${def.keepsLogins}`;
        },
      }),
    ],
  },
  {
    title: 'Phones',
    intro: (s) =>
      s.phones === 0 ? 'No phone paired yet.' : `${plural(s.phones, 'phone')} paired.`,
    actions: [
      list('See them', PHONES),
      flow('Pair a phone', pairStep),
      pick('Remove one', PHONES, {
        argv: (p) => ['approver', 'remove', p.id],
        confirm: (p) => `Remove the ${phoneWords(p)}? It can no longer approve.`,
      }),
    ],
  },
  {
    title: 'Agents',
    intro: (s) => `${plural(s.agents, 'active agent')}.`,
    actions: [
      list('See them', AGENTS, active),
      flow('Add one and set up its app', agentStep),
      pick('Revoke one', AGENTS, {
        keep: active,
        argv: (a) => ['agent', 'revoke', a.id],
        confirm: (a) =>
          `Revoke ${agentWords(a)}? Its token and browser session stop now, for good.`,
      }),
    ],
  },
  {
    title: 'Sign-in rules',
    intro: () => 'Every sign-in asks by default. A rule changes that for one site.',
    actions: [
      list('See them', RULES),
      {
        kind: 'form',
        label: 'Set a rule',
        fields: [
          SITE,
          { kind: 'agent', key: 'agent', question: 'For which agent?' },
          { kind: 'choice', key: 'mode', question: 'What should happen?', options: MODES },
          {
            kind: 'text',
            key: 'for',
            question: 'For how long after an approval (such as 30m or 2h; at most 24h)',
            required: true,
          },
        ],
        when: (key, a) => key !== 'for' || a.mode?.value === 'allow-for',
        build: (a) => {
          const mode = a.mode?.value ?? 'ask';
          const site = a.site?.value ?? '';
          const time = mode === 'allow-for' ? (a.for?.value ?? '') : '';
          return {
            argv: [
              'policy',
              'set',
              site,
              `--${mode}`,
              ...(time ? [time] : []),
              ...scopeArgs(a.agent?.value ?? ''),
            ],
            confirm: `${site}: ${MODE_WORDS[mode]}${time ? ` for ${time}` : ''}, for ${a.agent?.words}?`,
          };
        },
      },
      pick('Remove one', RULES, {
        argv: (r) => ['policy', 'remove', r.site, ...scopeArgs(r.agentId)],
        confirm: (r) => `Remove the rule ${ruleWords(r)}?`,
      }),
    ],
  },
  {
    title: 'Saved sessions',
    intro: () =>
      "Each agent's browser stays signed in between restarts. High-risk sites only when you keep them.",
    actions: [
      list('See them', SESSIONS),
      {
        kind: 'form',
        label: 'Sign agents out',
        fields: [
          { kind: 'agent', key: 'agent', question: 'Which agent?' },
          {
            kind: 'text',
            key: 'site',
            question: 'Which site (blank: every site)',
            required: false,
          },
        ],
        build: (a) => {
          const agent = a.agent?.value ?? '';
          const site = a.site?.value ?? '';
          return {
            argv: [
              'sessions',
              'clear',
              ...(agent === '' ? ['--all'] : ['--agent', agent]),
              ...(site ? ['--site', site] : []),
            ],
            confirm: `Sign ${a.agent?.words} out of ${site || 'every site'}? The saved cookies and storage are deleted.`,
          };
        },
      },
      {
        kind: 'form',
        label: 'Keep a high-risk site signed in',
        fields: [SITE, { kind: 'agent', key: 'agent', question: 'For which agent?' }],
        build: (a) => ({
          argv: ['sessions', 'keep', a.site?.value ?? '', ...scopeArgs(a.agent?.value ?? '')],
          confirm: `Keep ${a.site?.value} signed in across restarts, for ${a.agent?.words}?`,
        }),
      },
      pick('Stop keeping one', KEPT, {
        argv: (k) => ['sessions', 'unkeep', k.site, ...scopeArgs(k.agentId)],
        confirm: (k) => `Stop keeping ${k.site}? Its saved session is dropped.`,
      }),
    ],
  },
  {
    title: 'Health',
    intro: () => '',
    actions: [
      { kind: 'show', label: 'Status', argv: ['status'] },
      { kind: 'doctor', label: 'Run the checks' },
      { kind: 'show', label: 'Check the audit log', argv: ['audit', 'verify'] },
      { kind: 'show', label: 'Recent activity', argv: ['audit', 'tail', '--limit', '20'] },
    ],
  },
];
