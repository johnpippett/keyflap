import type { TermStyle } from '@aab/approver';
import { PromptAborted } from '../passphrase.ts';
import type { ScreenUi } from '../setup/ui.ts';
import { FULL_INSTALL_COMMAND, simpleInstall } from '../simple-install.ts';

export const UNPROTECTED_FLAP = '! UNPROTECTED';

export const UNPROTECTED_HEADLINE = 'This is the unprotected version of Keyflap.';

export const UNPROTECTED_MEANING =
  "It runs as you, so an agent running as you can read Keyflap's files and change its code.";

export const UNPROTECTED_WAY_OUT =
  'The protected version stops that. It is the full install: Tab shows the command.';

const BANG = ['', '  ████  ', '  ████  ', '  ████  ', '  ████  ', '', '  ████  ', ''];

export function bang(st: TermStyle): string {
  return BANG.map((row) => st.bad(row.padEnd(8))).join('\n');
}

export function unprotectedDetails(o: { simple: boolean; home: string }): string {
  const lines = [
    'Why it protects less:',
    o.simple
      ? '  This is the simple install: Keyflap runs in the background as you.'
      : '  This is dev mode (keyflap daemon --unprotected): Keyflap runs as you.',
    "  A process that runs as you can read Keyflap's key file and data, change the code it runs",
    "  from, and read the broker's memory. Passwords and passkeys still stay out of the agent's",
    '  context, and every sign-in still needs your approval, but nothing stops an agent that',
    '  runs commands as you from reaching around them.',
    '',
    'The protected version:',
    '  The full install runs Keyflap as its own system users, which an agent running as you',
    '  cannot read or change:',
    `    ${FULL_INSTALL_COMMAND}`,
    '  More: docs/integrations/service-mode.md',
  ];
  if (o.simple) {
    lines.push(
      '',
      'Switching:',
      '  The full installer refuses while the simple install is there. Run the uninstaller first:',
      `    "${simpleInstall(o.home).uninstaller}"`,
      '  Nothing moves across: the full install starts a new key store.',
    );
  }
  return lines.join('\n');
}

export async function showUnprotected(
  ui: ScreenUi,
  o: { style: TermStyle; simple: boolean; home: string },
): Promise<boolean> {
  try {
    await ui.page('Unprotected', 'replace');
    ui.brief(
      {
        art: bang(o.style),
        beside: `${o.style.bold(UNPROTECTED_HEADLINE)}\n\n${UNPROTECTED_MEANING}`,
      },
      unprotectedDetails(o),
      { log: false },
    );
    ui.out(UNPROTECTED_WAY_OUT);
    await ui.hold('Press Enter to continue');
    return true;
  } catch (err) {
    if (err instanceof PromptAborted) return false;
    throw err;
  }
}
