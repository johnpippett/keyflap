import {
  checkedPrompt,
  HookFailure,
  type HookOptions,
  type HookOutcome,
  type ParsedHookInput,
  parseHookObject,
  runHook,
} from './hook-core.ts';

export {
  DEFAULT_HOOK_TIMEOUT_MS,
  type HookOptions,
  type HookOutcome,
  MAX_HOOK_INPUT,
  MAX_PROMPT,
  readHostToken,
} from './hook-core.ts';

const HOST_CONTEXT_OPEN = '<system-reminder>';
const HOST_CONTEXT_CLOSE = '</system-reminder>';

function withoutLeadingHostContext(prompt: string): string {
  let rest = prompt;
  for (;;) {
    const trimmed = rest.trimStart();
    if (!trimmed.startsWith(HOST_CONTEXT_OPEN)) return rest === prompt ? prompt : trimmed;
    const end = trimmed.indexOf(HOST_CONTEXT_CLOSE);
    if (end < 0) return rest === prompt ? prompt : trimmed;
    rest = trimmed.slice(end + HOST_CONTEXT_CLOSE.length);
  }
}

export function promptFromHookInput(raw: Buffer): ParsedHookInput {
  const o = parseHookObject(raw);
  if (o.hook_event_name !== undefined && o.hook_event_name !== 'UserPromptSubmit') {
    return { skip: 'not a UserPromptSubmit event' };
  }
  if (o.agent_id !== undefined) return { skip: 'fired inside a subagent' };
  if (
    o.prompt_type !== undefined &&
    o.prompt_type !== 'user_input' &&
    o.prompt_type !== 'slash_command'
  ) {
    return { skip: 'prompt type is not user input' };
  }
  if (typeof o.prompt !== 'string') throw new HookFailure('malformed hook input (no prompt)');
  const prompt = withoutLeadingHostContext(o.prompt);
  if (prompt.trim().length === 0) return { skip: 'empty prompt' };
  if (/^\s*<task-notification>/.test(prompt)) return { skip: 'background task report' };
  return checkedPrompt(prompt);
}

export function runClaudeCodeHook(opts: HookOptions): Promise<HookOutcome> {
  return runHook(opts, promptFromHookInput);
}
