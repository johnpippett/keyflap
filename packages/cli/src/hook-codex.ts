import {
  checkedPrompt,
  HookFailure,
  type HookOptions,
  type HookOutcome,
  type ParsedHookInput,
  parseHookObject,
  runHook,
} from './hook-core.ts';

export function promptFromCodexInput(raw: Buffer): ParsedHookInput {
  const o = parseHookObject(raw);
  if (o.hook_event_name !== 'UserPromptSubmit') return { skip: 'not a UserPromptSubmit event' };
  if (o.agent_id !== undefined || o.agent_type !== undefined) {
    return { skip: 'fired inside a subagent' };
  }
  if (typeof o.prompt !== 'string') throw new HookFailure('malformed hook input (no prompt)');
  return checkedPrompt(o.prompt);
}

export function runCodexHook(opts: HookOptions): Promise<HookOutcome> {
  return runHook(opts, promptFromCodexInput);
}
