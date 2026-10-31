import {
  checkedPrompt,
  HookFailure,
  type HookOptions,
  type HookOutcome,
  type ParsedHookInput,
  parseHookObject,
  runHook,
} from './hook-core.ts';

export const HUMAN_PLATFORMS: readonly string[] = [
  'telegram',
  'discord',
  'slack',
  'signal',
  'whatsapp',
  'whatsapp_cloud',
  'matrix',
  'mattermost',
  'bluebubbles',
];

export const GOAL_ALREADY_SEEN_KICK =
  '[Goal set] Continue with the goal you were just given; there is no need to re-read it.';

export interface HermesOwner {
  platform: string;
  userId: string;
}

export interface HermesFilter {
  owners: readonly HermesOwner[];
  profile: string | null;
}

export function parseOwner(v: string): HermesOwner {
  const i = v.indexOf(':');
  const platform = i < 0 ? '' : v.slice(0, i).trim().toLowerCase();
  const userId = i < 0 ? '' : v.slice(i + 1);
  if (!HUMAN_PLATFORMS.includes(platform)) {
    throw new Error(
      `--owner must be <platform>:<user id> with platform one of ${HUMAN_PLATFORMS.join(', ')}; got "${v.slice(0, 40)}"`,
    );
  }
  if (!/^[\x21-\x7e]{1,128}$/.test(userId)) {
    throw new Error('--owner user id must be 1-128 printable characters without spaces');
  }
  return { platform, userId };
}

const str = (v: unknown): v is string => typeof v === 'string';

export function promptFromHermesInput(raw: Buffer, filter: HermesFilter): ParsedHookInput {
  const o = parseHookObject(raw);
  if (o.event !== 'post_gateway_admission') return { skip: 'not a post_gateway_admission event' };
  const s = o.source;
  if (typeof s !== 'object' || s === null || Array.isArray(s)) {
    throw new HookFailure('malformed hook input (no source)');
  }
  const source = s as Record<string, unknown>;
  const platform = o.platform;
  if (!str(platform) || !HUMAN_PLATFORMS.includes(platform)) {
    return { skip: 'not a human chat platform' };
  }
  if (source.platform !== platform) return { skip: 'platform mismatch' };
  if (source.chat_type !== 'dm') return { skip: 'not a direct message' };
  if (source.is_bot !== undefined && source.is_bot !== false) return { skip: 'sent by a bot' };
  const userId = source.user_id;
  if (!str(userId) && typeof userId !== 'number') return { skip: 'no sender' };
  const sender = String(userId);
  if (!filter.owners.some((w) => w.platform === platform && w.userId === sender)) {
    return { skip: 'not from an owner' };
  }
  const profile = source.profile ?? null;
  if (profile !== filter.profile && !(filter.profile === null && profile === '')) {
    return { skip: 'another Hermes profile' };
  }
  const id = o.message_id;
  if (!((str(id) && id.length > 0) || (typeof id === 'number' && Number.isFinite(id)))) {
    return { skip: 'no platform message id (synthetic turn)' };
  }
  if (!str(o.text)) throw new HookFailure('malformed hook input (no text)');
  if (o.text.trim() === GOAL_ALREADY_SEEN_KICK) return { skip: 'Hermes goal kick-off' };
  return checkedPrompt(o.text);
}

export function runHermesHook(opts: HookOptions & HermesFilter): Promise<HookOutcome> {
  const filter = { owners: opts.owners, profile: opts.profile };
  return runHook(opts, (raw) => promptFromHermesInput(raw, filter));
}
