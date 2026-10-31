import type { System } from './system.ts';

export interface UserInfo {
  uid: number;
  gid: number;
  name: string;
  home: string;
}

export type UserQuery = { uid: number } | { name: string };

const ID_BIN = '/usr/bin/id';

export function parsePasswdLine(line: string): UserInfo | null {
  const f = line.split(':');
  if (f.length < 7) return null;
  const uid = Number(f[2]);
  const gid = Number(f[3]);
  const name = f[0] as string;
  const home = f[f.length - 2] as string;
  if (!Number.isInteger(uid) || !Number.isInteger(gid) || name === '' || home === '') return null;
  return { uid, gid, name, home };
}

function matches(user: UserInfo, q: UserQuery): boolean {
  return 'uid' in q ? user.uid === q.uid : user.name === q.name;
}

function passwdUser(sys: System, q: UserQuery): UserInfo | null {
  const text = sys.readFile('/etc/passwd');
  if (text === null) return null;
  for (const line of text.split('\n')) {
    const user = parsePasswdLine(line);
    if (user && matches(user, q)) return user;
  }
  return null;
}

async function directoryServicesUser(sys: System, q: UserQuery): Promise<UserInfo | null> {
  const who = 'uid' in q ? String(q.uid) : q.name;
  if (!/^[A-Za-z0-9_][A-Za-z0-9._-]*$/.test(who)) return null;
  const r = await sys.exec(ID_BIN, ['-P', who], { timeoutMs: 5_000 });
  if (r.code !== 0) return null;
  const user = parsePasswdLine(r.stdout.trim().split('\n')[0] ?? '');
  if (!user) return null;
  if ('uid' in q && user.uid !== q.uid) return null;
  return user;
}

export function lookupUser(sys: System, q: UserQuery): Promise<UserInfo | null> {
  return sys.platform === 'darwin'
    ? directoryServicesUser(sys, q)
    : Promise.resolve(passwdUser(sys, q));
}
