import { describe, expect, it } from 'vitest';
import { DARWIN_SERVICE_PATHS } from '../src/service/paths.ts';
import { serviceBackend } from '../src/setup/backend.ts';
import { lookupUser, parsePasswdLine } from '../src/setup/users.ts';
import { FakeSystem } from './setup-fakes.ts';

const PASSWD = [
  'root:x:0:0:root:/root:/bin/bash',
  'keyflap-signer:x:990:990::/var/lib/keyflap/signer:/usr/sbin/nologin',
  'u:x:1000:1000:U Ser:/home/u:/bin/bash',
  'broken line',
  '',
].join('\n');

const MAC_ID_P = (who: string) =>
  ({
    '501': 'sam:********:501:20::0:0:Sam:/Users/sam:/bin/zsh\n',
    sam: 'sam:********:501:20::0:0:Sam:/Users/sam:/bin/zsh\n',
    'keyflap-signer':
      '_keyflap-signer:*:492:492::0:0:Keyflap signer:/Library/Keyflap/data/signer:/usr/bin/false\n',
    '_keyflap-signer':
      '_keyflap-signer:*:492:492::0:0:Keyflap signer:/Library/Keyflap/data/signer:/usr/bin/false\n',
  })[who];

function mac(): FakeSystem {
  const sys = new FakeSystem();
  sys.platform = 'darwin';
  sys.exec_ = (cmd, args) => {
    const line =
      cmd === '/usr/bin/id' && args[0] === '-P' ? MAC_ID_P(args[1] as string) : undefined;
    return line === undefined
      ? { code: 1, stdout: '', stderr: `id: ${args[1]}: no such user\n` }
      : { code: 0, stdout: line, stderr: '' };
  };
  return sys;
}

describe('passwd lines', () => {
  it('reads the 7-field Linux and the 10-field macOS shapes: home is the field before the shell', () => {
    expect(parsePasswdLine('u:x:1000:1000:U Ser:/home/u:/bin/bash')).toEqual({
      uid: 1000,
      gid: 1000,
      name: 'u',
      home: '/home/u',
    });
    expect(parsePasswdLine('sam:********:501:20::0:0:Sam:/Users/sam:/bin/zsh')).toEqual({
      uid: 501,
      gid: 20,
      name: 'sam',
      home: '/Users/sam',
    });
    expect(parsePasswdLine('broken line')).toBeNull();
    expect(parsePasswdLine('u:x:abc:1000::/home/u:/bin/sh')).toBeNull();
    expect(parsePasswdLine('')).toBeNull();
  });
});

describe('user lookup on Linux: /etc/passwd through System', () => {
  it('finds a user by uid or by name, and nobody when the file or the entry is missing', async () => {
    const sys = new FakeSystem();
    expect(await lookupUser(sys, { uid: 1000 })).toBeNull();
    sys.file('/etc/passwd', PASSWD, 0o644, 0);
    expect(await lookupUser(sys, { uid: 1000 })).toEqual({
      uid: 1000,
      gid: 1000,
      name: 'u',
      home: '/home/u',
    });
    expect(await lookupUser(sys, { name: 'keyflap-signer' })).toMatchObject({ uid: 990, gid: 990 });
    expect(await lookupUser(sys, { uid: 7 })).toBeNull();
    expect(await lookupUser(sys, { name: 'nobody-here' })).toBeNull();
    expect(sys.execs).toEqual([]);
  });
});

describe('user lookup on macOS: Directory Services through System (/usr/bin/id -P)', () => {
  it('finds a user by uid or by name and never opens /etc/passwd', async () => {
    const sys = mac();
    sys.file('/etc/passwd', 'root:*:0:0:System Administrator:/var/root:/bin/sh\n', 0o644, 0);
    expect(await lookupUser(sys, { uid: 501 })).toEqual({
      uid: 501,
      gid: 20,
      name: 'sam',
      home: '/Users/sam',
    });
    expect(await lookupUser(sys, { name: 'sam' })).toMatchObject({ uid: 501 });
    expect(sys.reads).not.toContain('/etc/passwd');
    expect(sys.execs.map((e) => `${e.cmd} ${e.args.join(' ')}`)).toEqual([
      '/usr/bin/id -P 501',
      '/usr/bin/id -P sam',
    ]);
  });

  it('resolves a service user by either RecordName and reports the primary one', async () => {
    const sys = mac();
    for (const name of ['keyflap-signer', '_keyflap-signer']) {
      expect(await lookupUser(sys, { name })).toEqual({
        uid: 492,
        gid: 492,
        name: '_keyflap-signer',
        home: '/Library/Keyflap/data/signer',
      });
    }
  });

  it('is nobody when id fails, answers for someone else, or the query is not a name', async () => {
    const sys = mac();
    expect(await lookupUser(sys, { uid: 777 })).toBeNull();
    expect(await lookupUser(sys, { name: 'nobody-here' })).toBeNull();
    sys.exec_ = () => ({ code: 0, stdout: MAC_ID_P('sam') as string, stderr: '' });
    expect(await lookupUser(sys, { uid: 502 })).toBeNull();
    expect(await lookupUser(sys, { name: 'a b; rm -rf /' })).toBeNull();
    expect(await lookupUser(sys, { name: '-x' })).toBeNull();
    expect(sys.execs.map((e) => e.args[1])).toEqual(['777', 'nobody-here', '502']);
  });

  it('serviceBackend on a Mac names the hook-dir owner from Directory Services', async () => {
    const sys = mac();
    sys.uid = 0;
    sys.dir(DARWIN_SERVICE_PATHS.hookDir, 0o700, 501);
    const admin = async <T>(): Promise<T> => ({}) as T;
    const b = await serviceBackend({ sys, paths: DARWIN_SERVICE_PATHS, admin });
    expect(b.user).toEqual({ uid: 501, gid: 20, name: 'sam', home: '/Users/sam' });
    expect(b.fileOwner).toEqual({ uid: 501, gid: 20 });
    expect(b.hookCommand('a')).toBe('/usr/local/bin/keyflap hook claude-code --agent a --service');
  });
});
