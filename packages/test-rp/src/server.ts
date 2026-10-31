import { randomBytes } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  type AuthenticationResponseJSON,
  generateAuthenticationOptions,
  generateRegistrationOptions,
  type RegistrationResponseJSON,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type WebAuthnCredential,
} from '@simplewebauthn/server';
import {
  accountPage,
  challengePage,
  challengeWidget,
  homePage,
  identifierPage,
  identifierPasswordPage,
  identifierScriptPage,
  loginPage,
  passwordLoginPage,
  signupPage,
  totpPage,
  webauthnJs,
} from './pages.ts';
import { verifyTotp } from './totp.ts';

export interface TestUser {
  username: string;
  id: Uint8Array;
  password?: string;
  totpSecret?: string;
  passkeys: WebAuthnCredential[];
}

interface Session {
  userId?: string;
  challenge?: string;
  pendingTotpUser?: string;
  pendingIdentifier?: string;
}

export interface TestRpOptions {
  host?: string;
  port?: number;
  rpId?: string;
  rpName?: string;
  listenHost?: string;
  userVerification?: 'required' | 'preferred' | 'discouraged';
  users?: { username: string; password?: string; totpSecret?: string }[];
  challenge?: 'aws-waf' | 'cloudflare' | 'frame' | 'text-only';
  challengeAt?: 'after-password' | 'login-page';
  challengeHost?: string;
  invisibleWidget?: boolean;
}

export interface TestRp {
  url: string;
  origin: string;
  rpId: string;
  users: Map<string, TestUser>;
  logins: { username: string; method: 'passkey' | 'password' | 'password+totp' }[];
  requests: { method: string; host: string; path: string }[];
  close(): Promise<void>;
}

export async function startTestRp(opts: TestRpOptions = {}): Promise<TestRp> {
  const host = opts.host ?? 'localhost';
  const rpId = opts.rpId ?? host;
  const rpName = opts.rpName ?? 'Test RP';
  const userVerification = opts.userVerification ?? 'preferred';
  const users = new Map<string, TestUser>();
  const sessions = new Map<string, Session>();
  const logins: TestRp['logins'] = [];
  const requests: TestRp['requests'] = [];
  const challenge = opts.challenge ?? null;
  const onLoginPage = challenge !== null && opts.challengeAt === 'login-page';
  const LOGIN_PAGES = new Set([
    '/login',
    '/password/login',
    '/password/login-id',
    '/password/login-pw',
  ]);
  const challengeHost = opts.challengeHost ?? 'captcha.localhost';
  let origin = '';
  let port = 0;
  const widgetOrigin = () => `http://${challengeHost}:${port}`;
  const cleared = (req: IncomingMessage) =>
    /(?:^|;\s*)rp_clearance=ok(?:;|$)/.test(req.headers.cookie ?? '');
  const sendChallenge = (res: ServerResponse, next?: string) => {
    const page = challengePage(
      challenge === 'frame' ? `${widgetOrigin()}/challenge/widget` : null,
      next,
    );
    if (challenge === 'aws-waf') {
      res.writeHead(405, {
        'content-type': 'text/html; charset=utf-8',
        'x-amzn-waf-action': 'captcha',
      });
    } else if (challenge === 'cloudflare') {
      res.writeHead(403, {
        'content-type': 'text/html; charset=utf-8',
        'cf-mitigated': 'challenge',
      });
    } else {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    }
    res.end(page);
  };

  for (const u of opts.users ?? []) {
    users.set(u.username, { ...u, id: randomBytes(16), passkeys: [] });
  }

  const session = (req: IncomingMessage, res: ServerResponse): Session => {
    const sid = /(?:^|;\s*)sid=([A-Za-z0-9_-]+)/.exec(req.headers.cookie ?? '')?.[1];
    if (sid && sessions.has(sid)) return sessions.get(sid) as Session;
    const id = randomBytes(18).toString('base64url');
    const s: Session = {};
    sessions.set(id, s);
    res.setHeader('set-cookie', `sid=${id}; Path=/; HttpOnly; SameSite=Lax`);
    return s;
  };

  const handler = async (req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? '/', origin);
    requests.push({ method: req.method ?? '', host: req.headers.host ?? '', path: url.pathname });
    if (url.pathname === '/challenge/widget' || url.pathname === '/challenge/api.js') {
      if (url.pathname === '/challenge/api.js') {
        res.writeHead(200, { 'content-type': 'text/javascript' });
        return res.end('/* background widget */');
      }
      return html(res, challengeWidget());
    }
    const s = session(req, res);
    const user = s.userId ? users.get(s.userId) : undefined;
    const route = `${req.method} ${url.pathname}`;
    if (onLoginPage && req.method === 'GET' && LOGIN_PAGES.has(url.pathname) && !cleared(req)) {
      return sendChallenge(res, url.pathname);
    }

    switch (route) {
      case 'GET /':
        return html(res, homePage(user?.username ?? null));
      case 'GET /static/webauthn.js':
        res.writeHead(200, { 'content-type': 'text/javascript' });
        return res.end(webauthnJs);
      case 'GET /signup':
        return html(res, signupPage());
      case 'POST /signup': {
        const { username } = await body(req);
        if (!username || users.has(username)) return html(res, signupPage(), 400);
        users.set(username, { username, id: randomBytes(16), passkeys: [] });
        s.userId = username;
        return redirect(res, '/account');
      }
      case 'POST /logout':
        delete s.userId;
        return redirect(res, '/');
      case 'GET /account':
        if (!user) return redirect(res, '/login');
        if (challenge && !cleared(req)) return sendChallenge(res);
        return html(res, accountPage(user.username, user.passkeys.length));
      case 'POST /challenge/solve': {
        res.setHeader('set-cookie', [
          ...[res.getHeader('set-cookie') ?? []].flat().map(String),
          'rp_clearance=ok; Path=/; Max-Age=86400; SameSite=Lax',
        ]);
        const { next } = await body(req);
        return redirect(res, next && LOGIN_PAGES.has(next) ? next : '/account');
      }
      case 'GET /login':
        return html(res, loginPage(user?.username ?? null));
      case 'GET /api/whoami':
        return json(res, { username: user?.username ?? null });

      case 'POST /api/passkey/register/options': {
        if (!user) return json(res, { error: 'not_signed_in' }, 401);
        const options = await generateRegistrationOptions({
          rpName,
          rpID: rpId,
          userName: user.username,
          userID: user.id as Uint8Array<ArrayBuffer>,
          attestationType: 'none',
          excludeCredentials: user.passkeys.map((c) => ({ id: c.id })),
          authenticatorSelection: { residentKey: 'required', userVerification },
          supportedAlgorithmIDs: [-7],
        });
        s.challenge = options.challenge;
        return json(res, options);
      }
      case 'POST /api/passkey/register/verify': {
        if (!user || !s.challenge) return json(res, { verified: false, error: 'no_ceremony' }, 400);
        const expectedChallenge = s.challenge;
        delete s.challenge;
        try {
          const v = await verifyRegistrationResponse({
            response: (await body(req)) as unknown as RegistrationResponseJSON,
            expectedChallenge,
            expectedOrigin: origin,
            expectedRPID: rpId,
            requireUserVerification: userVerification === 'required',
          });
          if (!v.verified) return json(res, { verified: false, error: 'not_verified' }, 400);
          user.passkeys.push(v.registrationInfo.credential);
          return json(res, { verified: true, count: user.passkeys.length });
        } catch (e) {
          return json(res, { verified: false, error: (e as Error).message }, 400);
        }
      }
      case 'POST /api/passkey/login/options': {
        const options = await generateAuthenticationOptions({ rpID: rpId, userVerification });
        s.challenge = options.challenge;
        return json(res, options);
      }
      case 'POST /api/passkey/login/verify': {
        if (!s.challenge) return json(res, { verified: false, error: 'no_ceremony' }, 400);
        const expectedChallenge = s.challenge;
        delete s.challenge;
        const response = (await body(req)) as unknown as AuthenticationResponseJSON;
        const owner = [...users.values()].find((u) => u.passkeys.some((c) => c.id === response.id));
        const credential = owner?.passkeys.find((c) => c.id === response.id);
        if (!owner || !credential)
          return json(res, { verified: false, error: 'unknown_credential' }, 400);
        try {
          const v = await verifyAuthenticationResponse({
            response,
            expectedChallenge,
            expectedOrigin: origin,
            expectedRPID: rpId,
            credential,
            requireUserVerification: userVerification === 'required',
          });
          if (!v.verified) return json(res, { verified: false, error: 'not_verified' }, 400);
          credential.counter = v.authenticationInfo.newCounter;
          s.userId = owner.username;
          logins.push({ username: owner.username, method: 'passkey' });
          return json(res, { verified: true });
        } catch (e) {
          return json(res, { verified: false, error: (e as Error).message }, 400);
        }
      }

      case 'GET /password/login':
        return html(
          res,
          passwordLoginPage(undefined, opts.invisibleWidget ? widgetOrigin() : undefined),
        );
      case 'POST /password/login': {
        const { username, password } = await body(req);
        const u = username ? users.get(username) : undefined;
        if (!u?.password || u.password !== password) {
          return html(res, passwordLoginPage('Wrong username or password'), 401);
        }
        if (u.totpSecret) {
          s.pendingTotpUser = u.username;
          return redirect(res, '/password/totp');
        }
        s.userId = u.username;
        logins.push({ username: u.username, method: 'password' });
        if (challenge && !cleared(req)) return sendChallenge(res);
        return redirect(res, '/account');
      }
      case 'GET /password/login-id':
        return html(res, identifierPage());
      case 'GET /password/login-id-script':
        return html(res, identifierScriptPage());
      case 'POST /password/login-id': {
        const { username } = await body(req);
        if (!username) return html(res, identifierPage('Enter your username'), 400);
        s.pendingIdentifier = username;
        return redirect(res, '/password/login-pw');
      }
      case 'GET /password/login-pw':
        if (!s.pendingIdentifier) return redirect(res, '/password/login-id');
        return html(res, identifierPasswordPage(s.pendingIdentifier));
      case 'POST /password/login-pw': {
        const name = s.pendingIdentifier;
        if (!name) return redirect(res, '/password/login-id');
        const { password } = await body(req);
        const u = users.get(name);
        if (!u?.password || u.password !== password) {
          return html(res, identifierPasswordPage(name, 'Wrong password'), 401);
        }
        delete s.pendingIdentifier;
        if (u.totpSecret) {
          s.pendingTotpUser = u.username;
          return redirect(res, '/password/totp');
        }
        s.userId = u.username;
        logins.push({ username: u.username, method: 'password' });
        if (challenge && !cleared(req)) return sendChallenge(res);
        return redirect(res, '/account');
      }
      case 'GET /password/totp':
        if (!s.pendingTotpUser) return redirect(res, '/password/login');
        return html(res, totpPage());
      case 'POST /password/totp': {
        const pending = s.pendingTotpUser ? users.get(s.pendingTotpUser) : undefined;
        if (!pending?.totpSecret) return redirect(res, '/password/login');
        const { code } = await body(req);
        if (!code || !verifyTotp(pending.totpSecret, code)) {
          return html(res, totpPage('Wrong code'), 401);
        }
        delete s.pendingTotpUser;
        s.userId = pending.username;
        logins.push({ username: pending.username, method: 'password+totp' });
        if (challenge && !cleared(req)) return sendChallenge(res);
        return redirect(res, '/account');
      }
      default:
        res.writeHead(404, { 'content-type': 'text/plain' });
        return res.end('not found');
    }
  };

  const server = createServer((req, res) => {
    handler(req, res).catch(() => {
      if (!res.headersSent) res.writeHead(500);
      res.end('error');
    });
  });
  await new Promise<void>((resolve) =>
    server.listen(opts.port ?? 0, opts.listenHost ?? '127.0.0.1', resolve),
  );
  port = (server.address() as AddressInfo).port;
  origin = `http://${host}:${port}`;

  return {
    url: `${origin}/`,
    origin,
    rpId,
    users,
    logins,
    requests,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

function html(res: ServerResponse, page: string, status = 200): void {
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8' });
  res.end(page);
}

function json(res: ServerResponse, value: unknown, status = 200): void {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(value));
}

function redirect(res: ServerResponse, to: string): void {
  res.writeHead(303, { location: to });
  res.end();
}

async function body(req: IncomingMessage): Promise<Record<string, string>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > 64 * 1024) throw new Error('body too large');
    chunks.push(chunk as Buffer);
  }
  const raw = Buffer.concat(chunks).toString('utf8');
  if (!raw) return {};
  if ((req.headers['content-type'] ?? '').includes('application/json')) return JSON.parse(raw);
  return Object.fromEntries(new URLSearchParams(raw));
}
