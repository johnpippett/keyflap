const HOST = /^[a-z0-9.:[\]-]{1,260}$/;
let pushCount = 0;
const freshTag = (name) => `${name}-${Date.now()}-${++pushCount}`;

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

self.addEventListener('push', (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch {
    data = {};
  }
  if (data && data.t === 'handoff') {
    const host = typeof data.host === 'string' && HOST.test(data.host) ? data.host : null;
    event.waitUntil(
      self.registration.showNotification(host ? `Human check on ${host}` : 'Human check', {
        body: 'Tap to open the live view and complete it yourself.',
        tag: freshTag('keyflap-handoff'),
        requireInteraction: true,
        data: { url: '/handoff' },
      }),
    );
    return;
  }
  if (data && data.t === 'address') {
    const on = data.on === 'Mac' ? 'Mac' : 'computer';
    event.waitUntil(
      self.registration.showNotification('Approval address changed', {
        body: `The approval address on your ${on} was changed. Don't approve anything until you've checked it at your ${on}.`,
        tag: freshTag('keyflap-address'),
        requireInteraction: true,
        data: { url: '/' },
      }),
    );
    return;
  }
  event.waitUntil(
    self.registration.showNotification('Approval requested', {
      body: 'Open to review the sign-in request.',
      tag: freshTag('keyflap-approval'),
      requireInteraction: true,
      data: { url: '/' },
    }),
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const url =
    event.notification.data && event.notification.data.url === '/handoff' ? '/handoff' : '/';
  event.waitUntil(
    (async () => {
      const wins = await self.clients.matchAll({ type: 'window' });
      for (const w of wins) {
        if (new URL(w.url).pathname === url && 'focus' in w) return w.focus();
      }
      for (const w of wins) {
        if ('navigate' in w) {
          try {
            const c = await w.navigate(url);
            if (c) return c.focus();
          } catch {}
        }
        w.postMessage({ t: 'open', url });
        if ('focus' in w) return w.focus();
        return;
      }
      return self.clients.openWindow(url);
    })(),
  );
});
