// The extension's logic against a fake browser: a cookie jar with the
// domain, host-only and path rules the cookies API has, a native host that
// answers from a script, and tabs. `node --test browser/extension/test/`.

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { makeSignin, onSite, parseWait, NOTES, HELD, WAIT } = require('../src/signin.js');

const TOKEN = 'tok_0123456789abcdefABCDEF-_0123456789abcd';
const T0 = 1_800_000_000;

/** A browser with a cookie jar, a native host and tabs. */
function browser({ origin = 'https://mauvely.com', answers = [], hostAvailable = true } = {}) {
  const b = {
    clock: T0,
    jar: [],
    events: [],
    asked: [],
    reloaded: [],
    logs: [],
    answers: [...answers],
  };
  const hostOf = (url) => new URL(url).hostname;
  const key = (c) => `${c.name}|${c.domain}|${c.path}`;
  const domainMatch = (cookieDomain, host) =>
    cookieDomain.startsWith('.')
      ? host === cookieDomain.slice(1) || host.endsWith(cookieDomain)
      : host === cookieDomain;
  const live = () => b.jar.filter((c) => c.expirationDate === undefined || c.expirationDate > b.clock);
  const remove = (c, cause) => {
    b.jar = b.jar.filter((x) => x !== c);
    b.events.push({ removed: true, cookie: { ...c }, cause });
  };
  b.remove = remove;
  b.api = {
    runtime: {
      async sendNativeMessage(name, message) {
        assert.equal(name, 'com.mauvely.browser');
        b.asked.push(message.op);
        if (!hostAvailable) throw new Error('Specified native messaging host not found.');
        if (message.op === 'origin') {
          return origin ? { ok: true, origin } : { ok: false, reason: 'forbidden' };
        }
        const next = b.answers.shift();
        assert.ok(next, 'an unexpected browser ask');
        return next;
      },
    },
    cookies: {
      async get({ url, name }) {
        const u = new URL(url);
        const found = live()
          .filter((c) => c.name === name && domainMatch(c.domain, u.hostname) && u.pathname.startsWith(c.path))
          .sort((a, z) => z.path.length - a.path.length);
        return found[0] ? { ...found[0] } : null;
      },
      async getAll({ domain, name }) {
        return live()
          .filter((c) => c.name === name)
          .filter((c) => {
            const d = c.domain.replace(/^\./, '');
            return d === domain || d.endsWith(`.${domain}`);
          })
          .map((c) => ({ ...c }));
      },
      async set(d) {
        assert.ok(d.url.startsWith('https://'), d.url);
        const host = hostOf(d.url);
        const c = {
          name: d.name,
          value: d.value,
          domain: d.domain ? `.${d.domain}` : host,
          hostOnly: !d.domain,
          path: d.path ?? '/',
          secure: !!d.secure,
          httpOnly: !!d.httpOnly,
          sameSite: d.sameSite ?? 'unspecified',
          session: d.expirationDate === undefined,
          expirationDate: d.expirationDate,
        };
        // The extension may only set what its host permissions cover.
        assert.ok(/(^|\.)mauvely\.(com|dev)$/.test(c.domain.replace(/^\./, '')), c.domain);
        const old = b.jar.find((x) => key(x) === key(c));
        if (old) remove(old, 'overwrite');
        b.jar.push(c);
        b.events.push({ removed: false, cookie: { ...c }, cause: 'explicit' });
        return { ...c };
      },
      async remove({ url, name }) {
        const u = new URL(url);
        const c = b.jar.find((x) => x.name === name && domainMatch(x.domain, u.hostname) &&
          (x.hostOnly ? x.domain === u.hostname : true) && u.pathname.startsWith(x.path));
        if (c) remove(c, 'explicit');
        return c ? { name } : null;
      },
    },
    tabs: {
      async reload(id) {
        b.reloaded.push(id);
      },
    },
  };
  b.signin = () => makeSignin(b.api, () => b.clock, (line) => b.logs.push(line));
  /** The site's sign-out: an expired Set-Cookie for the domain cookie. */
  b.siteSignsOut = (domain, cause = 'expired_overwrite') => {
    const c = b.jar.find((x) => x.name === 'mauvely_session' && x.domain === `.${domain}`);
    assert.ok(c, 'signed in');
    remove(c, cause);
    return b.events.at(-1);
  };
  /** The browser restarts: session cookies go, the background starts afresh. */
  b.restart = () => {
    b.jar = b.jar.filter((c) => !c.session);
  };
  b.session = (domain = 'mauvely.com') =>
    b.jar.find((c) => c.name === 'mauvely_session' && c.domain === `.${domain}` && !c.hostOnly);
  return b;
}

const granted = (over = {}) => ({
  ok: true,
  token: TOKEN,
  expiresAt: T0 + 30 * 86400,
  origin: 'https://mauvely.com',
  ...over,
});

test('a missing cookie is asked for once and set on the domain', async () => {
  const b = browser({ answers: [granted()] });
  const s = b.signin();
  assert.equal(await s.ensure(), 'set');
  assert.deepEqual(b.asked, ['origin', 'browser']);
  const c = b.session();
  assert.deepEqual(
    { ...c },
    {
      name: 'mauvely_session',
      value: TOKEN,
      domain: '.mauvely.com',
      hostOnly: false,
      path: '/',
      secure: true,
      httpOnly: true,
      sameSite: 'lax',
      session: false,
      expirationDate: T0 + 30 * 86400,
    },
  );
  // There now: nothing more is asked, by this background or a new one.
  assert.equal(await s.ensure(), 'present');
  assert.equal(await b.signin().ensure(), 'present');
  assert.deepEqual(b.asked, ['origin', 'browser', 'origin']);
});

test('the host says which domain; mauvely.dev gets .mauvely.dev alone', async () => {
  const b = browser({
    origin: 'https://mauvely.dev',
    answers: [granted({ origin: 'https://mauvely.dev' })],
  });
  // A production session in the jar is not this computer's.
  await b.api.cookies.set({ url: 'https://mauvely.com/', name: 'mauvely_session', value: 'x'.repeat(43),
    domain: 'mauvely.com', path: '/', secure: true, httpOnly: true, expirationDate: T0 + 999 });
  assert.equal(await b.signin().ensure(), 'set');
  assert.ok(b.session('mauvely.dev'));
  assert.equal(b.session('mauvely.com').value, 'x'.repeat(43));
});

test('it never guesses: no origin, no cookie', async () => {
  for (const setup of [
    { hostAvailable: false },
    { origin: null },
    { origin: 'http://localhost:8787' },
    { origin: 'https://evil.example' },
  ]) {
    const b = browser(setup);
    const s = b.signin();
    assert.equal(await s.ensure(), 'no_origin', JSON.stringify(setup));
    assert.equal(b.jar.length, 0);
    assert.deepEqual(b.asked, ['origin']);
    // Backed off in memory: nothing is asked for a minute.
    assert.equal(await s.ensure(), 'waiting');
    b.clock += 61;
    assert.equal(await s.ensure(), 'no_origin');
    assert.deepEqual(b.asked, ['origin', 'origin']);
  }
});

test('host-only cookies that would shadow it are removed, and nothing else', async () => {
  const b = browser({ answers: [granted()] });
  const set = (url, name, domain) =>
    b.api.cookies.set({ url, name, value: 'old', domain, path: '/', secure: true, expirationDate: T0 + 999 });
  await set('https://mauvely.com/', 'mauvely_session');
  await set('https://cloud.mauvely.com/', 'mauvely_session');
  await set('https://mauvely.com/', 'mauvely_consent');
  await set('https://mauvely.dev/', 'mauvely_session');
  assert.equal(await b.signin().ensure(), 'set');
  const left = b.jar.map((c) => `${c.name}@${c.domain}`).sort();
  assert.deepEqual(left, [
    'mauvely_consent@mauvely.com',
    'mauvely_session@.mauvely.com',
    'mauvely_session@mauvely.dev',
  ]);
});

test('a sign-out in the page holds until the browser restarts', async () => {
  for (const cause of ['expired_overwrite', 'explicit']) {
    const b = browser({ answers: [granted(), granted({ token: `${TOKEN}2` })] });
    let s = b.signin();
    await s.ensure();
    assert.equal(await s.changed(b.siteSignsOut('mauvely.com', cause)), 'held', cause);
    // The note: host-only on the accounts host, at a path nothing is served
    // from, and gone with the browser.
    const held = b.jar.find((c) => c.name === HELD);
    assert.deepEqual(
      [held.domain, held.hostOnly, held.path, held.secure, held.httpOnly, held.sameSite, held.session],
      ['mauvely.com', true, NOTES, true, true, 'strict', true],
    );
    // Reloads, navigations and a background that was stopped and started
    // again all leave it signed out.
    assert.equal(await s.ensure(), 'held');
    assert.equal(await s.loading(7, 'https://mauvely.com/account'), 'held');
    s = b.signin();
    assert.equal(await s.ensure(), 'held');
    b.clock += 7 * 86400;
    assert.equal(await s.ensure(), 'held');
    assert.deepEqual(b.asked.filter((a) => a === 'browser'), ['browser']);
    // Restarted: signed in again.
    b.restart();
    assert.equal(await b.signin().ensure(), 'set');
    assert.equal(b.session().value, `${TOKEN}2`);
  }
});

test('an expiry is not a sign-out: it is asked for again at once', async () => {
  const b = browser({
    answers: [granted({ expiresAt: T0 + 3600 }), granted({ token: `${TOKEN}2`, expiresAt: T0 + 9000 })],
  });
  const s = b.signin();
  await s.ensure();
  b.clock = T0 + 3600;
  const c = b.session();
  b.remove(c, 'expired');
  assert.equal(await s.changed(b.events.at(-1)), 'expired');
  assert.equal(b.session().value, `${TOKEN}2`);
  assert.ok(!b.jar.some((x) => x.name === HELD));
  // Firefox says `explicit` when it drops an expired cookie: the expiry
  // still tells it apart from a sign-out.
  b.clock = T0 + 9000 - 10;
  b.remove(b.session(), 'explicit');
  b.answers.push(granted({ token: `${TOKEN}3`, expiresAt: T0 + 99_999 }));
  assert.equal(await s.changed(b.events.at(-1)), 'expired');
  assert.equal(b.session().value, `${TOKEN}3`);
});

test('other changes are not sign-outs', async () => {
  const b = browser({ answers: [granted()] });
  const s = b.signin();
  await s.ensure();
  const c = { ...b.session() };
  for (const change of [
    { removed: true, cookie: c, cause: 'overwrite' },
    { removed: false, cookie: c, cause: 'explicit' },
    { removed: true, cookie: { ...c, name: 'mauvely_consent' }, cause: 'explicit' },
    { removed: true, cookie: { ...c, hostOnly: true, domain: 'mauvely.com' }, cause: 'explicit' },
    { removed: true, cookie: { ...c, domain: '.mauvely.dev' }, cause: 'explicit' },
    { removed: true, cookie: { ...c, path: '/api' }, cause: 'explicit' },
  ]) {
    assert.equal(await s.changed(change), 'ignored', JSON.stringify(change));
  }
  assert.ok(!b.jar.some((x) => x.name === HELD));
});

test('a refusal backs off, and the back-off outlives the background', async () => {
  const b = browser({
    answers: [
      { ok: false, reason: 'signed_out' },
      { ok: false, reason: 'signed_out' },
      { ok: false, reason: 'unreachable' },
      granted(),
    ],
  });
  let s = b.signin();
  assert.equal(await s.ensure(), 'refused');
  assert.equal(b.jar.find((c) => c.name === WAIT).value, `${T0 + 60}.1`);
  // A new background, as after Chromium stops its service worker.
  s = b.signin();
  b.clock += 30;
  assert.equal(await s.ensure(), 'waiting');
  assert.equal(await s.loading(3, 'https://mauvely.com/'), 'waiting');
  b.clock = T0 + 60;
  assert.equal(await s.ensure(), 'refused');
  assert.equal(b.jar.find((c) => c.name === WAIT).value, `${T0 + 180}.2`);
  b.clock = T0 + 180;
  s = b.signin();
  assert.equal(await s.ensure(), 'refused');
  assert.equal(b.jar.find((c) => c.name === WAIT).value, `${T0 + 480}.3`);
  b.clock = T0 + 480;
  assert.equal(await s.ensure(), 'set');
  assert.ok(!b.jar.some((c) => c.name === WAIT), 'cleared by a success');
  assert.deepEqual(b.asked.filter((a) => a === 'browser').length, 4);
  // A refusal's reason, never the token, in the log.
  assert.ok(b.logs.some((l) => l.includes('signed_out')));
  assert.ok(!b.logs.some((l) => l.includes(TOKEN)));
});

test('the back-off stops growing at an hour', async () => {
  const b = browser({ answers: Array.from({ length: 9 }, () => ({ ok: false, reason: 'rate_limited' })) });
  const s = b.signin();
  const delays = [];
  for (let i = 0; i < 9; i++) {
    const before = b.clock;
    assert.equal(await s.ensure(), 'refused');
    const wait = parseWait(b.jar.find((c) => c.name === WAIT).value);
    delays.push(wait.until - before);
    b.clock = wait.until;
  }
  assert.deepEqual(delays, [60, 120, 300, 900, 1800, 3600, 3600, 3600, 3600]);
});

test('an answer it does not understand sets nothing', async () => {
  for (const answer of [
    granted({ token: 'short' }),
    granted({ token: 'has;semicolon_0123456789abcdef' }),
    granted({ token: 7 }),
    granted({ expiresAt: T0 + 30 }),
    granted({ expiresAt: '1900000000' }),
    granted({ expiresAt: 1.5e9 + 0.5 }),
    granted({ origin: 'https://mauvely.dev' }),
    { ok: 'true', token: TOKEN },
    null,
  ]) {
    const b = browser({ answers: [answer] });
    assert.equal(await b.signin().ensure(), 'refused', JSON.stringify(answer));
    assert.ok(!b.session());
    assert.ok(b.jar.some((c) => c.name === WAIT));
  }
});

test('a page of the site loading without the cookie is reloaded signed in', async () => {
  const b = browser({ answers: [granted()] });
  const s = b.signin();
  // Other sites do not even ask the host.
  assert.equal(s.loading(1, 'https://example.com/'), null);
  assert.equal(s.loading(1, 'http://mauvely.com/'), null);
  assert.equal(s.loading(1, 'https://mauvely.com.evil.example/'), null);
  assert.deepEqual(b.asked, []);
  // Two tabs at once: one ask, both reloaded.
  const one = s.loading(4, 'https://mauvely.com/account');
  const two = s.loading(5, 'https://cloud.mauvely.com/');
  assert.equal(await one, 'set');
  assert.equal(await two, 'set');
  assert.deepEqual(b.asked, ['origin', 'browser']);
  assert.deepEqual(b.reloaded, [4, 5]);
  // Signed in: the next page is left alone.
  assert.equal(await s.loading(6, 'https://mauvely.com/'), 'present');
  assert.deepEqual(b.reloaded, [4, 5]);
});

test('a staging page on a production computer is not reloaded', async () => {
  const b = browser({ answers: [granted()] });
  assert.equal(await b.signin().loading(9, 'https://mauvely.dev/account'), 'set');
  assert.deepEqual(b.reloaded, []);
  assert.ok(b.session('mauvely.com'));
});

test('a sign-in in the page while the host was asked wins', async () => {
  const b = browser({ answers: [granted()] });
  const send = b.api.runtime.sendNativeMessage;
  b.api.runtime.sendNativeMessage = async (name, message) => {
    const answer = await send(name, message);
    if (message.op === 'browser') {
      await b.api.cookies.set({ url: 'https://mauvely.com/', name: 'mauvely_session', value: 'mine'.repeat(11),
        domain: 'mauvely.com', path: '/', secure: true, httpOnly: true, expirationDate: T0 + 99 });
    }
    return answer;
  };
  assert.equal(await b.signin().ensure(), 'present');
  assert.equal(b.session().value, 'mine'.repeat(11));
});

test('events that wake the background together ask the origin once', async () => {
  const b = browser({ answers: [granted()] });
  const s = b.signin();
  await s.ensure();
  const c = { ...b.session() };
  const fresh = b.signin();
  // A cookie event and a tab, each needing the origin, at the same moment.
  await Promise.all([
    fresh.changed({ removed: true, cookie: { ...c, expirationDate: T0 - 1 }, cause: 'expired' }),
    fresh.loading(1, 'https://mauvely.com/'),
  ]);
  assert.deepEqual(b.asked, ['origin', 'browser', 'origin']);
});

test('onSite matches the domain and its subdomains, over https only', () => {
  assert.ok(onSite('https://mauvely.com/account', 'mauvely.com'));
  assert.ok(onSite('https://cloud.mauvely.com/x', 'mauvely.com'));
  assert.ok(!onSite('https://mauvely.com.evil.example/', 'mauvely.com'));
  assert.ok(!onSite('https://evilmauvely.com/', 'mauvely.com'));
  assert.ok(!onSite('http://mauvely.com/', 'mauvely.com'));
  assert.ok(!onSite('not a url', 'mauvely.com'));
  assert.ok(!onSite(undefined, 'mauvely.com'));
});

// ── the package ─────────────────────────────────────────────────────────────

const root = path.join(__dirname, '..');
const manifest = (name) => JSON.parse(fs.readFileSync(path.join(root, name), 'utf8'));

test('the manifests ask for exactly these permissions', () => {
  for (const name of ['manifest.chromium.json', 'manifest.firefox.json']) {
    const m = manifest(name);
    assert.equal(m.manifest_version, 3);
    assert.deepEqual(m.permissions, ['nativeMessaging', 'cookies'], name);
    assert.deepEqual(m.host_permissions, ['https://*.mauvely.com/*', 'https://*.mauvely.dev/*'], name);
    for (const key of ['content_scripts', 'web_accessible_resources', 'content_security_policy',
      'optional_permissions', 'optional_host_permissions', 'externally_connectable']) {
      assert.ok(!(key in m), `${name}: ${key}`);
    }
  }
  const [c, f] = [manifest('manifest.chromium.json'), manifest('manifest.firefox.json')];
  assert.equal(c.version, f.version);
  assert.equal(c.name, f.name);
  assert.match(c.key, /^[A-Za-z0-9+/]+=*$/);
  assert.equal(f.browser_specific_settings.gecko.id, 'os-signin@mauvely.com');
  assert.deepEqual(f.browser_specific_settings.gecko.data_collection_permissions, { required: ['none'] });
});

test('no remote code and no network', () => {
  for (const file of ['src/signin.js', 'src/background.js']) {
    const source = fs.readFileSync(path.join(root, file), 'utf8');
    for (const banned of ['fetch(', 'XMLHttpRequest', 'WebSocket', 'EventSource', 'eval(',
      'new Function', 'import(', 'sendBeacon', 'http://', 'innerHTML']) {
      assert.ok(!source.includes(banned), `${file} holds ${banned}`);
    }
  }
});
