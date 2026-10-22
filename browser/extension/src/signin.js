// Mauvely OS sign-in: signs the browser in to Mauvely with the session the
// computer's sign-in broker mints (brief 22, S4). os-agent's docs/browser.md
// has the design; this file is all of the logic, and background.js wires it to
// the browser's events.
//
// - It sets one cookie, `mauvely_session`, on `.mauvely.com` or
//   `.mauvely.dev`: whichever the native host says this computer uses. It
//   never guesses, and never sets a cookie anywhere else.
// - It asks for a session only when that cookie is missing, and never after
//   the person signed out in the page, until the browser restarts.
// - It fetches nothing. Everything it learns comes from the native host.
//
// No analytics, no remote code. The token is never logged.

'use strict';

/** The native messaging host, `mauvely-browser-host` (os-agent). */
const HOST = 'com.mauvely.browser';

/** website-main's session cookie. */
const COOKIE = 'mauvely_session';

/** The accounts origins the extension acts for, and each one's cookie domain. */
const DOMAINS = new Map([
  ['https://mauvely.com', 'mauvely.com'],
  ['https://mauvely.dev', 'mauvely.dev'],
]);

/**
 * The extension's two notes, kept as cookies on the accounts host at a path
 * the site never serves, so they are never sent. Cookies, because they need
 * no permission beyond `cookies`, and because a cookie with no expiry is
 * exactly "until the browser restarts".
 *  - HELD: the person signed out in the page.
 *  - WAIT: the broker refused; `<retry at>.<refusals so far>`, Unix seconds.
 */
const NOTES = '/.mauvely-os-extension/';
const HELD = 'mauvely_os_held';
const WAIT = 'mauvely_os_wait';

/** Seconds before asking again after the first, second, … refusal. */
const BACKOFF = [60, 120, 300, 900, 1800, 3600];

/** website-main's tokens: 32 random bytes in base64url. */
const TOKEN = /^[A-Za-z0-9_-]{16,256}$/;

/** A removal this close to the cookie's own expiry is the expiry. */
const EXPIRY_SLACK = 60;

/**
 * @param api   `browser` in Firefox, `chrome` in Chromium: runtime,
 *              cookies and tabs, promise-returning.
 * @param now   Unix seconds.
 * @param log   One line, never holding a token.
 */
function makeSignin(api, now = () => Date.now() / 1000, log = () => {}) {
  // Learned from the host, kept while this background lives.
  let origin = null;
  // Back-off while the origin is not known (the host cannot be reached), when
  // there is nowhere to keep a note.
  let waitUntil = 0;
  let refusals = 0;
  // One ask at a time; tabs that asked meanwhile are reloaded with the first.
  let running = null;
  const tabs = new Set();

  async function host(op) {
    try {
      const answer = await api.runtime.sendNativeMessage(HOST, { op });
      return answer && typeof answer === 'object' ? answer : { ok: false, reason: 'bad_response' };
    } catch (e) {
      // Not installed, or not allowed to start it.
      return { ok: false, reason: 'unavailable' };
    }
  }

  /** This computer's accounts origin, from the host, or null. Events that
   *  wake the background together share one question. */
  let learning = null;
  function learnOrigin() {
    if (origin) return Promise.resolve(origin);
    if (!learning) {
      learning = host('origin').then((answer) => {
        learning = null;
        if (answer.ok === true && DOMAINS.has(answer.origin)) origin = answer.origin;
        else log(`no origin: ${reasonOf(answer)}`);
        return origin;
      });
    }
    return learning;
  }

  const notesUrl = (domain) => `https://${domain}${NOTES}`;

  async function note(domain, name) {
    const c = await api.cookies.get({ url: notesUrl(domain), name });
    return c ? c.value : null;
  }

  // Host-only on the accounts host, Secure, HttpOnly, SameSite=Strict, at a
  // path nothing is served from, and with no expiry: gone with the browser.
  function setNote(domain, name, value) {
    return api.cookies.set({
      url: notesUrl(domain),
      name,
      value,
      path: NOTES,
      secure: true,
      httpOnly: true,
      sameSite: 'strict',
    });
  }

  function clearNote(domain, name) {
    return api.cookies.remove({ url: notesUrl(domain), name });
  }

  /** The domain cookie the extension sets, if it is there. */
  async function sessionCookie(domain) {
    const all = await api.cookies.getAll({ domain, name: COOKIE });
    return all.find((c) => isSessionCookie(c, domain)) || null;
  }

  async function backOff(domain, previous, why) {
    const count = Math.max(previous ? previous.count : 0, refusals) + 1;
    refusals = count;
    const delay = BACKOFF[Math.min(count, BACKOFF.length) - 1];
    waitUntil = now() + delay;
    if (domain) await setNote(domain, WAIT, `${Math.floor(waitUntil)}.${count}`);
    log(`not signed in: ${why}; asking again in ${delay} s`);
  }

  async function once() {
    if (now() < waitUntil) return 'waiting';
    const o = await learnOrigin();
    if (!o) {
      await backOff(null, null, 'the host did not say which origin');
      return 'no_origin';
    }
    const domain = DOMAINS.get(o);
    if (await sessionCookie(domain)) return 'present';
    if (await note(domain, HELD)) return 'held';
    const wait = parseWait(await note(domain, WAIT));
    if (wait && now() < wait.until) {
      waitUntil = wait.until;
      return 'waiting';
    }

    const answer = await host('browser');
    if (answer.ok !== true) {
      await backOff(domain, wait, reasonOf(answer));
      return 'refused';
    }
    if (answer.origin !== o) {
      // The computer moved to another server: learn it again next time.
      origin = null;
      await backOff(domain, wait, 'a session for another origin');
      return 'refused';
    }
    if (!TOKEN.test(answer.token) || !Number.isSafeInteger(answer.expiresAt) ||
        answer.expiresAt <= now() + EXPIRY_SLACK) {
      await backOff(domain, wait, 'an answer it does not understand');
      return 'refused';
    }
    // The person may have signed in, or out, while the broker was asked.
    if ((await sessionCookie(domain)) || (await note(domain, HELD))) return 'present';

    await api.cookies.set({
      url: `https://${domain}/`,
      name: COOKIE,
      value: answer.token,
      domain,
      path: '/',
      secure: true,
      httpOnly: true,
      sameSite: 'lax',
      expirationDate: answer.expiresAt,
    });
    // A host-only cookie of the same name would be sent beside it, oldest
    // first, and shadow it.
    for (const c of await api.cookies.getAll({ domain, name: COOKIE })) {
      if (c.hostOnly) {
        await api.cookies.remove({ url: `https://${c.domain}${c.path}`, name: COOKIE });
      }
    }
    refusals = 0;
    waitUntil = 0;
    await clearNote(domain, WAIT);
    log(`signed in on .${domain}`);
    return 'set';
  }

  /**
   * Signs the browser in if it should be. `tab` is a tab that started loading
   * a page of the accounts site without the cookie; it is reloaded once the
   * cookie is set, so the page it shows is signed in.
   */
  function ensure(tab) {
    if (tab) tabs.add(tab);
    if (!running) {
      running = (async () => {
        try {
          const outcome = await once();
          if (outcome === 'set') await reload();
          return outcome;
        } catch (e) {
          log(`could not sign in: ${e && e.message}`);
          return 'error';
        } finally {
          tabs.clear();
          running = null;
        }
      })();
    }
    return running;
  }

  async function reload() {
    const domain = DOMAINS.get(origin);
    for (const tab of tabs) {
      if (onSite(tab.url, domain)) {
        try {
          await api.tabs.reload(tab.id);
        } catch (e) {
          // Closed meanwhile.
        }
      }
    }
  }

  /**
   * A cookie changed. The site removing the session cookie before its expiry
   * is a sign-out, held until the browser restarts; an expiry is asked again
   * for at once.
   */
  async function changed({ removed, cookie, cause }) {
    if (!removed || cookie.name !== COOKIE || cause === 'overwrite') return 'ignored';
    const o = await learnOrigin();
    if (!o) return 'ignored';
    const domain = DOMAINS.get(o);
    if (!isSessionCookie(cookie, domain)) return 'ignored';
    const expired = cause === 'expired' || cause === 'evicted' ||
      (typeof cookie.expirationDate === 'number' && cookie.expirationDate <= now() + EXPIRY_SLACK);
    if (expired) {
      await ensure();
      return 'expired';
    }
    await setNote(domain, HELD, '1');
    log(`signed out in the page (${cause}); not signing in again until the browser restarts`);
    return 'held';
  }

  /** A tab started loading; is it the accounts site? */
  function loading(tabId, url) {
    // Either domain may be this computer's until the host has said; `ensure`
    // asks it, and acts for that one alone.
    for (const domain of DOMAINS.values()) {
      if (onSite(url, domain)) return ensure({ id: tabId, url });
    }
    return null;
  }

  return { ensure, changed, loading };
}

function isSessionCookie(c, domain) {
  return c.name === COOKIE && !c.hostOnly && c.domain === `.${domain}` && c.path === '/';
}

/** `https://<domain>/…` or `https://<anything>.<domain>/…`. */
function onSite(url, domain) {
  let host;
  try {
    const u = new URL(url);
    if (u.protocol !== 'https:') return false;
    host = u.hostname;
  } catch (e) {
    return false;
  }
  return host === domain || host.endsWith(`.${domain}`);
}

function parseWait(value) {
  const m = /^(\d{1,12})\.(\d{1,3})$/.exec(value || '');
  return m ? { until: Number(m[1]), count: Number(m[2]) } : null;
}

function reasonOf(answer) {
  return typeof answer.reason === 'string' && /^[a-z_]{1,32}$/.test(answer.reason)
    ? answer.reason
    : 'bad_response';
}

if (typeof module === 'object' && module.exports) {
  module.exports = { makeSignin, onSite, parseWait, HOST, COOKIE, NOTES, HELD, WAIT, BACKOFF };
}
