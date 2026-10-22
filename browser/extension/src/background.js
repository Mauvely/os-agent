// The browser's events, wired to signin.js. Firefox loads both files as the
// background's scripts; Chromium starts this one as its service worker, which
// imports the other. Every listener is added at once, at the top, so an event
// that wakes the background finds it.

'use strict';

if (typeof makeSignin === 'undefined') importScripts('signin.js');

const api = globalThis.browser ?? globalThis.chrome;
const signin = makeSignin(api, () => Date.now() / 1000, (line) => console.info(`mauvely: ${line}`));

// The browser started, or the extension was installed or updated by policy.
api.runtime.onStartup.addListener(() => signin.ensure());
api.runtime.onInstalled.addListener(() => signin.ensure());

// The session cookie went: expired (ask again) or signed out (hold).
api.cookies.onChanged.addListener((change) => {
  signin.changed(change).catch((e) => console.info(`mauvely: ${e && e.message}`));
});

// A page of the accounts site started loading: ask, if the cookie is missing
// and nothing says not to, and reload it signed in. Firefox can filter the
// event; Chromium cannot, and is told which tabs only for the hosts above.
const loading = (tabId, info, tab) => {
  if (info.status === 'loading') signin.loading(tabId, (tab && tab.url) || info.url);
};
try {
  api.tabs.onUpdated.addListener(loading, {
    urls: ['https://*.mauvely.com/*', 'https://*.mauvely.dev/*'],
    properties: ['status'],
  });
} catch (e) {
  api.tabs.onUpdated.addListener(loading);
}
