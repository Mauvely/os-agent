// Spike S0 extension: one source for Firefox and Chromium. Reports every step to a loopback
// collector (write-only, no-cors, so it needs no host permission).
const api = typeof browser !== "undefined" && browser.runtime && browser.runtime.getBrowserInfo ? browser : chrome;
const WHO = typeof browser !== "undefined" && browser.runtime && browser.runtime.getBrowserInfo ? "firefox" : "chromium";
const HOST = "com.mauvely.s0";
const COLLECTOR = "http://127.0.0.1:18099/report";

function report(step, data) {
  return fetch(COLLECTOR, {
    method: "POST", mode: "no-cors", headers: { "Content-Type": "text/plain" },
    body: JSON.stringify({ browser: WHO, step, data, t: Date.now() }),
  }).catch(() => {});
}
const lastErr = () => (chrome.runtime.lastError ? String(chrome.runtime.lastError.message) : null);

function sendOnce(msg, host = HOST) {
  return new Promise((resolve) => {
    try {
      api.runtime.sendNativeMessage(host, msg, (r) => resolve({ response: r === undefined ? null : r, error: lastErr() }));
    } catch (e) { resolve({ error: "throw: " + e }); }
  });
}
function viaPort(msgs) {
  return new Promise((resolve) => {
    const got = [];
    let port;
    try { port = api.runtime.connectNative(HOST); } catch (e) { return resolve({ error: "throw: " + e }); }
    const timer = setTimeout(() => { try { port.disconnect(); } catch (_) {} resolve({ got, error: "timeout" }); }, 8000);
    port.onMessage.addListener((m) => { got.push(m); if (got.length === msgs.length) { clearTimeout(timer); port.disconnect(); resolve({ got, error: null }); } });
    port.onDisconnect.addListener((p) => { clearTimeout(timer); resolve({ got, error: (p && p.error && p.error.message) || lastErr() || "disconnected" }); });
    msgs.forEach((m) => port.postMessage(m));
  });
}
const cookieP = (fn, arg) => new Promise((res) => { try { api.cookies[fn](arg, (r) => res({ r, e: lastErr() })); } catch (e) { res({ e: "throw: " + e }); } });

async function main() {
  await report("loaded", { id: api.runtime.id, ua: navigator.userAgent, manifest: api.runtime.getManifest().manifest_version });
  await report("sendNativeMessage", await sendOnce({ hello: "one-shot", from: WHO }));
  // a second host name, registered only by the Chromium NativeMessagingHost ref (make-remote-extra.sh)
  await report("sendNativeMessage-refhost", await sendOnce({ hello: "refhost" }, "com.mauvely.s0ext"));
  // and a third, registered only by the single Chromium ref org.chromium.Chromium.Extension.s0all
  await report("sendNativeMessage-singleref", await sendOnce({ hello: "singleref" }, "com.mauvely.s0all"));
  await report("connectNative", await viaPort([{ hello: "port", n: 1 }, { hello: "port", n: 2 }]));
  try { await report("permissions", await new Promise((res) => api.permissions.getAll((p) => res(p)))); } catch (e) { await report("permissions", { error: String(e) }); }

  // The S4 cookie dance, on a domain that cannot exist: a host-only cookie must be removable
  // and a Domain= cookie (Secure, HttpOnly, SameSite=Lax) must be settable and readable back.
  const url = "https://accounts.mauvely.invalid/";
  const out = {};
  out.setHostOnly = await cookieP("set", { url, name: "mauvely_session", value: "shadow" });
  out.removeHostOnly = await cookieP("remove", { url, name: "mauvely_session" });
  out.setDomain = await cookieP("set", { url, name: "mauvely_session", value: "token", domain: ".mauvely.invalid", secure: true, httpOnly: true, sameSite: "lax", expirationDate: Math.floor(Date.now() / 1000) + 3600 });
  out.get = await cookieP("getAll", { name: "mauvely_session" });
  await report("cookies", out);
  await report("done", {});
}
main().catch((e) => report("fatal", String(e)));
