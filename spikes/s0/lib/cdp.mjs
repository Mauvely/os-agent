// Tiny Chrome DevTools Protocol helper (Node >= 22: global WebSocket and fetch, no packages).
//   node cdp.mjs PORT open URL            open URL in a new tab, print its target id
//   node cdp.mjs PORT eval TARGET_ID JS   evaluate JS in that tab, print the JSON result
const [port, op, a, b] = process.argv.slice(2);
const base = `http://127.0.0.1:${port}`;
const call = (ws, method, params = {}) => new Promise((res, rej) => {
  const id = ++call.n;
  const on = (ev) => { const m = JSON.parse(ev.data); if (m.id === id) { ws.removeEventListener("message", on); m.error ? rej(new Error(JSON.stringify(m.error))) : res(m.result); } };
  ws.addEventListener("message", on);
  ws.send(JSON.stringify({ id, method, params }));
}); call.n = 0;
const connect = (url) => new Promise((res, rej) => { const ws = new WebSocket(url); ws.onopen = () => res(ws); ws.onerror = rej; });

if (op === "open") {
  const t = await (await fetch(`${base}/json/new?${a}`, { method: "PUT" })).json();
  console.log(t.id);
} else if (op === "eval") {
  const list = await (await fetch(`${base}/json/list`)).json();
  const t = list.find((x) => x.id === a);
  if (!t) { console.error("no such target"); process.exit(1); }
  const ws = await connect(t.webSocketDebuggerUrl);
  const r = await call(ws, "Runtime.evaluate", { expression: b, returnByValue: true, awaitPromise: true });
  console.log(JSON.stringify(r.result?.value ?? r, null, 1));
  ws.close();
} else if (op === "list") {
  console.log(JSON.stringify((await (await fetch(`${base}/json/list`)).json()).map((x) => ({ id: x.id, type: x.type, url: x.url, title: x.title })), null, 1));
}
