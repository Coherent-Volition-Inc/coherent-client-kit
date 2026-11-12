import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';

const store = new Map();
const session = new Map();
const storage = data => ({
  getItem: key => data.get(key) ?? null,
  setItem: (key, value) => data.set(key, String(value)),
  removeItem: key => data.delete(key),
});

globalThis.localStorage = storage(store);
globalThis.window = {
  localStorage,
  sessionStorage: storage(session),
  location: { search: '', hash: '', href: 'https://coherentvolition.ai/', origin: 'https://coherentvolition.ai' },
  addEventListener: () => {},
  m: Object.assign((tag, attrs) => ({ tag, attrs }), { redraw: () => {}, route: { get: () => '/slides' } }),
};

const { Auth } = await import('../src/auth.js');
const { ProtectedRouteFactory } = await import('../src/protected-route.js');
const jwt = exp => ['eyJhbGciOiJub25lIn0', Buffer.from(JSON.stringify({ exp, iss: 'test', user: { username: 'user', permissions: [['*', '*']] } })).toString('base64url'), 'signature'].join('.');
const future = () => Math.floor(Date.now() / 1000) + 3600;
const expired = () => Math.floor(Date.now() / 1000) - 3600;
const originalFetch = globalThis.fetch;

beforeEach(() => {
  store.clear(); session.clear();
  Auth._clearRefreshTimer();
  Auth._initPromise = null;
  Auth._initDone = false;
  Auth._refreshPromise = null;
  Auth.setToken(null);
  Auth.configure({ authApi: 'https://auth.example.test', homePath: '/store' });
});
afterEach(() => { Auth._clearRefreshTimer(); globalThis.fetch = originalFetch; });

function response(token, status = 200) {
  return { ok: status === 200, status,
    headers: { get: () => 'application/json' },
    json: async () => token ? { jwt: token } : { message: 'expired' } };
}

test('expired JWT is refreshed from cookie before route guard renders', async () => {
  localStorage.setItem('jwt', jwt(expired()));
  let requests = 0;
  globalThis.fetch = async (url, opts) => {
    requests++;
    assert.equal(url, 'https://auth.example.test/api/token');
    assert.equal(opts.credentials, 'include');
    return response(jwt(future()));
  };
  const p = Auth.init();
  assert.equal(Auth.init(), p, 'init must be idempotent');
  await p;
  assert.equal(requests, 1);
  assert.equal(Auth.isAuthenticated, true);
  assert.equal(Auth.user.username, 'user');
  assert.ok(localStorage.getItem('jwt'));
});

test('expired JWT with failed refresh shows login instead of a blank guard', async () => {
  localStorage.setItem('jwt', jwt(expired()));
  globalThis.fetch = async () => response(null, 401);
  const init = Auth.init();
  const Login = { view: () => 'login' };
  const guard = ProtectedRouteFactory(Login);
  const vnode = { state: {}, attrs: { component: { view: () => 'private' } } };
  guard.oninit(vnode);
  assert.match(guard.view(vnode).attrs, /Restoring session/);
  await init;
  await Promise.resolve();
  assert.equal(Auth.isAuthenticated, false);
  assert.equal(localStorage.getItem('jwt'), null);
  assert.equal(guard.view(vnode).tag, Login);
});

test('corrupt stored JWT cannot stop app initialization', async () => {
  localStorage.setItem('jwt', 'not-a-jwt');
  globalThis.fetch = async () => response(null, 401);
  await Auth.init();
  assert.equal(Auth._initDone, true);
  assert.equal(Auth.jwt, null);
  assert.equal(Auth.isAuthenticated, false);
});

test('valid stored JWT needs no startup refresh', async () => {
  localStorage.setItem('jwt', jwt(future()));
  globalThis.fetch = () => { throw Error('unexpected fetch'); };
  await Auth.init();
  assert.equal(Auth.isAuthenticated, true);
});

test('explicitly logged-out browser does not silently sign in from cookie', async () => {
  globalThis.fetch = () => { throw Error('unexpected fetch'); };
  await Auth.init();
  assert.equal(Auth.isAuthenticated, false);
});

test('idle active sessions refresh before JWT expiry', async () => {
  let calls = 0;
  globalThis.fetch = async () => { calls++; return response(jwt(future())); };
  Auth.setToken(jwt(Math.ceil(Date.now() / 1000) + 2));
  await new Promise(resolve => setTimeout(resolve, 2050));
  assert.equal(calls, 1);
  assert.equal(Auth.isAuthenticated, true);
});

test('an in-flight refresh cannot revive a manually logged-out session', async () => {
  Auth.setToken(jwt(future()));
  let finish;
  globalThis.fetch = () => new Promise(resolve => { finish = resolve; });
  const pending = Auth.refreshJwt();
  await Promise.resolve();
  Auth.logout();
  finish(response(jwt(future())));
  await assert.rejects(pending, /Authentication changed/);
  assert.equal(Auth.jwt, null);
  assert.equal(Auth.isAuthenticated, false);
});

test('refresh returning an expired JWT logs out rather than retaining a dead session', async () => {
  Auth.setToken(jwt(future()));
  globalThis.fetch = async () => response(jwt(expired()));
  await assert.rejects(Auth.refreshJwt(), /unusable JWT/);
  assert.equal(Auth.isAuthenticated, false);
  assert.equal(Auth.jwt, null);
});

test('a newer login is not discarded if bootstrapping the stale token fails', async () => {
  localStorage.setItem('jwt', jwt(expired()));
  let rejectRefresh, requestStarted;
  const started = new Promise(resolve => { requestStarted = resolve; });
  globalThis.fetch = () => new Promise((resolve, reject) => {
    rejectRefresh = reject;
    requestStarted();
  });
  const init = Auth.init();
  await started;
  Auth.setToken(jwt(future()));
  rejectRefresh(new Error('failed refresh'));
  await init;
  assert.equal(Auth.isAuthenticated, true);
  assert.equal(Auth.user.username, 'user');
});

class FakeChannel {
  constructor(readyState = 'connecting') { this.readyState = readyState; this.sent = []; this.events = new Map(); }
  send(raw) { this.sent.push(JSON.parse(raw)); }
  addEventListener(type, callback) { const ls = this.events.get(type) || []; ls.push(callback); this.events.set(type, ls); }
  removeEventListener(type, callback) { this.events.set(type, (this.events.get(type) || []).filter(x => x !== callback)); }
  emit(type, detail = {}) { for (const callback of this.events.get(type) || []) callback(detail); }
  close() { this.readyState = 'closed'; this.emit('close'); }
}

test('RTC control channels renew in place and stop after disposal', () => {
  Auth.setToken(jwt(future()));
  const channel = new FakeChannel('connecting');
  let renewAcks = 0;
  const stop = Auth.registerChannel(channel, {onRenewed:()=>renewAcks++});
  channel.readyState = 'open'; channel.emit('open');
  channel.emit('message', {data:JSON.stringify({type:'auth.renewed'})});
  assert.equal(renewAcks, 1);
  assert.equal(channel.sent.length, 1);
  assert.equal(channel.sent[0].action, 'auth.renew');
  Auth.setToken(jwt(future()+100));
  assert.equal(channel.sent.length, 2);
  stop();
  Auth.setToken(jwt(future()+200));
  assert.equal(channel.sent.length, 2);
  assert.equal(channel.readyState, 'open');
  channel.close();
});

test('registerChannel closes RTC channel on explicit logout', () => {
  Auth.setToken(jwt(future()));
  const channel = new FakeChannel('open');
  Auth.registerChannel(channel);
  Auth.logout();
  assert.equal(channel.readyState, 'closed');
  assert.equal(Auth._liveChannels.size, 0);
});

test('Api.authed.socket auto-renews before the application onOpen callback', async () => {
  const {default: Api} = await import('../src/api.js');
  Auth.setToken(jwt(future()));
  const oldWebSocket = globalThis.WebSocket;
  let ws;
  globalThis.WebSocket = class extends FakeChannel {
    constructor(url) { super(); this.url = url; ws = this; }
  };
  try {
    const seen = [];
    const created = Api.authed.socket('https://slides.example.test/', 'ws', {}, {
      onOpen: () => seen.push(...ws.sent.map(x => x.action)),
    });
    assert.equal(created, ws);
    assert.ok(ws.url.includes('jwt='));
    Auth.setToken(jwt(future()+100)); // changed while handshake in flight
    ws.readyState = 'open'; ws.emit('open');
    assert.deepEqual(seen, ['auth.renew']);
    assert.equal(ws.sent.length, 1);
    ws.close();
    Auth.setToken(jwt(future()+200));
    assert.equal(ws.sent.length, 1);
  } finally { globalThis.WebSocket = oldWebSocket; }
});

test('transient refresh failures keep session and retry; explicit logout cancels retry', async () => {
  Auth.setToken(jwt(future()));
  globalThis.fetch = async () => { throw new Error('temporary network failure'); };
  await assert.rejects(Auth.refreshJwt(), /temporary network/);
  assert.equal(Auth.isAuthenticated, true);
  assert.ok(Auth._refreshRetryTimer);
  Auth.logout();
  assert.equal(Auth._refreshRetryTimer, null);
  assert.equal(Auth.isAuthenticated, false);
});

test('liveSocket reconnects after transport loss and calls onResume once', async () => {
  const {default: Api} = await import('../src/api.js');
  Auth.setToken(jwt(future()));
  const previous = globalThis.WebSocket;
  const sockets = [];
  globalThis.WebSocket = class extends FakeChannel {
    static OPEN = 'open';
    constructor(url) { super(); this.url = url; sockets.push(this); }
  };
  try {
    let opens = 0, resumes = 0;
    const live = Api.authed.liveSocket('https://slides.example.test/', 'ws', {}, {
      retryBaseMs: 5, retryMaxMs: 10,
      onOpen: () => opens++,
      onResume: () => resumes++,
    });
    await new Promise(resolve => setTimeout(resolve, 0));
    assert.equal(sockets.length, 1);
    sockets[0].readyState = 'open'; sockets[0].emit('open');
    assert.equal(opens, 1);
    assert.equal(live.send(JSON.stringify({type:'hello'})), true);
    sockets[0].close();
    await new Promise(resolve => setTimeout(resolve, 25));
    assert.equal(sockets.length, 2);
    sockets[1].readyState = 'open'; sockets[1].emit('open');
    assert.equal(opens, 2);
    assert.equal(resumes, 1);
    live.close();
    await new Promise(resolve => setTimeout(resolve, 15));
    assert.equal(sockets.length, 2);
  } finally { globalThis.WebSocket = previous; }
});
