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
