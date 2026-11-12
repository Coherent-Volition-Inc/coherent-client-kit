import test from 'node:test';
import assert from 'node:assert/strict';
const values = new Map();
globalThis.localStorage = { getItem: key => values.get(key) ?? null, setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key) };
globalThis.window = { m: { redraw() {} }, location: { origin: 'https://ui.example', hash: '', search: '' } };
const { Auth } = await import('../src/auth.js');
const { default: Api } = await import('../src/api.js');
const { handleOAuthReturnIfPresent, stripOAuthParamsFromUrl } = await import('../src/oauth.js');
const jwt = (extra = {}) => 'header.' + Buffer.from(JSON.stringify({ user: { username: 'alice', permissions: [] }, iss: 'auth', exp: Math.floor(Date.now()/1000)+900, ...extra })).toString('base64url') + '.sig';
const response = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
function setup(requestMfaCode = async () => '123456') { Auth.configure({ authApi: 'https://auth.example', homePath: '/home', requestMfaCode }); Auth.setToken(null); }

test('ordinary password login retains existing call and return contract', async () => {
  setup(); const token = jwt();
  globalThis.fetch = async () => response({ status: 'ok', jwt: token });
  const result = await Auth.loginWithPassword('alice', 'password');
  assert.equal(result.jwt, token); assert.equal(Auth.jwt, token);
});
test('password MFA is completed internally, and no partial token is installed', async () => {
  let prompts = 0; setup(async () => { prompts++; assert.equal(Auth.jwt, null); return '123456'; });
  const calls = []; const token = jwt();
  globalThis.fetch = async (url, options) => { calls.push([url, JSON.parse(options.body)]); return response(calls.length === 1 ? { status: 'mfa_required', challenge: 'opaque' } : { status: 'ok', jwt: token }); };
  assert.equal((await Auth.loginWithPassword('alice', 'password')).jwt, token);
  assert.equal(prompts, 1); assert.deepEqual(calls[1][1], { challenge: 'opaque', code: '123456' });
});
test('invalid MFA retries and cancellation never installs credentials', async () => {
  let attempts = 0; setup(async () => ++attempts === 1 ? '000000' : null);
  globalThis.fetch = async () => response({ status: 'error' }, 403);
  await assert.rejects(Auth.completeMfa('opaque'), err => err.code === 'MFA_CANCELLED');
  assert.equal(Auth.jwt, null); assert.equal(attempts, 2);
});
test('reset token is memory-only and cannot refresh', async () => {
  setup(); const token = jwt({ purpose: 'password_reset' }); Auth.setToken(token);
  assert.equal(localStorage.getItem('jwt'), null);
  globalThis.fetch = async () => { throw new Error('must not request'); };
  await assert.rejects(Auth.refreshJwt(), /cannot refresh/);
});
test('MFA after password reset is handled internally', async () => {
  setup(); Auth.setToken(jwt({ purpose: 'password_reset' })); let count = 0;
  globalThis.fetch = async () => response(++count === 1 ? { status: 'mfa_required', challenge: 'after-reset' } : { status: 'ok', jwt: jwt() });
  const result = await Auth.changePassword({ newPassword: 'new-password' });
  assert.equal(result.status, 'ok'); assert.equal(count, 2);
});
test('permission-denied mutation is not refreshed or replayed', async () => {
  setup(); Auth.setToken(jwt()); let count = 0;
  globalThis.fetch = async () => { count++; return response({ status: 'error', message: 'forbidden' }, 403); };
  await assert.rejects(Api.authed.post('https://store.example/', '/buy', {}));
  assert.equal(count, 1);
});
test('authentication rejection refreshes then retries once', async () => {
  setup(); Auth.setToken(jwt()); const calls = [];
  globalThis.fetch = async url => { calls.push(url); return calls.length === 1 ? response({ code: 'invalid_token' }, 403) : calls.length === 2 ? response({ status: 'ok', jwt: jwt() }) : response({ status: 'ok' }); };
  assert.equal((await Api.authed.post('https://store.example/', '/buy', {})).status, 'ok');
  assert.equal(calls.length, 3);
});
test('OAuth MFA challenge is removed from URL before internal completion', async () => {
  let cleaned = false, completed = false, navigated = false;
  const win = { location: { href: 'https://ui.example/?oauth=github&mfa_challenge=opaque', search: '?oauth=github&mfa_challenge=opaque', hash: '', pathname: '/' }, history: { replaceState(a,b,url) { cleaned = !url.includes('mfa_challenge'); } } };
  await handleOAuthReturnIfPresent({ win, auth: { async completeMfa(challenge) { assert.equal(challenge, 'opaque'); assert.ok(cleaned); completed = true; }, getPreferredLandingRoute: () => '/home' }, navigate: () => { navigated = true; } });
  assert.ok(completed && navigated);
});
test('same-origin tabs coordinate refresh with Web Locks when available', async () => {
  setup(); let locked = false;
  const original = globalThis.navigator;
  Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { locks: { async request(name, callback) { assert.match(name, /cvkit:refresh:/); locked = true; return callback(); } } } });
  try {
    globalThis.fetch = async () => { assert.ok(locked); return response({ status: 'ok', jwt: jwt() }); };
    await Auth.refreshJwt();
  } finally { Object.defineProperty(globalThis, 'navigator', { configurable: true, value: original }); }
});

test('reset credential exchange returns to the caller without presenting UI or a normal session', async () => {
  setup(); const reset = jwt({ purpose: 'password_reset', user: { username: 'alice', permissions: [{ user_group: '*', group_ability: '*' }] } });
  let requests = 0;
  globalThis.fetch = async () => { requests++; return response({ status: 'ok', jwt: reset }); };
  const result = await Auth.loginWithPassword('alice', 'one-time-reset-token');
  assert.equal(result.jwt, reset); assert.equal(Auth.jwt, reset);
  assert.equal(Auth.isAuthenticated, false); assert.deepEqual(Auth.permissions, []);
  assert.equal(localStorage.getItem('jwt'), null); assert.equal(requests, 1);
  assert.equal(Auth.completePasswordReset, undefined);
});
test('a caller-owned reset form can submit its password and establish normal authentication', async () => {
  setup(); const reset = jwt({ purpose: 'password_reset' }), normal = jwt(); const requests = [];
  globalThis.fetch = async (url, options) => {
    requests.push([url, options]);
    return response({ status: 'ok', jwt: requests.length === 1 ? reset : normal });
  };
  await Auth.loginWithPassword('alice', 'one-time-reset-token');
  const result = await Auth.changePassword({ newPassword: 'replacement-password' });
  assert.equal(requests[1][1].headers.Authorization, `Bearer ${reset}`);
  assert.equal(result.jwt, normal); assert.equal(Auth.isAuthenticated, true);
  assert.equal(localStorage.getItem('jwt'), normal);
});
test('invalid reset submissions leave the restricted credential available for caller validation UI', async () => {
  setup(); const reset = jwt({ purpose: 'password_reset' }); Auth.setToken(reset);
  globalThis.fetch = async () => response({ message: 'invalid new password' }, 400);
  await assert.rejects(Auth.changePassword({ newPassword: 'short' }), e => e.code === 400);
  assert.equal(Auth.jwt, reset); assert.equal(Auth.isAuthenticated, false);
});
