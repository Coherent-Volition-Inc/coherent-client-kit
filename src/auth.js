// src/auth.js
import { handleOAuthReturnIfPresent, startOAuthFlow } from './oauth.js';

const m = window.m;

export function decodeJwt(token) {
  const base64Url = token.split('.')[1];
  const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  const jsonPayload = decodeURIComponent(
    atob(base64)
      .split('')
      .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
      .join('')
  );
  return JSON.parse(jsonPayload);
}

function flattenRouteTree(tree, out = [], parent = null) {
  for (const n of (tree || [])) {
    out.push(n);
    if (n.children?.length) flattenRouteTree(n.children, out, n);
  }
  return out;
}

async function _postJson(url, body, { credentials } = {}) {
  const res = await fetch(url, {
    method: 'POST',
    credentials: credentials || 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : null,
  });

  const ct = res.headers.get('content-type') || '';
  const payload = ct.includes('application/json')
    ? await res.json().catch(() => null)
    : await res.text().catch(() => null);

  if (!res.ok) {
    const msg = (payload && payload.message) ? payload.message : `HTTP ${res.status}`;
    const err = new Error(msg);
    err.code = res.status;
    err.response = payload;
    throw err;
  }

  return payload;
}

export const Auth = {
  jwt: null,
  isAuthenticated: false,
  user: null,
  iss: null,
  permissions: [],

  // route tree is optional; used for landing heuristics
  _routeTree: null,

  // runtime config (set by host app)
  _config: {
    authApi: null,
    homePath: '/home', // default landing path for OAuth completion
  },

  configure(opts = {}) {
    const {
      authApi,
      homePath,
    } = opts;

    if (authApi != null) {
      const s = String(authApi).trim().replace(/\/+$/, '');
      this._config.authApi = s || null;
    }

    if (homePath != null) {
      const hp = String(homePath).trim();
      if (hp) this._config.homePath = hp;
    }

    return this;
  },

  _requireAuthApi() {
    const v = this._config?.authApi;
    if (!v) {
      throw new Error('Auth is not configured. Call Auth.configure({ authApi }) before use.');
    }
    return v;
  },

  setRouteTree(tree) {
    this._routeTree = tree || null;
  },

  // ------------------------------------------------------------------
  // Permissions
  // ------------------------------------------------------------------

  hasPermission(ability, userGroup) {
    if (!ability) return true;

    for (const p of this.permissions) {
      const group = Array.isArray(p) ? p[0] : p?.user_group;
      const ab = Array.isArray(p) ? p[1] : p?.group_ability;
      if (!group || !ab) continue;

      const ability_ok = (ab === ability) || (ab === "*");
      const group_ok = (userGroup == null) || (group === userGroup) || (group === "*");

      if (ability_ok && group_ok) return true;
    }
    return false;
  },

  getUserId() {
    const iss = this.iss || null;
    const username = this.user?.username || null;
    if (iss && username) return `${iss}::${username}`;

    const direct = this.user?.user_id || this.user?.userId || null;
    if (typeof direct === 'string' && direct.includes('::')) return direct;

    return null;
  },

  // ------------------------------------------------------------------
  // Smart landing (based on route tree)
  // ------------------------------------------------------------------

  _utilityPaths: new Set(['/profile']),
  _landingOverrideKey: 'preferredLandingRoute',

  getPreferredLandingRouteOverride() {
    const raw = localStorage.getItem(this._landingOverrideKey);
    const s = (raw || '').trim();
    return s || '';
  },

  setPreferredLandingRouteOverride(path) {
    const p = String(path || '').trim();
    if (!p) return localStorage.removeItem(this._landingOverrideKey);
    localStorage.setItem(this._landingOverrideKey, p);
  },

  clearPreferredLandingRouteOverride() {
    localStorage.removeItem(this._landingOverrideKey);
  },

  // “Primary” means “not a utility route”
  getPreferredLandingRoute(homePath = '/home') {
    const override = this.getPreferredLandingRouteOverride();
    if (override) return override;

    const tree = this._routeTree;
    if (!tree) return homePath;

    const flat = flattenRouteTree(tree);
    const visible = flat
      .filter(r => r.path && r.path.startsWith('/'))
      .filter(r => !r.public) // only protected routes count as “app areas”
      .filter(r => !r.utility && !this._utilityPaths.has(r.path))
      .filter(r => !r.requires || this.hasPermission(r.requires, r.requiredGroup));

    const uniq = Array.from(new Set(visible.map(r => r.path)));
    if (uniq.length === 2 && uniq.includes(homePath)) {
      const other = uniq.find(p => p !== homePath);
      if (other) return other;
    }

    return homePath;
  },

  // ------------------------------------------------------------------
  // Session (cookie-based refresh token, JWT kept client-side for UI state)
  // ------------------------------------------------------------------

  setToken(jwt) {
    this.jwt = jwt || null;
    this.isAuthenticated = !!jwt;

    if (jwt) {
      localStorage.setItem('jwt', jwt);

      const payload = decodeJwt(jwt);
      this.user = payload.user || null;
      this.iss = payload.iss || null;
      this.permissions = Array.isArray(payload.user?.permissions)
        ? payload.user.permissions
        : [];
    } else {
      localStorage.removeItem('jwt');
      this.user = null;
      this.iss = null;
      this.permissions = [];
    }

    // Clean up old pre-cookie storage if present
    localStorage.removeItem('refreshToken');
  },

  // Backward-compatible alias (in case old callers still call setTokens)
  setTokens(jwt, _refreshTokenIgnored) {
    this.setToken(jwt);
  },

  logout() {
    this.jwt = null;
    this.isAuthenticated = false;
    this.user = null;
    this.iss = null;
    this.permissions = [];
    localStorage.removeItem('jwt');
    localStorage.removeItem('refreshToken');
    m.redraw();
  },

  _refreshPromise: null,
  async refreshJwt() {
    if (this._refreshPromise) return this._refreshPromise;

    this._refreshPromise = (async () => {
      try {
        const authApi = this._requireAuthApi();

        // Cookie-based refresh: no body token, include credentials
        const response = await _postJson(
          `${authApi}/api/token`,
          null,
          { credentials: 'include' }
        );

        if (response && response.jwt) {
          this.setToken(response.jwt);
          return response;
        }

        throw new Error(response?.message || 'Token refresh failed - no JWT in response');
      } catch (e) {
        this.logout();
        throw e;
      } finally {
        this._refreshPromise = null;
      }
    })();

    return this._refreshPromise;
  },

  // Optional helper if you want this module to own password login too
  async loginWithPassword(username, password) {
    const authApi = this._requireAuthApi();

    const response = await _postJson(
      `${authApi}/api/password/authenticate`,
      { username, password },
      { credentials: 'include' } // IMPORTANT for refresh cookie
    );

    if (response?.status === 'ok' && response.jwt) {
      this.setToken(response.jwt);
      return response;
    }

    throw new Error(response?.message || 'Authentication failed');
  },

  // ------------------------------------------------------------------
  // OAuth helpers (delegated to oauth.js)
  // ------------------------------------------------------------------

  startGithubOAuthLogin() {
    return startOAuthFlow({
      authApi: this._requireAuthApi(),
      provider: 'github',
      intent: 'login',
      win: window,
    });
  },

  startGithubOAuthLink() {
    return startOAuthFlow({
      authApi: this._requireAuthApi(),
      provider: 'github',
      intent: 'link',
      win: window,
    });
  },

  async _handleOAuthReturnIfPresent() {
    return handleOAuthReturnIfPresent({
      auth: this,
      homePath: this._config.homePath || '/home',
      navigate: (path) => {
        if (m?.route?.set) m.route.set(path);
      },
      logger: console,
      win: window,
    });
  },

  init() {
    const storedJwt = localStorage.getItem('jwt');
    if (storedJwt) {
      // Keep optimistic UI state from cached JWT
      this.setToken(storedJwt);
    } else {
      this.setToken(null);
    }

    // Handle OAuth callback if present (async, fire-and-forget)
    this._handleOAuthReturnIfPresent();
  },
};
