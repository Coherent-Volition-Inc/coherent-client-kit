// src/auth.js
import { AUTH_API } from '../constants.js';

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

// ------------------------------------------------------------------
// Small helpers (cookie-friendly POST + OAuth query parsing)
// ------------------------------------------------------------------

function _qsFromLocation() {
  // Supports both path-based and hash-based routing.
  if (window.location.search && window.location.search.includes('oauth=')) {
    return new URLSearchParams(window.location.search);
  }
  const h = window.location.hash || '';
  const idx = h.indexOf('?');
  if (idx >= 0) return new URLSearchParams(h.slice(idx + 1));
  return new URLSearchParams(window.location.search || '');
}

function _stripOauthParamsFromUrl() {
  const params = _qsFromLocation();
  if (!params.has('oauth')) return;

  const kill = ['oauth', 'login', 'linked', 'authed', 'error', 'provider', 'message'];
  kill.forEach(k => params.delete(k));

  // Query in location.search
  if (window.location.search && window.location.search.includes('oauth=')) {
    const url = new URL(window.location.href);
    kill.forEach(k => url.searchParams.delete(k));
    window.history.replaceState({}, '', url.toString());
    return;
  }

  // Query in hash
  const h = window.location.hash || '';
  const idx = h.indexOf('?');
  if (idx >= 0) {
    const base = h.slice(0, idx);
    const rest = params.toString();
    window.history.replaceState(
      {},
      '',
      window.location.pathname + window.location.search + (rest ? `${base}?${rest}` : base)
    );
  }
}

function _currentReturnUrl() {
  // Return current SPA URL (including hash route), without transient query params.
  const base = window.location.origin + window.location.pathname;
  const hash = window.location.hash ? window.location.hash.split('?')[0] : '';
  return base + hash;
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
      const ab    = Array.isArray(p) ? p[1] : p?.group_ability;
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
        // Cookie-based refresh: no body token, include credentials
        const response = await _postJson(
          `${AUTH_API}/api/token`,
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
    const response = await _postJson(
      `${AUTH_API}/api/password/authenticate`,
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
  // Optional GitHub OAuth helpers (same pattern as main app)
  // ------------------------------------------------------------------

  _oauthStartPath(provider) {
    return `/api/oauth/${provider}/start`;
  },

  startGithubOAuthLogin() {
    const nextUrl = _currentReturnUrl();
    const url = `${AUTH_API}${this._oauthStartPath('github')}?intent=login&next_url=${encodeURIComponent(nextUrl)}`;
    window.location.assign(url);
  },

  startGithubOAuthLink() {
    const nextUrl = _currentReturnUrl();
    const url = `${AUTH_API}${this._oauthStartPath('github')}?intent=link&next_url=${encodeURIComponent(nextUrl)}`;
    window.location.assign(url);
  },

  async _handleOAuthReturnIfPresent() {
    const q = _qsFromLocation();
    const provider = (q.get('oauth') || '').toLowerCase();
    if (!provider) return;

    const login = q.get('login') === '1' || q.get('authed') === '1';
    const linked = q.get('linked') === '1';

    if (login) {
      try {
        await this.refreshJwt();
        const dest = this.getPreferredLandingRoute('/home');
        _stripOauthParamsFromUrl();

        if (m?.route?.set) m.route.set(dest);
        return;
      } catch (e) {
        console.error('OAuth login completion failed:', e);
        _stripOauthParamsFromUrl();
        return;
      }
    }

    if (linked) {
      try { await this.refreshJwt(); } catch {}
      _stripOauthParamsFromUrl();
      return;
    }

    _stripOauthParamsFromUrl();
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
