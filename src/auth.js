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

function joinPath(parent, child) {
  const p = String(parent || '').replace(/\/+$/, '');
  const c = String(child || '').replace(/^\/+/, '');

  if (!p) return '/' + c;
  if (!c) return p || '/';
  return p + '/' + c;
}

function flattenRouteTree(tree, out = [], inherited = {}, parentPath = '') {
  for (const n of (tree || [])) {
    const rawPath = n.path || '';
    const path = rawPath.startsWith('/')
      ? rawPath
      : joinPath(parentPath, rawPath);

    const merged = {
      ...n,
      path,
      public: (n.public !== undefined)
        ? n.public
        : (inherited.public ?? false),
      requires: (n.requires !== undefined)
        ? n.requires
        : (inherited.requires ?? null),
      requiredGroup: (n.requiredGroup !== undefined)
        ? n.requiredGroup
        : (inherited.requiredGroup ?? null),
      utility: n.utility ?? false,
    };

    out.push(merged);

    if (n.children?.length) {
      flattenRouteTree(
        n.children,
        out,
        {
          public: merged.public,
          requires: merged.requires,
          requiredGroup: merged.requiredGroup,
        },
        path
      );
    }
  }

  return out;
}

function normalizeInternalPath(path) {
  const p = String(path || '').trim();

  // Only permit application-internal paths. In particular, reject
  // protocol-relative URLs such as //example.com.
  if (!p || !p.startsWith('/') || p.startsWith('//')) return '';

  return p;
}

function routePathname(path) {
  const p = normalizeInternalPath(path);
  if (!p) return '';

  const splitAt = p.search(/[?#]/);
  const pathname = splitAt === -1 ? p : p.slice(0, splitAt);

  if (!pathname) return '/';
  return pathname.length > 1
    ? pathname.replace(/\/+$/, '')
    : pathname;
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function routePatternMatches(pattern, actualPath) {
  const expected = routePathname(pattern);
  const actual = routePathname(actualPath);

  if (!expected || !actual) return false;

  const source = expected
    .split('/')
    .map(segment => {
      // Mithril variadic route parameter, e.g. /files/:path...
      if (/^:[^/]+\.\.\.$/.test(segment)) return '.+';

      // Mithril route parameter, e.g. /audio/:id
      if (/^:[^/]+$/.test(segment)) return '[^/]+';

      return escapeRegex(segment);
    })
    .join('/');

  return new RegExp(`^${source}/?$`).test(actual);
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
    const msg = (payload && payload.message)
      ? payload.message
      : `HTTP ${res.status}`;

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

  // Route tree is optional; used for landing heuristics and validating
  // interrupted routes before restoring them.
  _routeTree: null,

  // Resolves when init() has finished the OAuth-return check.
  // Guards and landing routes await this before making auth decisions.
  _initPromise: null,
  _initDone: false,

  // Runtime config (set by host app).
  _config: {
    authApi: null,
    homePath: null,
  },

  configure(opts = {}) {
    const { authApi, homePath } = opts;

    // --- authApi REQUIRED ---
    if (authApi == null) {
      throw new Error("Auth.configure: 'authApi' is required");
    }

    const api = String(authApi).trim().replace(/\/+$/, '');
    if (!api) {
      throw new Error(
        "Auth.configure: 'authApi' must be a non-empty string"
      );
    }

    // --- homePath REQUIRED ---
    if (homePath == null) {
      throw new Error("Auth.configure: 'homePath' is required");
    }

    const hp = String(homePath).trim();
    if (!hp || !hp.startsWith('/')) {
      throw new Error(
        "Auth.configure: 'homePath' must be a non-empty absolute path " +
        "(e.g. '/home')"
      );
    }

    this._config.authApi = api;
    this._config.homePath = hp;

    return this;
  },

  _requireAuthApi() {
    const v = this._config?.authApi;

    if (!v) {
      throw new Error(
        'Auth is not configured. ' +
        'Call Auth.configure({ authApi }) before use.'
      );
    }

    return v;
  },

  _requireHomePath() {
    const hp = this._config?.homePath;

    if (!hp) {
      throw new Error(
        'Auth is not configured. ' +
        'Call Auth.configure({ authApi, homePath }) before use.'
      );
    }

    return hp;
  },

  setRouteTree(tree) {
    this._routeTree = tree || null;
  },

  // ------------------------------------------------------------------
  // Permissions
  // ------------------------------------------------------------------

  hasPermission(ability, userGroup) {
    if (!ability) return true;

    const abilities = Array.isArray(ability)
      ? ability
      : [ability];

    for (const p of this.permissions) {
      const group = Array.isArray(p)
        ? p[0]
        : p?.user_group;

      const ab = Array.isArray(p)
        ? p[1]
        : p?.group_ability;

      if (!group || !ab) continue;

      const ability_ok =
        ab === '*' ||
        abilities.some(a => ab === a);

      const group_ok =
        userGroup == null ||
        group === userGroup ||
        group === '*';

      if (ability_ok && group_ok) return true;
    }

    return false;
  },

  getUserId() {
    const iss = this.iss || null;
    const username = this.user?.username || null;

    if (iss && username) {
      return `${iss}::${username}`;
    }

    const direct =
      this.user?.user_id ||
      this.user?.userId ||
      null;

    if (
      typeof direct === 'string' &&
      direct.includes('::')
    ) {
      return direct;
    }

    return null;
  },

  // ------------------------------------------------------------------
  // Smart landing and interrupted-route restoration
  // ------------------------------------------------------------------

  _utilityPaths: new Set(['/profile']),
  _landingOverrideKey: 'preferredLandingRoute',
  _interruptedPathKey: 'cvkit.auth.interruptedPath',

  _getCurrentRoutePath() {
    try {
      if (typeof m?.route?.get === 'function') {
        return normalizeInternalPath(m.route.get());
      }
    } catch {}

    return '';
  },

  _canRestorePath(path, { checkPermission = true } = {}) {
    const candidate = normalizeInternalPath(path);

    if (
      !candidate ||
      routePathname(candidate) === '/'
    ) {
      return false;
    }

    // If the host has not supplied a route tree, we can still safely
    // restore an internal route. The router remains responsible for
    // deciding whether that route exists.
    const tree = this._routeTree;
    if (!tree) return true;

    const flat = flattenRouteTree(tree);

    const route = flat.find(r =>
      r.path &&
      (r.component || r.redirectTo) &&
      !r.public &&
      routePatternMatches(r.path, candidate)
    );

    if (!route) return false;

    if (
      checkPermission &&
      route.requires &&
      !this.hasPermission(
        route.requires,
        route.requiredGroup
      )
    ) {
      return false;
    }

    return true;
  },

  rememberCurrentPath(path = this._getCurrentRoutePath()) {
    const candidate = normalizeInternalPath(path);

    // While authenticated, validate against the user's current
    // permissions. While logged out, validate only that this is a known
    // protected route; the new user's permissions are checked on restore.
    if (
      !candidate ||
      !this._canRestorePath(candidate, {
        checkPermission: this.isAuthenticated,
      })
    ) {
      return '';
    }

    try {
      window.sessionStorage.setItem(
        this._interruptedPathKey,
        candidate
      );
    } catch (error) {
      console.warn(
        'Unable to remember interrupted route:',
        error
      );

      return '';
    }

    return candidate;
  },

  peekInterruptedPath() {
    try {
      return normalizeInternalPath(
        window.sessionStorage.getItem(
          this._interruptedPathKey
        )
      );
    } catch {
      return '';
    }
  },

  clearInterruptedPath() {
    try {
      window.sessionStorage.removeItem(
        this._interruptedPathKey
      );
    } catch {}
  },

  consumeInterruptedPath() {
    const candidate = this.peekInterruptedPath();

    this.clearInterruptedPath();

    if (
      !candidate ||
      !this._canRestorePath(candidate, {
        checkPermission: this.isAuthenticated,
      })
    ) {
      return '';
    }

    return candidate;
  },

  getPreferredLandingRouteOverride() {
    const raw = localStorage.getItem(
      this._landingOverrideKey
    );

    const s = (raw || '').trim();
    return s || '';
  },

  setPreferredLandingRouteOverride(path) {
    const p = String(path || '').trim();

    if (!p) {
      return localStorage.removeItem(
        this._landingOverrideKey
      );
    }

    localStorage.setItem(
      this._landingOverrideKey,
      p
    );
  },

  clearPreferredLandingRouteOverride() {
    localStorage.removeItem(
      this._landingOverrideKey
    );
  },

  // "Primary" means "not a utility route".
  getPreferredLandingRoute(homePath) {
    const hp = String(homePath || '').trim();

    if (!hp) {
      throw new Error(
        'Auth.getPreferredLandingRoute(homePath): ' +
        'homePath is required'
      );
    }

    if (this.isAuthenticated) {
      // First preference: a route explicitly remembered when refresh
      // failed or immediately before starting an OAuth login.
      const interruptedPath =
        this.consumeInterruptedPath();

      if (interruptedPath) {
        return interruptedPath;
      }

      // Password login commonly happens in place: ProtectedRoute renders
      // the login component without changing the current URL. This covers
      // that case even when no session value was required.
      const currentPath =
        this._getCurrentRoutePath();

      if (
        currentPath &&
        this._canRestorePath(currentPath, {
          checkPermission: true,
        })
      ) {
        return currentPath;
      }
    }

    const tree = this._routeTree;
    if (!tree) return hp;

    const flat = flattenRouteTree(tree);

    const visible = flat
      .filter(r =>
        r.path &&
        r.path.startsWith('/')
      )
      .filter(r =>
        r.path !== '/'
      )
      .filter(r =>
        !r.public
      )
      .filter(r =>
        !r.utility &&
        !this._utilityPaths.has(r.path)
      )
      .filter(r =>
        !r.requires ||
        this.hasPermission(
          r.requires,
          r.requiredGroup
        )
      );

    const uniq = Array.from(
      new Set(
        visible.map(r => r.path)
      )
    );

    const override =
      this.getPreferredLandingRouteOverride();

    if (
      override &&
      uniq.includes(override)
    ) {
      return override;
    }

    if (
      uniq.length === 2 &&
      uniq.includes(hp)
    ) {
      const other = uniq.find(
        p => p !== hp
      );

      if (other) return other;
    }

    if (uniq.includes(hp)) return hp;
    if (uniq.length > 0) return uniq[0];

    // Caller-provided fallback.
    return hp;
  },

  // ------------------------------------------------------------------
  // Session
  //
  // Refresh token is cookie-based. The JWT is kept client-side for UI
  // state and authorization headers.
  // ------------------------------------------------------------------

  setToken(jwt) {
    this.jwt = jwt || null;
    this.isAuthenticated = !!jwt;

    if (jwt) {
      localStorage.setItem('jwt', jwt);

      const payload = decodeJwt(jwt);

      this.user = payload.user || null;
      this.iss = payload.iss || null;
      this.permissions = Array.isArray(
        payload.user?.permissions
      )
        ? payload.user.permissions
        : [];
    } else {
      localStorage.removeItem('jwt');

      this.user = null;
      this.iss = null;
      this.permissions = [];
    }

    // Clean up old pre-cookie storage if present.
    localStorage.removeItem('refreshToken');
  },

  // Backward-compatible alias in case old callers still use setTokens.
  setTokens(jwt, _refreshTokenIgnored) {
    this.setToken(jwt);
  },

  logout({ rememberCurrentPath = false } = {}) {
    if (rememberCurrentPath) {
      const remembered =
        this.rememberCurrentPath();

      if (!remembered) {
        this.clearInterruptedPath();
      }
    } else {
      // Explicit logout should not send the user back into the previous
      // protected screen after their next login.
      this.clearInterruptedPath();
    }

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

  async refreshJwt({ logoutOnFailure = true } = {}) {
    if (this._refreshPromise) return this._refreshPromise;

    this._refreshPromise = (async () => {
      try {
        const authApi = this._requireAuthApi();

        const response = await _postJson(
          `${authApi}/api/token`,
          null,
          { credentials:'include' }
        );

        if (response?.jwt) {
          this.setToken(response.jwt);
          return response;
        }

        throw new Error(
          response?.message ||
            'Token refresh failed - no JWT in response'
        );
      } catch (e) {
        if (logoutOnFailure) {
          this.logout({ rememberCurrentPath:true });
        }
        throw e;
      } finally {
        this._refreshPromise = null;
      }
    })();

    return this._refreshPromise;
  },

  async loginWithPassword(username, password) {
    const authApi =
      this._requireAuthApi();

    const response = await _postJson(
      `${authApi}/api/password/authenticate`,
      {
        username,
        password,
      },
      {
        credentials: 'include',
      }
    );

    if (
      response?.status === 'ok' &&
      response.jwt
    ) {
      this.setToken(response.jwt);
      return response;
    }

    throw new Error(
      response?.message ||
      'Authentication failed'
    );
  },

  async changePassword({
    currentPassword,
    newPassword,
  }) {
    const authApi =
      this._requireAuthApi();

    const body = currentPassword
      ? {
          current_password: currentPassword,
          new_password: newPassword,
        }
      : {
          new_password: newPassword,
        };

    const response = await fetch(
      `${authApi}/api/me/password`,
      {
        method: 'PATCH',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          ...(this.jwt
            ? {
                Authorization: `Bearer ${this.jwt}`,
              }
            : {}),
        },
        body: JSON.stringify(body),
      }
    );

    const payload = await response
      .json()
      .catch(() => null);

    if (!response.ok) {
      const err = new Error(
        payload?.message ||
        `HTTP ${response.status}`
      );

      err.code = response.status;
      throw err;
    }

    if (payload?.jwt) {
      this.setToken(payload.jwt);
    }

    return payload;
  },

  // ------------------------------------------------------------------
  // OAuth helpers delegated to oauth.js
  // ------------------------------------------------------------------

  _oauthProviders: [
    'github',
    'google',
  ],

  _startOAuth(
    provider,
    intent,
    { nextUrl, win } = {}
  ) {
    // sessionStorage survives an OAuth round trip in the same tab.
    // Keep the current protected route as a fallback when the caller
    // did not provide an explicit nextUrl.
    if (intent === 'login') {
      this.rememberCurrentPath();
    }

    return startOAuthFlow({
      authApi: this._requireAuthApi(),
      provider,
      intent,
      ...(nextUrl !== undefined
        ? { nextUrl }
        : {}),
      win: win || window,
    });
  },

  oauth: null,

  async _handleOAuthReturnIfPresent() {
    const interruptedPath =
      this.peekInterruptedPath();

    const oauthHomePath = (
      interruptedPath &&
      this._canRestorePath(
        interruptedPath,
        {
          // The OAuth return handler installs the new JWT, so permissions
          // may not be available yet while choosing its fallback.
          checkPermission: false,
        }
      )
    )
      ? interruptedPath
      : this._requireHomePath();

    let navigated = false;

    const result =
      await handleOAuthReturnIfPresent({
        auth: this,
        homePath: oauthHomePath,

        navigate: path => {
          navigated = true;

          if (m?.route?.set) {
            m.route.set(path);
          }
        },

        logger: console,
        win: window,
      });

    // Avoid leaving a stale destination in this tab after a successful
    // OAuth-return navigation. If no OAuth return was present, navigate
    // was never called and the pending destination remains untouched.
    if (
      this.isAuthenticated &&
      navigated
    ) {
      this.clearInterruptedPath();
    }

    return result;
  },

  init() {
    this._requireAuthApi();
    this._requireHomePath();

    const storedJwt =
      localStorage.getItem('jwt');

    this.setToken(storedJwt || null);

    // Store the promise so route guards and landing routes can await it
    // before making any auth decisions. Always resolves and never rejects.
    this._initDone = false;

    this._initPromise =
      this._handleOAuthReturnIfPresent()
        .catch(() => {})
        .then(() => {
          this._initDone = true;
        });

    return this._initPromise;
  },
};

(function attachOAuthHelpers() {
  const providers = Array.isArray(
    Auth._oauthProviders
  )
    ? Auth._oauthProviders
    : [];

  Auth.oauth = Auth.oauth || {};

  for (const p of providers) {
    const provider = String(p || '')
      .trim()
      .toLowerCase();

    if (!provider) continue;

    Auth.oauth[provider] = Object.freeze({
      startLogin(nextUrl) {
        return Auth._startOAuth(
          provider,
          'login',
          { nextUrl }
        );
      },

      startLink(nextUrl) {
        return Auth._startOAuth(
          provider,
          'link',
          { nextUrl }
        );
      },
    });
  }
})();
