// src/oauth.js

export function oauthQueryParams(win = window) {
  // Supports both path-based and hash-based routing.
  if (win.location.search && win.location.search.includes('oauth=')) {
    return new URLSearchParams(win.location.search);
  }

  const h = win.location.hash || '';
  const idx = h.indexOf('?');
  if (idx >= 0) return new URLSearchParams(h.slice(idx + 1));

  return new URLSearchParams(win.location.search || '');
}

export function stripOAuthParamsFromUrl(win = window) {
  const params = oauthQueryParams(win);
  if (!params.has('oauth')) return false;

  const kill = ['oauth', 'login', 'linked', 'authed', 'error', 'provider', 'message'];
  kill.forEach(k => params.delete(k));

  // Query in location.search
  if (win.location.search && win.location.search.includes('oauth=')) {
    const url = new URL(win.location.href);
    kill.forEach(k => url.searchParams.delete(k));
    win.history.replaceState({}, '', url.toString());
    return true;
  }

  // Query in hash
  const h = win.location.hash || '';
  const idx = h.indexOf('?');
  if (idx >= 0) {
    const base = h.slice(0, idx);
    const rest = params.toString();
    win.history.replaceState(
      {},
      '',
      win.location.pathname + win.location.search + (rest ? `${base}?${rest}` : base)
    );
    return true;
  }

  return true;
}

export function currentReturnUrl(win = window) {
  // Return current SPA URL (including hash route), without transient query params.
  const base = win.location.origin + win.location.pathname;
  const hash = win.location.hash ? win.location.hash.split('?')[0] : '';
  return base + hash;
}

export function oauthStartPath(provider) {
  return `/api/oauth/${provider}/start`;
}

export function buildOAuthStartUrl({
  authApi,
  provider,
  intent,
  nextUrl,
  win = window,
}) {
  if (!authApi) throw new Error('buildOAuthStartUrl: authApi is required');
  if (!provider) throw new Error('buildOAuthStartUrl: provider is required');
  if (!intent) throw new Error('buildOAuthStartUrl: intent is required');

  const next = nextUrl || currentReturnUrl(win);
  return `${authApi}${oauthStartPath(provider)}?intent=${encodeURIComponent(intent)}&next_url=${encodeURIComponent(next)}`;
}

export function startOAuthFlow({
  authApi,
  provider,
  intent,
  nextUrl,
  win = window,
}) {
  const url = buildOAuthStartUrl({ authApi, provider, intent, nextUrl, win });
  win.location.assign(url);
  return url;
}

/**
 * Handle OAuth callback query params currently on the page.
 *
 * Returns true if an OAuth callback was present (and handled), else false.
 */
export async function handleOAuthReturnIfPresent({
  auth,
  homePath = '/home',
  navigate,               // optional (path) => void
  logger = console,       // optional logger
  win = window,
}) {
  if (!auth) throw new Error('handleOAuthReturnIfPresent: auth is required');

  const q = oauthQueryParams(win);
  const provider = (q.get('oauth') || '').toLowerCase();
  if (!provider) return false;

  const login = q.get('login') === '1' || q.get('authed') === '1';
  const linked = q.get('linked') === '1';

  if (login) {
    try {
      await auth.refreshJwt();
      const dest = auth.getPreferredLandingRoute(homePath);
      stripOAuthParamsFromUrl(win);
      if (navigate && dest) navigate(dest);
      return true;
    } catch (e) {
      try { logger?.error?.('OAuth login completion failed:', e); } catch {}
      stripOAuthParamsFromUrl(win);
      return true;
    }
  }

  if (linked) {
    try { await auth.refreshJwt(); } catch {}
    stripOAuthParamsFromUrl(win);
    return true;
  }

  stripOAuthParamsFromUrl(win);
  return true;
}
