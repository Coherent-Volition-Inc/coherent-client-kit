// src/oauth.js

const OAUTH_PARAM_KEYS = [
  'oauth',
  'login',
  'linked',
  'authed',
  'error',
  'provider',
  'message',
];

export function oauthQueryParams(win = window) {
  // Supports both path-based and hash-based routing.
  if (
    win.location.search &&
    win.location.search.includes('oauth=')
  ) {
    return new URLSearchParams(win.location.search);
  }

  const h = win.location.hash || '';
  const idx = h.indexOf('?');

  if (idx >= 0) {
    return new URLSearchParams(h.slice(idx + 1));
  }

  return new URLSearchParams(
    win.location.search || ''
  );
}

export function stripOAuthParamsFromUrl(win = window) {
  const params = oauthQueryParams(win);

  if (!params.has('oauth')) {
    return false;
  }

  // OAuth callback query in location.search.
  if (
    win.location.search &&
    win.location.search.includes('oauth=')
  ) {
    const url = new URL(win.location.href);

    for (const key of OAUTH_PARAM_KEYS) {
      url.searchParams.delete(key);
    }

    win.history.replaceState(
      {},
      '',
      url.toString()
    );

    return true;
  }

  // OAuth callback query in the hash route.
  const hash = win.location.hash || '';
  const idx = hash.indexOf('?');

  if (idx >= 0) {
    const base = hash.slice(0, idx);
    const remaining = new URLSearchParams(
      hash.slice(idx + 1)
    );

    for (const key of OAUTH_PARAM_KEYS) {
      remaining.delete(key);
    }

    const query = remaining.toString();

    win.history.replaceState(
      {},
      '',
      win.location.pathname +
        win.location.search +
        (
          query
            ? `${base}?${query}`
            : base
        )
    );

    return true;
  }

  return true;
}

export function currentReturnUrl(win = window) {
  // Return the current SPA URL, including the hash route, while removing
  // only transient OAuth callback parameters. Preserve unrelated query
  // parameters belonging to the application route.
  const url = new URL(win.location.href);

  for (const key of OAUTH_PARAM_KEYS) {
    url.searchParams.delete(key);
  }

  const hash = url.hash || '';
  const idx = hash.indexOf('?');

  if (idx >= 0) {
    const base = hash.slice(0, idx);
    const params = new URLSearchParams(
      hash.slice(idx + 1)
    );

    for (const key of OAUTH_PARAM_KEYS) {
      params.delete(key);
    }

    const query = params.toString();

    url.hash = query
      ? `${base}?${query}`
      : base;
  }

  return url.toString();
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
  if (!authApi) {
    throw new Error(
      'buildOAuthStartUrl: authApi is required'
    );
  }

  if (!provider) {
    throw new Error(
      'buildOAuthStartUrl: provider is required'
    );
  }

  if (!intent) {
    throw new Error(
      'buildOAuthStartUrl: intent is required'
    );
  }

  const next =
    nextUrl ||
    currentReturnUrl(win);

  return (
    `${authApi}${oauthStartPath(provider)}` +
    `?intent=${encodeURIComponent(intent)}` +
    `&next_url=${encodeURIComponent(next)}`
  );
}

export function startOAuthFlow({
  authApi,
  provider,
  intent,
  nextUrl,
  win = window,
}) {
  const url = buildOAuthStartUrl({
    authApi,
    provider,
    intent,
    nextUrl,
    win,
  });

  win.location.assign(url);
  return url;
}

/**
 * Handle OAuth callback query params currently on the page.
 *
 * Returns true if an OAuth callback was present and handled,
 * otherwise false.
 */
export async function handleOAuthReturnIfPresent({
  auth,
  homePath = '/home',
  navigate,
  logger = console,
  win = window,
}) {
  if (!auth) {
    throw new Error(
      'handleOAuthReturnIfPresent: auth is required'
    );
  }

  const q = oauthQueryParams(win);
  const provider = (
    q.get('oauth') || ''
  ).toLowerCase();

  if (!provider) {
    return false;
  }

  const login =
    q.get('login') === '1' ||
    q.get('authed') === '1';

  const linked =
    q.get('linked') === '1';

  // Remove callback parameters before refreshing. If refresh fails,
  // Auth.refreshJwt() may remember the current route; it should remember
  // the clean application route rather than the OAuth callback URL.
  stripOAuthParamsFromUrl(win);

  if (login) {
    try {
      await auth.refreshJwt();

      const dest =
        auth.getPreferredLandingRoute(homePath);

      if (navigate && dest) {
        navigate(dest);
      }

      return true;
    } catch (error) {
      try {
        logger?.error?.(
          'OAuth login completion failed:',
          error
        );
      } catch {}

      return true;
    }
  }

  if (linked) {
    try {
      await auth.refreshJwt();
    } catch {}

    return true;
  }

  return true;
}
