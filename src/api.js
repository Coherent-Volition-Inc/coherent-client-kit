// src/api.js
import { Auth, decodeJwt } from './auth.js';
const m = window.m;

function joinURL(base, endpoint) {
  const b = String(base || '').replace(/\/+$/, '/');
  const p = String(endpoint || '').replace(/^\/+/, '');
  return new URL(p, b).toString();
}

function isAbsolute(u) { return /^[a-zA-Z][a-zA-Z0-9+\-.]*:/.test(u); }

function normalizeWsBase(base) {
  // Accept ws(s):// or http(s):// (or schemeless //host)
  let b = String(base || "").trim();
  if (!b) return "";

  // schemeless URLs: //example.com -> use current page scheme to infer ws/wss
  if (b.startsWith("//")) {
    const pageIsHttps = (window.location && window.location.protocol === "https:");
    return (pageIsHttps ? "wss:" : "ws:") + b;
  }

  if (b.startsWith("ws://") || b.startsWith("wss://")) return b;
  if (b.startsWith("http://")) return "ws://" + b.slice("http://".length);
  if (b.startsWith("https://")) return "wss://" + b.slice("https://".length);

  // If it’s relative like "/api" or "localhost:4050", let URL() resolve it:
  // - "localhost:4050" is not a valid URL base; prefix with current scheme/host.
  if (!isAbsolute(b)) {
    const abs = new URL(b, window.location.origin).toString();
    return normalizeWsBase(abs);
  }
  return b;
}

function buildSocketUrl(baseUrl, endpoint, params = {}) {
  const base = normalizeWsBase(baseUrl);
  const url = joinURL(base, endpoint);

  const u = new URL(url);
  for (const [k, v] of Object.entries(params || {})) {
    if (v === undefined || v === null) continue;
    u.searchParams.set(k, String(v));
  }
  return u.toString();
}

async function parseResponse(res, responseType = 'auto') {
  if (responseType === 'response') return res;
  if (responseType === 'blob') return res.blob();
  if (responseType === 'arrayBuffer') return res.arrayBuffer();
  if (responseType === 'text') return res.text();
  if (responseType === 'json') return res.json();

  const ct = res.headers.get('content-type') || '';
  return ct.includes('application/json') ? res.json() : res.text();
}

const Api = {
  defaultTimeout: 20000,

  socket(baseUrl, endpoint, params = {}, options = {}) {
    const {
      protocols,
      log = false,
      onOpen,
      onMessage,
      onClose,
      onError,
    } = options;

    const wsUrl = buildSocketUrl(baseUrl, endpoint, params);
    if (log) {
      const safe = new URL(wsUrl);
      if (safe.searchParams.has('jwt')) safe.searchParams.set('jwt', '[redacted]');
      console.log('[Api.socket] connect', safe.toString());
    }

    const ws = protocols ? new WebSocket(wsUrl, protocols) : new WebSocket(wsUrl);

    // Authentication renewal must run before application onOpen callbacks,
    // since those callbacks often send a room.join immediately.
    if (typeof options.onCreate === 'function') options.onCreate(ws);
    if (typeof onOpen === "function") ws.addEventListener("open", onOpen);
    if (typeof onMessage === "function") ws.addEventListener("message", onMessage);
    if (typeof onClose === "function") ws.addEventListener("close", onClose);
    if (typeof onError === "function") ws.addEventListener("error", onError);

    return ws;
  },

  request(method, baseUrl, endpoint, options = {}) {
    const {
      params = {},
      headers = {},
      timeout = this.defaultTimeout,
      onprogress,
      credentials = undefined, // 'include' | 'same-origin' | 'omit'
      responseType = 'auto',   // 'auto' | 'json' | 'text' | 'blob' | 'arrayBuffer' | 'response'
    } = options;

    const upper = method.toUpperCase();

    // Build URL safely
    let url = joinURL(baseUrl, endpoint);

    // Append query for GET/DELETE
    const isBodyMethod = ['POST', 'PUT', 'PATCH'].includes(upper);
    if (!isBodyMethod && Object.keys(params).length > 0) {
      const qs = new URLSearchParams(params).toString();
      url += (url.includes('?') ? '&' : '?') + qs;
    }

    // Use fetch for streaming, absolute URLs, or explicit response typing.
    // Explicit responseType forces fetch so callers can request blob/arrayBuffer/raw response
    // even for relative URLs.
    const useFetch = !!onprogress || isAbsolute(url) || responseType !== 'auto';

    if (!useFetch) {
      // Mithril path (relative URLs only, default auto parsing)
      const requestOptions = { method: upper, url, headers, timeout };
      if (isBodyMethod) requestOptions.body = params; // object or FormData; mithril handles both
      return m.request(requestOptions);
    }

    // ---- Fetch path (streaming, absolute URLs, or explicit response types) ----
    const fetchHeaders = { ...headers };
    if (onprogress && !fetchHeaders['Accept']) {
      fetchHeaders['Accept'] = 'application/x-ndjson';
    }

    const controller = new AbortController();
    const tid = timeout > 0 ? setTimeout(() => controller.abort(), timeout) : null;

    const fetchOpts = {
      method: upper,
      headers: fetchHeaders,
      signal: controller.signal,
    };

    // Allow cookie-based flows when calling auth server cross-origin
    if (credentials) fetchOpts.credentials = credentials;

    if (isBodyMethod) {
      if (params instanceof FormData) {
        fetchOpts.body = params; // let browser set Content-Type boundary
      } else {
        if (!fetchHeaders['Content-Type']) fetchHeaders['Content-Type'] = 'application/json';
        fetchOpts.body = JSON.stringify(params);
      }
    }

    const readStream = async (res) => {
      if (!res.ok) {
        const txt = await res.text().catch(() => '');
        const err = new Error(`HTTP ${res.status}${txt ? `: ${txt}` : ''}`);
        err.code = res.status;
        try { err.response = JSON.parse(txt); } catch {}
        throw err;
      }
      if (!res.body) return null;

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '', lastObj = null;

      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split(/\r?\n/);
          buffer = lines.pop() || '';
          for (const line of lines) {
            const s = line.trim();
            if (!s) continue;
            try {
              lastObj = JSON.parse(s);
              onprogress(lastObj, res);
            } catch {}
          }
        }

        const tail = buffer.trim();
        if (tail) {
          try {
            const o = JSON.parse(tail);
            lastObj = o;
            onprogress(o, res);
          } catch {}
        }
        return lastObj;
      } finally {
        reader.releaseLock();
      }
    };

    const run = fetch(url, fetchOpts)
      .then(async (res) => {
        if (onprogress) return readStream(res);

        if (!res.ok) {
          const txt = await res.text().catch(() => '');
          const err = new Error(`HTTP ${res.status}${txt ? `: ${txt}` : ''}`);
          err.code = res.status;
          try { err.response = JSON.parse(txt); } catch {}
          throw err;
        }

        return parseResponse(res, responseType);
      })
      .finally(() => {
        if (tid) clearTimeout(tid);
      });

    return run;
  },

  authedRequest(method, baseUrl, endpoint, options = {}) {
    const {
      params = {},
      headers = {},
      timeout = this.defaultTimeout,
      onprogress,
      credentials,
      responseType = 'auto',
    } = options;

    const authHeaders = Auth.jwt ? { ...headers, Authorization: `Bearer ${Auth.jwt}` } : headers;

    return this.request(method, baseUrl, endpoint, {
      params,
      headers: authHeaders,
      timeout,
      onprogress,
      credentials,
      responseType,
    }).catch(err => {
      let claims = {};
      try { if (Auth.jwt) claims = decodeJwt(Auth.jwt); } catch {}
      if (!claims.purpose && err && (err.code === 401 || (err.code === 403 &&
          (err.response?.code === 'invalid_token' || (claims.exp && claims.exp * 1000 <= Date.now()))))) {
        // Refresh is cookie-only now (Auth.refreshJwt sends credentials: 'include')
        return Auth.refreshJwt().then(() =>
          this.request(method, baseUrl, endpoint, {
            params,
            headers: Auth.jwt ? { ...headers, Authorization: `Bearer ${Auth.jwt}` } : headers,
            timeout,
            onprogress,
            credentials,
            responseType,
          })
        );
      }
      throw err;
    });
  },

  get(b, e, p = {}, o = {}) { return this.request('GET', b, e, { ...o, params: p }); },
  post(b, e, p = {}, o = {}) { return this.request('POST', b, e, { ...o, params: p }); },
  put(b, e, p = {}, o = {}) { return this.request('PUT', b, e, { ...o, params: p }); },
  patch(b, e, p = {}, o = {}) { return this.request('PATCH', b, e, { ...o, params: p }); },
  delete(b, e, p = {}, o = {}) { return this.request('DELETE', b, e, { ...o, params: p }); }
};

Api.authed = {
  get(b, e, p = {}, o = {}) { return Api.authedRequest('GET', b, e, { ...o, params: p }); },
  post(b, e, p = {}, o = {}) { return Api.authedRequest('POST', b, e, { ...o, params: p }); },
  put(b, e, p = {}, o = {}) { return Api.authedRequest('PUT', b, e, { ...o, params: p }); },
  patch(b, e, p = {}, o = {}) { return Api.authedRequest('PATCH', b, e, { ...o, params: p }); },
  delete(b, e, p = {}, o = {}) { return Api.authedRequest('DELETE', b, e, { ...o, params: p }); },
  socket(baseUrl, endpoint, params = {}, options = {}) {
    const p = { ...(params || {}) };
    if (p.jwt === undefined || p.jwt === null || p.jwt === "") {
      if (Auth.jwt) p.jwt = Auth.jwt;
    }
    // A newly refreshed JWT is sent in-band to the existing socket; unlike
    // reconnecting, this preserves all server-side subscriptions and state.
    const ws = Api.socket(baseUrl, endpoint, p, {
      ...options,
      onCreate(ws) {
        if (options.autoRenew !== false) Auth.registerChannel(ws, {sendOnOpen:false, onRenewed:options.onRenewed});
        options.onCreate?.(ws);
      },
    });
    ws.addEventListener('close', (event) => {
      // A suspended tab can miss its refresh timer. Prompt a refresh when
      // an old server explicitly closes an expired lease; apps may reconnect.
      if (event.code === 4001 && Auth.isAuthenticated)
        Auth.refreshJwt({logoutOnFailure:false}).catch(() => {});
    });
    return ws;
  },

  /** A reconnecting *logical* socket. Unlike socket(), returns a controller.
   * onOpen runs after every physical connection; onResume runs on reconnect
   * so the application can fetch a current snapshot and rejoin subscriptions.
   * JWT rotation on a healthy transport needs no reconnection at all.
   */
  liveSocket(baseUrl, endpoint, params = {}, options = {}) {
    const {
      onOpen, onMessage, onClose, onError, onResume, onStateChange,
      retryBaseMs = 1000, retryMaxMs = 60000,
    } = options;
    let stopped = false, current = null, timer = null, failures = 0, everOpened = false;
    let generation = 0;
    const state = (name, detail = null) => { try { onStateChange?.(name, detail); } catch (e) { console.error(e); } };
    const controller = {
      get socket() { return current; },
      get readyState() { return current?.readyState ?? 3; },
      send(data) {
        if (!current || current.readyState !== WebSocket.OPEN) return false;
        try { current.send(data); return true; } catch { return false; }
      },
      close() {
        stopped = true; generation++;
        if (timer != null) clearTimeout(timer);
        timer = null;
        if (current) { try { current.close(); } catch {} }
        current = null;
        state('closed');
      },
    };
    const schedule = (detail) => {
      if (stopped) return;
      if (!Auth.isAuthenticated) { controller.close(); return; }
      const wait = Math.min(retryMaxMs, retryBaseMs * 2 ** Math.min(failures++, 8));
      state('reconnecting', detail);
      timer = setTimeout(() => { timer = null; connect(); }, wait);
      timer?.unref?.();
    };
    const connect = async () => {
      if (stopped) return;
      const id = ++generation;
      try {
        // If a suspended tab missed the pre-expiry timer, refresh *before*
        // attempting a new authenticated WebSocket upgrade.
        let claims;
        try { claims = Auth.jwt && decodeJwt(Auth.jwt); } catch {}
        if (claims?.exp && claims.exp * 1000 - Date.now() < 10000)
          await Auth.refreshJwt();
        if (stopped || id !== generation) return;
        if (!Auth.isAuthenticated || !Auth.jwt) { controller.close(); return; }
        state(everOpened ? 'reconnecting' : 'connecting');
        current = Api.authed.socket(baseUrl, endpoint, params, {
          ...options,
          onOpen(event) {
            if (stopped || id !== generation) return;
            failures = 0;
            state('connected');
            try { onOpen?.(event); } catch (e) { console.error(e); }
            if (everOpened) {
              try { onResume?.(event); } catch (e) { console.error(e); }
            }
            everOpened = true;
          },
          onMessage(event) { if (!stopped && id === generation) onMessage?.(event); },
          onError(event) { if (!stopped && id === generation) onError?.(event); },
          onClose(event) {
            if (stopped || id !== generation) return;
            current = null;
            try { onClose?.(event); } catch (e) { console.error(e); }
            // A 4001 from an older server calls refreshJwt in socket().
            // The next connect() awaits an up-to-date credential if needed.
            schedule(event);
          },
        });
      } catch (error) {
        if (!stopped && id === generation) schedule(error);
      }
    };
    void connect();
    return controller;
  }
};

export default Api;
