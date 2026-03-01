// src/api.js
import { Auth } from './auth.js';
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
    if (log) console.log("[Api.socket] connect", wsUrl);

    const ws = protocols ? new WebSocket(wsUrl, protocols) : new WebSocket(wsUrl);

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
      credentials = undefined, // NEW: 'include' | 'same-origin' | 'omit'
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

    // Use fetch for streaming OR any absolute URL (avoids mithril route parser on ports)
    const useFetch = !!onprogress || isAbsolute(url);

    if (!useFetch) {
      // Mithril path (relative URLs only)
      const requestOptions = { method: upper, url, headers, timeout };
      if (isBodyMethod) requestOptions.body = params; // object or FormData; mithril handles both
      return m.request(requestOptions);
    }

    // ---- Fetch path (streaming or absolute URLs) ----
    const fetchHeaders = { ...headers };
    if (onprogress && !fetchHeaders['Accept']) fetchHeaders['Accept'] = 'application/x-ndjson';

    const controller = new AbortController();
    const tid = timeout > 0 ? setTimeout(() => controller.abort(), timeout) : null;

    const fetchOpts = {
      method: upper,
      headers: fetchHeaders,
      signal: controller.signal,
    };

    // NEW: allow cookie-based flows when calling auth server cross-origin
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
          throw err;
        }

        const ct = res.headers.get('content-type') || '';
        return ct.includes('application/json') ? res.json() : res.text();
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
    } = options;

    const authHeaders = Auth.jwt ? { ...headers, Authorization: `Bearer ${Auth.jwt}` } : headers;

    return this.request(method, baseUrl, endpoint, {
      params,
      headers: authHeaders,
      timeout,
      onprogress,
      credentials,
    }).catch(err => {
      if (err && err.code === 403) {
        // Refresh is cookie-only now (Auth.refreshJwt sends credentials: 'include')
        return Auth.refreshJwt().then(() =>
          this.request(method, baseUrl, endpoint, {
            params,
            headers: Auth.jwt ? { ...headers, Authorization: `Bearer ${Auth.jwt}` } : headers,
            timeout,
            onprogress,
            credentials,
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
    return Api.socket(baseUrl, endpoint, p, options);
  }
};

export default Api;
