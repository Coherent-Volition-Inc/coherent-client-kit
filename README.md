# Coherent Client Kit

Browser-side auth/API/router helpers for Coherent Volition front-ends.

This repo is intentionally **source-only** and is meant to be consumed directly from **jsDelivr + GitHub tags** (no npm publish step).

The main stable entrypoint is:

- `src/core.js`

---

## What this gives you

- `Auth` (cookie-based auth/JWT UI state, OAuth helpers)
- `Api` (fetch + Mithril-friendly request wrapper, authed retries)
- `ProtectedRouteFactory` / `compileRouteMap` / `LandingRoute` (Mithril routing helpers)
- OAuth URL/query helpers

Designed for **browser ESM** (module scripts), especially Mithril.js front-ends.

---

## Requirements

- A modern browser with ES module support
- `mithril` loaded globally as `window.m` (for routing/redraw features)

This library assumes Mithril is already present on the page (same pattern as other CDN globals in Coherent front-ends).

---

## Installation (jsDelivr + import map)

You do **not** need a jsDelivr account.

Add an **import map** to your `index.html` and point `"CVKit"` at a tagged release:

```html
<script type="importmap">
{
  "imports": {
    "CVKit": "https://cdn.jsdelivr.net/gh/coherentvolition/coherent-client-kit@v0.1.0/src/core.js",
    "CVKit/": "https://cdn.jsdelivr.net/gh/coherentvolition/coherent-client-kit@v0.1.0/src/"
  }
}
</script>
````

Then load your app as a module:

```html
<script type="module" src="/main.js"></script>
```

### `@latest` vs pinned versions

* `@v0.1.0` → stable, recommended for production
* `@latest` → convenient, mutable (CDN cache may lag after updates)

---

## Quick start

### `index.html` (minimal example)

```html
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>CVKit Example</title>

    <!-- Mithril (required by auth/router helpers) -->
    <script src="https://unpkg.com/mithril/mithril.js"></script>

    <!-- CVKit import map -->
    <script type="importmap">
    {
      "imports": {
        "CVKit": "https://cdn.jsdelivr.net/gh/coherentvolition/coherent-client-kit@v0.1.0/src/core.js",
        "CVKit/": "https://cdn.jsdelivr.net/gh/coherentvolition/coherent-client-kit@v0.1.0/src/"
      }
    }
    </script>
  </head>
  <body>
    <div id="app"></div>
    <script type="module" src="/main.js"></script>
  </body>
</html>
```

### `main.js`

```js
import { Auth } from "CVKit";

Auth.configure({
  authApi: "https://auth.coherentvolition.ai",
  homePath: "/home",
});

Auth.init();
```

---

## Import styles

Both of these are supported:

### Named imports (recommended)

```js
import { Api, Auth, compileRouteMap, LandingRoute } from "CVKit";
```

### Namespace import

```js
import * as CVKit from "CVKit";

CVKit.Auth.configure({ authApi: "https://auth.example.com" });
CVKit.Api.get("https://api.example.com", "/api/health");
```

---

## Auth usage

## Configure once at startup

```js
import { Auth } from "CVKit";

Auth.configure({
  authApi: "https://auth.coherentvolition.ai",
  homePath: "/home", // where OAuth login completion lands
});

Auth.init();
```

`Auth.init()` will:

* restore cached JWT (if present) for optimistic UI state
* process OAuth callback params if present in the URL/hash

---

## Password login

```js
import { Auth } from "CVKit";

async function login(username, password) {
  try {
    const res = await Auth.loginWithPassword(username, password);
    console.log("Logged in:", res);
    // cookie refresh token is set by auth server (credentials: include)
    // UI state JWT is cached locally
  } catch (err) {
    console.error("Login failed:", err.message);
  }
}
```

---

## OAuth login (GitHub)

```js
import { Auth } from "CVKit";

// Redirects browser to auth server OAuth start endpoint
Auth.startGithubOAuthLogin();
```

Optional account-link flow:

```js
Auth.startGithubOAuthLink();
```

When the auth server redirects back to your app with `?oauth=...`, `Auth.init()` will detect it and complete login by calling the cookie-based refresh endpoint.

---

## Refresh JWT (cookie-based)

```js
import { Auth } from "CVKit";

try {
  await Auth.refreshJwt();
  console.log("JWT refreshed");
} catch (err) {
  console.error("Refresh failed:", err.message);
}
```

This sends `POST /api/token` to the configured auth server using `credentials: "include"`.

---

## Auth helpers

### Check permissions

```js
if (Auth.hasPermission("butterfly.admin")) {
  // show admin UI
}
```

### Get canonical user ID

```js
const userId = Auth.getUserId();
// e.g. "coherent::leo"
```

### Logout

```js
Auth.logout();
```

---

## API usage

`Api` is a thin wrapper around `fetch` / `m.request` with:

* safe URL joining
* JSON handling
* timeout support
* optional streaming NDJSON (`onprogress`)
* authed retry (`Api.authed.*`) that refreshes JWT on `403`

---

## Basic GET / POST

```js
import { Api } from "CVKit";

const SVC = "https://butterflies.coherentvolition.ai";

// GET /api/butterflies?status=AVAILABLE
const rows = await Api.get(SVC, "/api/butterflies", { status: "AVAILABLE" });

// POST JSON
const created = await Api.post(SVC, "/api/submissions", {
  butterfly_id: "bfly-123",
  butterfly_name: "Aurora",
  story: "A small story...",
});
```

---

## Authenticated requests (automatic refresh on 403)

```js
import { Api } from "CVKit";

const SVC = "https://butterflies.coherentvolition.ai";

// Adds Authorization: Bearer <jwt> if available.
// If the server returns 403, CVKit calls Auth.refreshJwt() and retries once.
const adminData = await Api.authed.get(SVC, "/api/admin/stats");
```

---

## Cookie-based cross-origin requests

For auth-domain requests (or any cross-origin endpoint that needs cookies), pass `credentials`.

```js
import { Api } from "CVKit";

const AUTH_API = "https://auth.coherentvolition.ai";

const profile = await Api.get(AUTH_API, "/api/profile", {}, {
  credentials: "include"
});
```

Valid values:

* `"include"` (send cookies cross-origin)
* `"same-origin"`
* `"omit"`

---

## Streaming (NDJSON) progress

If your endpoint streams NDJSON, pass `onprogress`.

```js
import { Api } from "CVKit";

await Api.post(
  "https://service.example.com",
  "/api/stream-task",
  { prompt: "hello" },
  {
    onprogress(obj) {
      console.log("chunk:", obj);
    }
  }
);
```

---

## Router usage (Mithril)

CVKit includes helpers for protected routes and route-tree compilation.

### Example route tree

```js
import m from "mithril"; // or rely on window.m
import { Auth, compileRouteMap, LandingRoute } from "CVKit";
import LoginComponent from "./login.js";

const Home = { view: () => m("div", "Home") };
const Admin = { view: () => m("div", "Admin") };
Admin.requires = "butterfly.admin";

const routeTree = [
  { path: "/", public: true, component: LandingRoute("/home") },
  { path: "/home", component: Home },
  { path: "/admin", component: Admin, requires: "butterfly.admin" },
  { path: "/profile", utility: true, component: { view: () => m("div", "Profile") } },
];

Auth.setRouteTree(routeTree);

m.route(document.getElementById("app"), "/", compileRouteMap(routeTree, {
  loginComponent: LoginComponent,
}));
```

### Protected route behavior

* Unauthenticated users see your provided `loginComponent`
* Authenticated users without permission see a default “Access denied” view
* Permission checks use `Auth.hasPermission(...)`

---

## OAuth helper exports

Most apps can just use `Auth.startGithubOAuthLogin()` and `Auth.init()`.

If you need lower-level control, CVKit also exports OAuth helpers (flat and namespaced):

```js
import {
  buildOAuthStartUrl,
  oauthQueryParams,
  stripOAuthParamsFromUrl,
  currentReturnUrl,
} from "CVKit";

// or:
import * as CVKit from "CVKit";
CVKit.oauth.buildOAuthStartUrl(...);
```

---

## Public API summary

`src/core.js` exports:

### Top-level

* `Api`
* `Auth`
* `decodeJwt`

### OAuth helpers

* `oauthQueryParams`
* `stripOAuthParamsFromUrl`
* `currentReturnUrl`
* `oauthStartPath`
* `buildOAuthStartUrl`
* `startOAuthFlow`
* `handleOAuthReturnIfPresent`

### Router helpers

* `ProtectedRouteFactory`
* `RedirectTo`
* `compileRouteMap`
* `LandingRoute`

### Namespaces

* `oauth`
* `router`

---

## Release model (Git tags + jsDelivr)

This repo is distributed via **GitHub tags** and served by jsDelivr.

Typical release flow:

1. Bump `package.json` version
2. Merge to `master`
3. GitHub Action tags:

   * `vX.Y.Z`
   * `latest` (mutable alias)
4. Consumers import from jsDelivr

Example pinned import:

```html
<script type="importmap">
{
  "imports": {
    "CVKit": "https://cdn.jsdelivr.net/gh/coherentvolition/coherent-client-kit@v0.1.0/src/core.js"
  }
}
</script>
```

---

## Notes

* This library is **browser-only**.
* It is intentionally **not** published to npm.
* It is designed for Coherent front-ends that already use CDN-loaded browser libraries (Mithril, FullCalendar, etc.).
