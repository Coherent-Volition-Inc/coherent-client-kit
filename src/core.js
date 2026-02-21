// src/core.js
//
// Single stable public entrypoint for browser ESM consumers.
// Intended usage (via import map):
//
//   import { Api, Auth } from "CVKit";
//   import * as CVKit from "CVKit";
//
// This file re-exports the library surface both as named exports and
// as grouped namespaces (`oauth`, `router`) for convenience.

import Api from './api.js';
import { Auth, decodeJwt } from './auth.js';

import {
  oauthQueryParams,
  stripOAuthParamsFromUrl,
  currentReturnUrl,
  oauthStartPath,
  buildOAuthStartUrl,
  startOAuthFlow,
  handleOAuthReturnIfPresent,
} from './oauth.js';

import { ProtectedRouteFactory } from './protected-route.js';
import { RedirectTo, compileRouteMap, LandingRoute } from './router.js';

// Grouped convenience namespaces (so CVKit.oauth.* / CVKit.router.* works)
const oauth = {
  oauthQueryParams,
  stripOAuthParamsFromUrl,
  currentReturnUrl,
  oauthStartPath,
  buildOAuthStartUrl,
  startOAuthFlow,
  handleOAuthReturnIfPresent,
};

const router = {
  ProtectedRouteFactory,
  RedirectTo,
  compileRouteMap,
  LandingRoute,
};

// Named exports (best ergonomics for: import { Api, Auth } from "CVKit")
export {
  Api,
  Auth,
  decodeJwt,

  // oauth helpers (flat)
  oauthQueryParams,
  stripOAuthParamsFromUrl,
  currentReturnUrl,
  oauthStartPath,
  buildOAuthStartUrl,
  startOAuthFlow,
  handleOAuthReturnIfPresent,

  // router helpers (flat)
  ProtectedRouteFactory,
  RedirectTo,
  compileRouteMap,
  LandingRoute,

  // grouped namespaces
  oauth,
  router,
};

// Optional default export for consumers who prefer `import CVKit from "CVKit"`
export default {
  Api,
  Auth,
  decodeJwt,
  oauth,
  router,
};
