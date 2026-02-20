// src/router.js
import { ProtectedRouteFactory } from './protected-route.js';
import { Auth } from './auth.js';

const m = window.m;

export function RedirectTo(path) {
  return {
    oncreate: () => m.route.set(path),
    view: () => null
  };
}

function joinPath(parent, child) {
  const p = String(parent || '').replace(/\/+$/, '');
  const c = String(child || '').replace(/^\/+/, '');
  if (!p) return '/' + c;
  if (!c) return p || '/';
  return p + '/' + c;
}

function normalizeNode(node, parentMeta = {}, parentPath = '') {
  const rawPath = node.path || '';
  const absPath = rawPath.startsWith('/') ? rawPath : joinPath(parentPath, rawPath);

  // child inherits parent protection + requires unless overridden
  const meta = {
    public: node.public ?? parentMeta.public ?? false,
    requires: node.requires ?? parentMeta.requires ?? null,
    requiredGroup: node.requiredGroup ?? parentMeta.requiredGroup ?? null,
    utility: node.utility ?? false,
  };

  return { ...node, path: absPath, ...meta };
}

function wrapIfProtected(route, LoginComponent) {
  if (route.public) return route.component;

  // redirectTo is allowed instead of component
  const comp = route.component || (route.redirectTo ? RedirectTo(route.redirectTo) : null);
  if (!comp) throw new Error(`Route ${route.path} missing component or redirectTo`);

  // If requires is defined on route, pass it through attrs.
  const ProtectedRoute = ProtectedRouteFactory(LoginComponent);

  return {
    view(vnode) {
      return m(ProtectedRoute, {
        component: comp,
        requires: route.requires,
        requiredGroup: route.requiredGroup,
        ...vnode.attrs
      });
    }
  };
}

/**
 * Compile a tree into a Mithril route map.
 *
 * Options:
 *  - loginComponent: required (what to show when not authed)
 */
export function compileRouteMap(routeTree, { loginComponent } = {}) {
  if (!loginComponent) throw new Error("compileRouteMap: loginComponent is required");

  const map = {};

  function walk(nodes, parentMeta = {}, parentPath = '') {
    for (const n of (nodes || [])) {
      const r = normalizeNode(n, parentMeta, parentPath);

      // If node has component or redirectTo, it becomes a routable leaf
      const isLeaf = !!r.component || !!r.redirectTo;
      if (isLeaf) {
        map[r.path] = wrapIfProtected(r, loginComponent);
      }

      if (r.children?.length) walk(r.children, r, r.path);
    }
  }

  walk(routeTree, {}, '');
  return map;
}

/**
 * Smart landing component:
 * - if authed: go to preferred landing route
 * - else: show login
 */
export function LandingRoute(homePath = '/home') {
  return {
    oninit() {
      if (Auth.isAuthenticated) {
        const dest = Auth.getPreferredLandingRoute(homePath);
        if (dest && dest !== '/') m.route.set(dest);
      }
    },
    view: () => null
  };
}
