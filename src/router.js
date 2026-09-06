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

function wrapIfProtected(route, LoginComponent, DeniedComponent) {
  if (route.public) return route.component;

  const comp = route.component || (route.redirectTo ? RedirectTo(route.redirectTo) : null);
  if (!comp) throw new Error(`Route ${route.path} missing component or redirectTo`);

  const ProtectedRoute = ProtectedRouteFactory(LoginComponent, DeniedComponent);

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

export function compileRouteMap(routeTree, {
  loginComponent,
  deniedComponent
} = {}) {
  if (!loginComponent) throw new Error("compileRouteMap: loginComponent is required");

  const map = {};

  function walk(nodes, parentMeta = {}, parentPath = '') {
    for (const n of (nodes || [])) {
      const r = normalizeNode(n, parentMeta, parentPath);

      const isLeaf = !!r.component || !!r.redirectTo;
      if (isLeaf) {
        map[r.path] = wrapIfProtected(r, loginComponent, deniedComponent);
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
 *
 * Awaits Auth._initPromise so that an OAuth return on the root path
 * is handled before the landing decision is made.
 */
export function LandingRoute(homePath) {
  const hp = String(homePath || '').trim();
  if (!hp) {
    throw new Error("LandingRoute(homePath): homePath is required");
  }

  return {
    oninit(vnode) {
      vnode.state._authReady = false;
      const p = Auth._initPromise ?? Promise.resolve();

      p.then(() => {
        vnode.state._authReady = true;

        if (Auth.isAuthenticated) {
          const dest = Auth.getPreferredLandingRoute(hp);
          if (dest && dest !== '/' && m.route.get() !== dest) {
            m.route.set(dest);
            return;
          }
        }

        m.redraw();
      });
    },

    view() {
      return null;
    }
  };
}
