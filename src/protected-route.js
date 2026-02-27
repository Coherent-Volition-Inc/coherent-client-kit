// src/protected-route.js
import { Auth } from './auth.js';
const m = window.m;

const DefaultDenied = {
  view: () => m('div.p-4.text-red-600', 'Access denied')
};

export function ProtectedRouteFactory(LoginComponent, DeniedComponent = DefaultDenied) {
  return {
    oninit(vnode) {
      // If Auth.init() has already resolved (normal page loads where a JWT
      // was cached in localStorage) this is a no-op: the promise is already
      // settled and the microtask queue drains before Mithril's first paint.
      //
      // If we're in the OAuth return window (no cached JWT yet, token exchange
      // in flight) we hold off rendering the guard until the exchange either
      // succeeds (Auth.isAuthenticated becomes true) or fails, then redraw.
      // Either way _initPromise never rejects — auth.js catches internally.
      vnode.state._authReady = false;
      const p = Auth._initPromise ?? Promise.resolve();
      p.then(() => {
        vnode.state._authReady = true;
        m.redraw();
      });
    },

    view(vnode) {
      if (!vnode.state._authReady) return null;

      if (!Auth.isAuthenticated) return m(LoginComponent);

      const comp = vnode.attrs.component;
      const requiredAbility = vnode.attrs.requires ?? comp?.requires;
      const requiredGroup   = vnode.attrs.requiredGroup ?? comp?.requiredGroup;

      if (requiredAbility && !Auth.hasPermission(requiredAbility, requiredGroup)) {
        return m(DeniedComponent);
      }
      return m(comp, vnode.attrs);
    }
  };
}
