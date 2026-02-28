// src/protected-route.js
import { Auth } from './auth.js';
const m = window.m;

const DefaultDenied = {
  view: () => m('div.p-4.text-red-600', 'Access denied')
};

export function ProtectedRouteFactory(LoginComponent, DeniedComponent = DefaultDenied) {
  return {
    oninit(vnode) {
      const p = Auth._initPromise ?? Promise.resolve();

      // If _initPromise is already settled, checking a flag avoids the
      // microtask gap that can cause a missed render in history-API routing.
      if (Auth._initDone) {
        vnode.state._authReady = true;
      } else {
        vnode.state._authReady = false;
        p.then(() => {
          vnode.state._authReady = true;
          m.redraw();
        });
      }
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
