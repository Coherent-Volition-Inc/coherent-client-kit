// src/protected-route.js
import { Auth } from './auth.js';
const m = window.m;

const DefaultDenied = {
  view: () => m('div.p-4.text-red-600', 'Access denied')
};

export function ProtectedRouteFactory(LoginComponent, DeniedComponent = DefaultDenied) {
  return {
    oninit(vnode) {
      vnode.state._authReady = false;
      vnode.state._permissionRefreshStarted = false;
      vnode.state._permissionRefreshDone = false;

      const p = Auth._initPromise ?? Promise.resolve();

      if (Auth._initDone) {
        vnode.state._authReady = true;
      } else {
        p.then(() => {
          vnode.state._authReady = true;
          m.redraw();
        });
      }
    },

    _refreshPermissions(vnode) {
      if (
        vnode.state._permissionRefreshStarted ||
        vnode.state._permissionRefreshDone
      ) return;

      vnode.state._permissionRefreshStarted = true;

      Auth.refreshJwt()
        .catch(() => {
          // refreshJwt() already logs out on refresh failure.
        })
        .finally(() => {
          vnode.state._permissionRefreshStarted = false;
          vnode.state._permissionRefreshDone = true;
          m.redraw();
        });
    },

    view(vnode) {
      if (!vnode.state._authReady) return null;

      if (!Auth.isAuthenticated) return m(LoginComponent);

      const comp = vnode.attrs.component;
      const requiredAbility = vnode.attrs.requires ?? comp?.requires;
      const requiredGroup = vnode.attrs.requiredGroup ?? comp?.requiredGroup;

      if (requiredAbility && !Auth.hasPermission(requiredAbility, requiredGroup)) {
        if (!vnode.state._permissionRefreshDone) {
          this._refreshPermissions(vnode);

          return m(
            '.min-h-screen.flex.items-center.justify-center.text-gray-500',
            'Checking access…'
          );
        }

        return m(DeniedComponent);
      }

      return m(comp, vnode.attrs);
    }
  };
}
