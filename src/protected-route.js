// src/protected-route.js
import { Auth } from './auth.js';
const m = window.m;

const DefaultDenied = {
  view: () => m('div.p-4.text-red-600', 'Access denied')
};

export function ProtectedRouteFactory(LoginComponent, DeniedComponent = DefaultDenied) {
  return {
    view(vnode) {
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
