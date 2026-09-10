// src/user-state.js
import { Auth } from "./auth.js";

const MISSING = Symbol("cvkit.user-state.missing");

export function createUserState({
  prefix = "cvkit:user-state:v1",
  subject = () => Auth.getUserId?.() || null,
} = {}) {
  function subjectId() {
    const value = typeof subject === "function" ? subject() : subject;
    return value == null || value === "" ? null : String(value);
  }

  function storageKey(layer, name) {
    const uid = subjectId();
    if (!uid || name == null || name === "") return null;
    return `${prefix}:${uid}:${layer}:${String(name)}`;
  }

  function read(storage, layer, name, fallback = MISSING) {
    const key = storageKey(layer, name);
    if (!key) return fallback;

    try {
      const raw = storage?.getItem(key);
      return raw == null ? fallback : JSON.parse(raw);
    } catch (_e) {
      return fallback;
    }
  }

  function write(storage, layer, name, value) {
    const key = storageKey(layer, name);
    if (!key) return false;

    try {
      if (value === undefined) storage?.removeItem(key);
      else storage?.setItem(key, JSON.stringify(value));
      return true;
    } catch (_e) {
      return false;
    }
  }

  function remove(storage, layer, name) {
    const key = storageKey(layer, name);
    if (!key) return false;

    try {
      storage?.removeItem(key);
      return true;
    } catch (_e) {
      return false;
    }
  }

  return {
    // explicit user choice > implicit remembered state > caller default
    get(name, fallback = null) {
      const explicit = read(window.localStorage, "explicit", name);
      if (explicit !== MISSING) return explicit;

      const implicit = read(window.localStorage, "implicit", name);
      return implicit !== MISSING ? implicit : fallback;
    },

    getExplicit(name, fallback = null) {
      const value = read(window.localStorage, "explicit", name);
      return value !== MISSING ? value : fallback;
    },

    getImplicit(name, fallback = null) {
      const value = read(window.localStorage, "implicit", name);
      return value !== MISSING ? value : fallback;
    },

    hasExplicit(name) {
      return read(window.localStorage, "explicit", name) !== MISSING;
    },

    hasImplicit(name) {
      return read(window.localStorage, "implicit", name) !== MISSING;
    },

    setExplicit(name, value) {
      return write(window.localStorage, "explicit", name, value);
    },

    setImplicit(name, value) {
      return write(window.localStorage, "implicit", name, value);
    },

    clearExplicit(name) {
      return remove(window.localStorage, "explicit", name);
    },

    clearImplicit(name) {
      return remove(window.localStorage, "implicit", name);
    },

    clear(name) {
      const a = this.clearExplicit(name);
      const b = this.clearImplicit(name);
      return a || b;
    },

    session: {
      get(name, fallback = null) {
        const value = read(window.sessionStorage, "session", name);
        return value !== MISSING ? value : fallback;
      },

      set(name, value) {
        return write(window.sessionStorage, "session", name, value);
      },

      clear(name) {
        return remove(window.sessionStorage, "session", name);
      },
    },
  };
}

export const UserState = createUserState();
export default UserState;
