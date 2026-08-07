/*
 * Token storage — the ONE module that knows where credentials live.
 *
 * Decision 03 puts the access JWT and the rotating refresh token in
 * `localStorage` (keys `pub_access` / `pub_refresh`), with the XSS exposure
 * compensated by S-11 (strict CSP, sanitized README HTML) and S-08 (rotation +
 * reuse detection + idle/absolute caps). Everything else in the app talks to
 * the `TokenStorage` interface, so swapping the backing store later (a
 * BFF cookie session, IndexedDB, an in-memory store for SSR) touches this file
 * only.
 */

export const ACCESS_TOKEN_KEY = "pub_access";
export const REFRESH_TOKEN_KEY = "pub_refresh";

export type TokenPair = {
  readonly accessToken: string;
  readonly refreshToken: string;
};

export type TokenStorage = {
  /** The stored pair, or `null` when either half is missing. */
  read(): TokenPair | null;
  write(pair: TokenPair): void;
  clear(): void;
  /** Notified on every write/clear (including cross-tab, where supported). */
  subscribe(listener: (pair: TokenPair | null) => void): () => void;
};

/** The slice of the Web Storage API this module needs — keeps doubles trivial. */
export type StorageLike = {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
};

function notifyAll(listeners: Set<(pair: TokenPair | null) => void>, pair: TokenPair | null): void {
  for (const listener of listeners) listener(pair);
}

/**
 * Storage backed by a Web Storage implementation (defaults to `localStorage`).
 *
 * Every access is wrapped: Safari private mode, disabled cookies, and SSR all
 * make `localStorage` throw on touch, and a storage failure must degrade to
 * "no session" rather than crash the island.
 */
export function createTokenStorage(backend?: StorageLike): TokenStorage {
  const listeners = new Set<(pair: TokenPair | null) => void>();
  const store = backend ?? resolveDefaultBackend();

  const read = (): TokenPair | null => {
    if (store === null) return null;
    try {
      const accessToken = store.getItem(ACCESS_TOKEN_KEY);
      const refreshToken = store.getItem(REFRESH_TOKEN_KEY);
      if (accessToken === null || refreshToken === null) return null;
      return { accessToken, refreshToken };
    } catch {
      return null;
    }
  };

  return {
    read,
    write(pair: TokenPair): void {
      try {
        store?.setItem(ACCESS_TOKEN_KEY, pair.accessToken);
        store?.setItem(REFRESH_TOKEN_KEY, pair.refreshToken);
      } catch {
        // Quota or a locked-down store: the pair stays in memory for this tab
        // only. Listeners still fire so the UI reflects the sign-in.
      }
      notifyAll(listeners, pair);
    },
    clear(): void {
      try {
        store?.removeItem(ACCESS_TOKEN_KEY);
        store?.removeItem(REFRESH_TOKEN_KEY);
      } catch {
        // Nothing to undo — a store that refuses removal never accepted a write.
      }
      notifyAll(listeners, null);
    },
    subscribe(listener): () => void {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
}

/** In-memory storage for tests and any non-browser context. */
export function createMemoryStorage(): StorageLike {
  const map = new Map<string, string>();
  return {
    getItem: (key) => map.get(key) ?? null,
    setItem: (key, value) => void map.set(key, value),
    removeItem: (key) => void map.delete(key),
  };
}

function resolveDefaultBackend(): StorageLike | null {
  try {
    return typeof localStorage === "undefined" ? null : localStorage;
  } catch {
    return null;
  }
}
