import { describe, expect, test } from "bun:test";
import {
  ACCESS_TOKEN_KEY,
  createMemoryStorage,
  createTokenStorage,
  REFRESH_TOKEN_KEY,
  type StorageLike,
} from "@pub/api/storage";

describe("token storage", () => {
  test("round-trips a pair through the documented keys", () => {
    const backend = createMemoryStorage();
    const storage = createTokenStorage(backend);
    storage.write({ accessToken: "a.b.c", refreshToken: "opaque" });

    expect(backend.getItem(ACCESS_TOKEN_KEY)).toBe("a.b.c");
    expect(backend.getItem(REFRESH_TOKEN_KEY)).toBe("opaque");
    expect(storage.read()).toEqual({ accessToken: "a.b.c", refreshToken: "opaque" });
  });

  test("a half-written pair reads as no session, never as a partial one", () => {
    const backend = createMemoryStorage();
    backend.setItem(ACCESS_TOKEN_KEY, "a.b.c");
    // The refresh half is missing — e.g. another tab cleared it mid-flight.
    expect(createTokenStorage(backend).read()).toBeNull();

    const other = createMemoryStorage();
    other.setItem(REFRESH_TOKEN_KEY, "opaque");
    expect(createTokenStorage(other).read()).toBeNull();
  });

  test("clear removes both keys", () => {
    const backend = createMemoryStorage();
    const storage = createTokenStorage(backend);
    storage.write({ accessToken: "a", refreshToken: "b" });
    storage.clear();
    expect(backend.getItem(ACCESS_TOKEN_KEY)).toBeNull();
    expect(backend.getItem(REFRESH_TOKEN_KEY)).toBeNull();
    expect(storage.read()).toBeNull();
  });

  test("subscribers see writes and clears; unsubscribe stops them", () => {
    const storage = createTokenStorage(createMemoryStorage());
    const seen: (string | null)[] = [];
    const unsubscribe = storage.subscribe((pair) => seen.push(pair?.accessToken ?? null));

    storage.write({ accessToken: "one", refreshToken: "r" });
    storage.clear();
    unsubscribe();
    storage.write({ accessToken: "two", refreshToken: "r" });

    expect(seen).toEqual(["one", null]);
  });

  test("a backend that throws on every access degrades to no session", () => {
    const hostile: StorageLike = {
      getItem: () => {
        throw new Error("SecurityError: storage disabled");
      },
      setItem: () => {
        throw new Error("QuotaExceededError");
      },
      removeItem: () => {
        throw new Error("SecurityError: storage disabled");
      },
    };
    const storage = createTokenStorage(hostile);

    // None of these may throw: Safari private mode must not crash the island.
    expect(storage.read()).toBeNull();
    expect(() => storage.write({ accessToken: "a", refreshToken: "b" })).not.toThrow();
    expect(() => storage.clear()).not.toThrow();
    expect(storage.read()).toBeNull();
  });

  test("listeners still fire when the backend refuses the write", () => {
    const hostile: StorageLike = {
      getItem: () => null,
      setItem: () => {
        throw new Error("QuotaExceededError");
      },
      removeItem: () => undefined,
    };
    const storage = createTokenStorage(hostile);
    let notified = false;
    storage.subscribe(() => {
      notified = true;
    });
    storage.write({ accessToken: "a", refreshToken: "b" });
    // The UI must reflect the sign-in even when persistence failed.
    expect(notified).toBe(true);
  });
});
