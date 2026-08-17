import type { TokenPair, TokenStorage } from "@pub/api/storage";
import type { LoginDto, MeDto, UserDto } from "@pub/api/types";
import { createSignal } from "solid-js";

/*
 * Session state — module-level signals, no context provider.
 *
 * Holds three things the whole app reads: who is signed in, whether we hold a
 * usable credential, and how long the session still counts as step-up-fresh.
 *
 * PROFILE CACHE: the committed API has no `GET /me`, so the user object is
 * only ever seen inside a `LoginDto`. To survive a reload we snapshot it under
 * `pub_user` — a *cache*, never a credential: it is display data, every
 * authorization decision is the server's, and a tampered copy buys nothing
 * beyond a wrong name in the header. Replace this with a real profile fetch as
 * soon as the app API exposes one.
 */

const USER_CACHE_KEY = "pub_user";

/**
 * Assumed step-up window, mirroring the server default `auth.step_up_minutes`.
 *
 * This is a DISPLAY HINT only — the client never decides that an action is
 * allowed. The server re-evaluates freshness on every gated call and answers
 * `step_up_required`; this value only lets the UI avoid promising freshness it
 * has no reason to believe in.
 */
const ASSUMED_STEP_UP_WINDOW_MS = 15 * 60 * 1000;

const [user, setUser] = createSignal<UserDto | null>(readCachedUser());
const [authenticated, setAuthenticated] = createSignal(false);
const [stepUpUntil, setStepUpUntil] = createSignal<number | null>(null);
const [sessionId, setSessionId] = createSignal<string | null>(null);

/** The signed-in user, or `null`. Display data only. */
export const currentUser = user;
/** Whether a token pair is present. Says nothing about whether the server still honours it. */
export const isAuthenticated = authenticated;
/** The current session id (`sid`), when a login reported one. */
export const currentSessionId = sessionId;

/** Whether the session is probably still step-up-fresh (a hint — see above). */
export function isStepUpFresh(now = Date.now()): boolean {
  const until = stepUpUntil();
  return until !== null && until > now;
}

/** Records a successful `POST /auth/step-up`. */
export function markStepUpFresh(validUntil: string | number): void {
  const parsed = typeof validUntil === "number" ? validUntil : Date.parse(validUntil);
  setStepUpUntil(Number.isNaN(parsed) ? Date.now() + ASSUMED_STEP_UP_WINDOW_MS : parsed);
}

/**
 * Adopts a completed login: stores the pair, caches the profile, and starts
 * the assumed step-up window (a login just ran the strongest factor chain the
 * account has — S-06.a arm (a)).
 */
export function adoptLogin(login: LoginDto, pair: TokenPair, storage: TokenStorage): void {
  storage.write(pair);
  setAuthenticated(true);
  setSessionId(login.session_id ?? null);
  setStepUpUntil(Date.now() + ASSUMED_STEP_UP_WINDOW_MS);
  if (login.user !== undefined) {
    setUser(login.user);
    writeCachedUser(login.user);
  }
}

/**
 * Adopts a fresh profile read (`GET /me`, decision 39) into the display cache.
 *
 * The cache exists so a reload shows a name before the first request answers;
 * this keeps it honest after a rename or an address change. Only the fields the
 * cache carries are copied — `totp_enabled` and `is_instance_admin` are read
 * per screen from the server, never cached, because a stale copy of either is a
 * UI that promises something the API will refuse.
 */
export function adoptProfile(me: MeDto): void {
  const profile: UserDto = {
    id: me.id,
    email: me.email,
    email_verified: me.email_verified,
    display_name: me.display_name,
    created_at: me.created_at,
  };
  setUser(profile);
  writeCachedUser(profile);
}

/** Boot-time sync: reflect whatever the storage already holds. */
export function hydrateSession(storage: TokenStorage): void {
  setAuthenticated(storage.read() !== null);
  setUser(readCachedUser());
}

/** Drops every trace of the session locally. Never talks to the server. */
export function clearSession(storage: TokenStorage): void {
  storage.clear();
  setAuthenticated(false);
  setUser(null);
  setSessionId(null);
  setStepUpUntil(null);
  writeCachedUser(null);
}

function readCachedUser(): UserDto | null {
  try {
    const raw = localStorage.getItem(USER_CACHE_KEY);
    if (raw === null) return null;
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null) return null;
    const candidate = parsed as UserDto;
    return typeof candidate.id === "string" ? candidate : null;
  } catch {
    return null;
  }
}

function writeCachedUser(value: UserDto | null): void {
  try {
    if (value === null) localStorage.removeItem(USER_CACHE_KEY);
    else localStorage.setItem(USER_CACHE_KEY, JSON.stringify(value));
  } catch {
    // No storage: the profile simply does not survive a reload.
  }
}
