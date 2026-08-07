import type { HomeDto, InstanceDto } from "@pub/api/types";
import { query } from "@solidjs/router";
import { createSignal } from "solid-js";
import { api } from "./api";

/*
 * Instance identity (decision 17 white-label).
 *
 * `GET /api/v1/home` carries the branding an administrator set at runtime:
 * name, tagline, logo, accent colour. The header, the document title, and the
 * landing hero all need it, and none of them owns the home request — so the
 * request lives HERE, as one cached router query, and publishes what it loaded
 * to the signals below.
 *
 * It used to live on the landing screen, which meant a rebranded instance
 * showed its own name only to readers who happened to enter through `/app`:
 * anyone deep-linking to `/app/search` or a package page got the product
 * default in the header for the rest of the session. Branding is a property of
 * the instance, not of one route, so the shell primes this query on mount and
 * the landing screen reuses the same cached payload for its counters and rails
 * — one request either way.
 *
 * THE FALLBACK IS THE PRODUCT DEFAULT, NOT A GUESS. Decision 17 fixes "Pub" as
 * the default name, so an instance that never rebranded and an instance whose
 * home request has not landed yet render the same word. That is why the header
 * does not show a skeleton for the wordmark: there is nothing to wait for.
 *
 * The accent colour is deliberately NOT applied to the theme. Overriding
 * `--pub-accent` from a server-supplied string would take the contrast pair
 * out of the gate that `bun run check` enforces (web/DESIGN.md §2) and could
 * produce unreadable text on `on-accent`. It is rendered as a swatch on the
 * admin settings form — visible, editable, and not load-bearing — until the
 * palette can be derived and re-checked.
 */

export const DEFAULT_INSTANCE_NAME = "Pub";

/** Router-cache key of the shared `GET /api/v1/home` payload. */
export const HOME_KEY = "home";

const [instance, setInstance] = createSignal<InstanceDto | null>(null);

/**
 * The landing payload: instance identity, caller-scoped counters, both rails.
 *
 * Adopting the identity is a side effect of *loading*, not of rendering, so it
 * happens here rather than in an effect on whichever screen asked — every
 * caller gets the branding published exactly once per fetch.
 */
export const homeQuery = query(async (): Promise<HomeDto> => {
  const home = await api.home.get();
  adoptInstance(home.instance);
  return home;
}, HOME_KEY);

/**
 * Fires the home request without suspending the caller.
 *
 * The shell needs the branding but must not block the app chrome on it: the
 * fallback IS the product default, so there is nothing to wait for. A failure
 * is deliberately swallowed — the header keeps saying "Pub", and the screen
 * that actually renders the payload reports the error through its own
 * boundary.
 */
export function primeInstance(): void {
  void homeQuery().catch(() => {});
}

/** The instance identity, or `null` before the first home request lands. */
export const currentInstance = instance;

/** The wordmark: the configured name, or the product default. */
export function instanceName(): string {
  const name = instance()?.name.trim();
  return name === undefined || name === "" ? DEFAULT_INSTANCE_NAME : name;
}

/** The instance's public base URL — what a user puts in `dart pub token add`. */
export function instancePublicUrl(): string {
  const url = instance()?.public_url;
  if (url !== undefined && url !== "") return url.replace(/\/+$/, "");
  // Before the payload arrives (and in a test without a DOM) the current
  // origin is the honest answer: the app is served from the instance.
  return typeof window === "undefined" ? "" : window.location.origin;
}

export function adoptInstance(next: InstanceDto): void {
  setInstance(next);
}
