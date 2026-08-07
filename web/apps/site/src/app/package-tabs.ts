/*
 * Package-page tab routing.
 *
 * The tab is a PATH SEGMENT, not component state: `/app/packages/http/versions`
 * is the versions tab. That makes every tab linkable, back-button-navigable,
 * and reloadable — which matters most for the one people paste into chat
 * ("look at the changelog") and for the deep link out of the versions list
 * into a single version's page.
 *
 * "readme" is the default and is NOT in the URL: `/packages/http` and
 * `/packages/http/readme` would otherwise be two URLs for one page.
 */

export const PACKAGE_TABS = [
  "readme",
  "changelog",
  "versions",
  "dependents",
  "installing",
  "manage",
] as const;

export type PackageTab = (typeof PACKAGE_TABS)[number];

export const DEFAULT_PACKAGE_TAB: PackageTab = "readme";

/**
 * Reads the tab out of a route parameter.
 *
 * An unknown segment falls back to the default rather than 404-ing: the
 * package exists, the reader typed something odd, and showing the package is
 * strictly more useful than showing "not found" for a name that resolves.
 */
export function readPackageTab(raw: string | undefined): PackageTab {
  if (raw === undefined || raw === "") return DEFAULT_PACKAGE_TAB;
  return (PACKAGE_TABS as readonly string[]).includes(raw)
    ? (raw as PackageTab)
    : DEFAULT_PACKAGE_TAB;
}

/** Canonical path for a package page on a given tab (default tab has no segment). */
export function packageTabPath(name: string, tab: PackageTab): string {
  const base = `/packages/${encodeURIComponent(name)}`;
  return tab === DEFAULT_PACKAGE_TAB ? base : `${base}/${tab}`;
}
