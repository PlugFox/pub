import { type ApiClient, jsonBody } from "./client";
import type {
  HardDeleteBody,
  HardDeletedDto,
  ListDto,
  PackageDetailDto,
  PackageOptionsBody,
  PackageOptionsDto,
  PackageSummaryDto,
  PackageTransferBody,
  PackageTransferredDto,
  SearchResultsDto,
  SearchSort,
  VersionDetailDto,
  VersionRetractedDto,
  VersionSummaryDto,
} from "./types";

/*
 * Packages: the public read model (decision 11) and the management mutations
 * (decisions 06/19).
 *
 * Two properties of this surface are worth stating where the calls are made:
 *
 *   - Every read is visibility-filtered server-side and answers **404** for a
 *     package the caller may not read — the same answer an unknown name gets
 *     (decision 05). A screen must therefore treat 404 as "not found", never
 *     as "forbidden", and must not offer a "request access" path it cannot
 *     know is meaningful.
 *   - Search cursors are **ordering-bound**: the token carries the sort it was
 *     minted under and presenting it under a different one is a 400, not a
 *     reshuffled page. The URL state in the search screen resets the cursor
 *     whenever the sort changes for exactly this reason.
 */

export type SearchOptions = {
  /** Free text plus filter tags (`org:` `topic:` `is:` `dependency:` `format:` `sort:`). */
  readonly q?: string;
  readonly sort?: SearchSort;
  /** Only valid for the same `sort` that produced it. */
  readonly cursor?: string;
  /** 1..=100; the server clamps and defaults to 20. */
  readonly limit?: number;
};

export type PageOptions = { readonly cursor?: string; readonly limit?: number };

/** Builds a query string from defined values only — an empty bag yields "". */
function queryString(params: Record<string, string | number | boolean | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === "") continue;
    search.set(key, String(value));
  }
  const encoded = search.toString();
  return encoded === "" ? "" : `?${encoded}`;
}

export type PackagesApi = ReturnType<typeof createPackagesApi>;

export function createPackagesApi(client: ApiClient) {
  const path = (name: string): string => `/packages/${encodeURIComponent(name)}`;
  const versionPath = (name: string, version: string): string =>
    `${path(name)}/versions/${encodeURIComponent(version)}`;

  return {
    /** Search + browse. `unknown_filters` echoes the tokens the parser ignored. */
    search(options: SearchOptions = {}): Promise<SearchResultsDto> {
      return client.request<SearchResultsDto>(`/packages${queryString({ ...options })}`);
    },

    /** Package detail: metadata, newest live version, links, flags, README HTML. */
    detail(name: string): Promise<PackageDetailDto> {
      return client.request<PackageDetailDto>(path(name));
    },

    /** Versions, newest first. Retracted ones are included and flagged. */
    versions(name: string, options: PageOptions = {}): Promise<ListDto<VersionSummaryDto>> {
      return client.request<ListDto<VersionSummaryDto>>(
        `${path(name)}/versions${queryString({ ...options })}`,
      );
    },

    /** One version in full: README + CHANGELOG HTML, pubspec, archive URL. */
    version(name: string, version: string): Promise<VersionDetailDto> {
      return client.request<VersionDetailDto>(versionPath(name, version));
    },

    /** Reverse dependencies, ordered by name (the `dependency:` filter, pinned). */
    dependents(name: string, options: PageOptions = {}): Promise<ListDto<PackageSummaryDto>> {
      return client.request<ListDto<PackageSummaryDto>>(
        `${path(name)}/dependents${queryString({ ...options })}`,
      );
    },

    // --- management (Write+ in the owning org; several are step-up-gated) ---

    /** Visibility / discontinued / unlisted / replaced-by. Absent fields keep their value. */
    setOptions(name: string, body: PackageOptionsBody): Promise<PackageOptionsDto> {
      return client.request<PackageOptionsDto>(`${path(name)}/options`, jsonBody("PATCH", body));
    },

    /** S-06: step-up-gated. Retraction excludes a version from new resolutions. */
    retract(name: string, version: string): Promise<VersionRetractedDto> {
      return client.request<VersionRetractedDto>(`${versionPath(name, version)}/retract`, {
        method: "POST",
      });
    },

    /** S-06: step-up-gated. 409 past the restore window (decision 06). */
    unretract(name: string, version: string): Promise<VersionRetractedDto> {
      return client.request<VersionRetractedDto>(`${versionPath(name, version)}/unretract`, {
        method: "POST",
      });
    },

    /** Admin+ and step-up-gated; `confirm` must be `"{name}@{version}"` (decision 06). */
    hardDelete(name: string, version: string, body: HardDeleteBody): Promise<HardDeletedDto> {
      return client.request<HardDeletedDto>(versionPath(name, version), jsonBody("DELETE", body));
    },

    /** Owner of both orgs, step-up-gated; `confirm` must be the package name. */
    transfer(name: string, body: PackageTransferBody): Promise<PackageTransferredDto> {
      return client.request<PackageTransferredDto>(
        `${path(name)}/transfer`,
        jsonBody("POST", body),
      );
    },
  };
}
