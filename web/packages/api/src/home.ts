import type { ApiClient } from "./client";
import type { HomeDto } from "./types";

/*
 * The landing dashboard (`GET /api/v1/home`).
 *
 * One request by design (server-side note on the route): instance identity,
 * counters, and both package rails arrive together so a cold visitor does not
 * pay four round trips before anything renders.
 *
 * Anonymous-reachable (decision 05). Everything in the payload is scoped to
 * what the caller may see, counters included — the same request returns a
 * bigger instance to a member than to a visitor, and that is correct.
 */

export type HomeApi = ReturnType<typeof createHomeApi>;

export function createHomeApi(client: ApiClient) {
  return {
    get(): Promise<HomeDto> {
      return client.request<HomeDto>("/home");
    },
  };
}
