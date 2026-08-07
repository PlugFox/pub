import { type ApiClient, jsonBody } from "./client";
import type { ListDto, OrgCreateBody, OrgDto, OrgMembershipDto } from "./types";

/*
 * Organizations (`/api/v1/orgs`).
 *
 * Only the two committed endpoints are wired: the listing (which carries the
 * caller's role per org, decision 19) and creation. Members, invitations,
 * settings, and the audit view arrive with the management surface — the org
 * detail screen is an explicit placeholder until then.
 */

export type OrgsApi = ReturnType<typeof createOrgsApi>;

export function createOrgsApi(client: ApiClient) {
  return {
    /** The caller's orgs with their role name in each. */
    list(): Promise<ListDto<OrgMembershipDto>> {
      return client.request<ListDto<OrgMembershipDto>>("/orgs");
    },

    /** The slug is the virtual registry base and is immutable afterwards (decision 19). */
    create(body: OrgCreateBody): Promise<OrgDto> {
      return client.request<OrgDto>("/orgs", jsonBody("POST", body));
    },
  };
}
