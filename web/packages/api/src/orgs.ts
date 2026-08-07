import { type ApiClient, jsonBody } from "./client";
import type {
  InvitationCreatedDto,
  InvitationDto,
  ListDto,
  MemberAddBody,
  MemberDto,
  MembershipChangedDto,
  OrgCreateBody,
  OrgDeleteBody,
  OrgDeletedDto,
  OrgDto,
  OrgMembershipDto,
  OrgProfileDto,
  OrgRole,
  OrgUpdateBody,
} from "./types";

/*
 * Organizations (`/api/v1/orgs`) — profile, packages, members, invitations,
 * and the danger zone.
 *
 * Two things the caller must know (decision 19's addendum):
 *
 *   - **The slug is immutable.** It *is* the virtual registry base
 *     (`/o/{slug}/pub`), so `update` carries name, description, and upstream
 *     policy and deliberately has no slug field.
 *   - **Org management answers 403 where package management answers 404.**
 *     Org slugs are not secret, so an insufficient role on a real org tells a
 *     Read member what they are missing; a package the caller cannot read
 *     answers the 404 an unknown name gets, because checking the role first
 *     would make the route an existence oracle.
 */

export type OrgsApi = ReturnType<typeof createOrgsApi>;

export function createOrgsApi(client: ApiClient) {
  const base = (slug: string): string => `/orgs/${encodeURIComponent(slug)}`;

  return {
    /** The caller's orgs with their role name in each. */
    list(): Promise<ListDto<OrgMembershipDto>> {
      return client.request<ListDto<OrgMembershipDto>>("/orgs");
    },

    /** The slug is the virtual registry base and is immutable afterwards (decision 19). */
    create(body: OrgCreateBody): Promise<OrgDto> {
      return client.request<OrgDto>("/orgs", jsonBody("POST", body));
    },

    /**
     * Public org profile plus the packages this caller may see.
     *
     * Anonymous-reachable: slugs are not secret (S-04.b), and the package list
     * runs through the same view search does, so a non-member sees exactly the
     * org's public, listed packages.
     */
    profile(
      slug: string,
      options: { readonly cursor?: string; readonly limit?: number } = {},
    ): Promise<OrgProfileDto> {
      const search = new URLSearchParams();
      if (options.cursor !== undefined && options.cursor !== "")
        search.set("cursor", options.cursor);
      if (options.limit !== undefined) search.set("limit", String(options.limit));
      const encoded = search.toString();
      return client.request<OrgProfileDto>(`${base(slug)}${encoded === "" ? "" : `?${encoded}`}`);
    },

    /** Admin+. No slug field — renaming the registry base is not a thing (decision 19). */
    update(slug: string, body: OrgUpdateBody): Promise<OrgDto> {
      return client.request<OrgDto>(base(slug), jsonBody("PATCH", body));
    },

    /** Owner + step-up. 409 while the org owns packages unless `force` archives it instead. */
    remove(slug: string, body: OrgDeleteBody): Promise<OrgDeletedDto> {
      return client.request<OrgDeletedDto>(base(slug), jsonBody("DELETE", body));
    },

    members(slug: string): Promise<ListDto<MemberDto>> {
      return client.request<ListDto<MemberDto>>(`${base(slug)}/members`);
    },

    /** Admin+; grants at Write or above are step-up-gated (S-06). Unknown emails are 404. */
    addMember(slug: string, body: MemberAddBody): Promise<MemberDto> {
      return client.request<MemberDto>(`${base(slug)}/members`, jsonBody("POST", body));
    },

    /** S-09: a demotion revokes the affected user's sessions; the count comes back. */
    setMemberRole(slug: string, userId: string, role: OrgRole): Promise<MembershipChangedDto> {
      return client.request<MembershipChangedDto>(
        `${base(slug)}/members/${encodeURIComponent(userId)}`,
        jsonBody("PATCH", { role }),
      );
    },

    removeMember(slug: string, userId: string): Promise<MembershipChangedDto> {
      return client.request<MembershipChangedDto>(
        `${base(slug)}/members/${encodeURIComponent(userId)}`,
        { method: "DELETE" },
      );
    },

    invitations(slug: string): Promise<ListDto<InvitationDto>> {
      return client.request<ListDto<InvitationDto>>(`${base(slug)}/invitations`);
    },

    /** The token comes back once so an instance without SMTP can still deliver it. */
    invite(slug: string, email: string, role: OrgRole): Promise<InvitationCreatedDto> {
      return client.request<InvitationCreatedDto>(
        `${base(slug)}/invitations`,
        jsonBody("POST", { email, role }),
      );
    },

    revokeInvitation(slug: string, id: string): Promise<undefined> {
      return client.request<undefined>(`${base(slug)}/invitations/${encodeURIComponent(id)}`, {
        method: "DELETE",
      });
    },

    /** Redeems an invitation token; answers the org the caller just joined. */
    acceptInvitation(token: string): Promise<OrgDto> {
      return client.request<OrgDto>("/invitations/accept", jsonBody("POST", { token }));
    },
  };
}
