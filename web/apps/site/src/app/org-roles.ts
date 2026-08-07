import type { OrgRole } from "@pub/api/types";
import { ORG_ROLES, roleRank } from "@pub/api/types";

/*
 * The UI half of decision 19's role-grant ceiling (D39) and its warning UX.
 *
 * The server rule these mirror: a non-Owner actor manages only role levels
 * STRICTLY below their own — both the level being granted and the level the
 * target currently holds — while an Owner is exempt entirely. Everything here
 * is a DISPLAY decision on top of that rule, never a substitute for it: the
 * org service re-checks every mutation, so a wrong answer from these helpers
 * costs a hidden control or a refused request, not an escalation. That is also
 * why an unknown or absent role name ranks 0 (see `roleRank`): a caller the
 * ladder does not recognize is offered the most restrictive view.
 */

/** Rank of `admin` — the level at which decision 19's warning UX starts to bite. */
const ADMIN_RANK = roleRank("admin");

/** Rank of `owner` — the ceiling exemption is by rank, not by name. */
const OWNER_RANK = roleRank("owner");

/**
 * Role levels the caller may grant: every role for an Owner, roles strictly
 * below their own for anybody else. An unknown or absent own role yields an
 * empty list — the most restrictive answer.
 */
export function assignableRoles(ownRole: string | null | undefined): readonly OrgRole[] {
  const own = roleRank(ownRole);
  if (own >= OWNER_RANK) return ORG_ROLES;
  return ORG_ROLES.filter((role) => roleRank(role) < own);
}

/**
 * Whether the caller may manage (re-role, remove) a member currently holding
 * `targetRole`: an Owner manages everybody including other Owners; a non-Owner
 * only members strictly below their own level. Mirrors the server-side check
 * in the org service so the UI hides what a request would 403 on.
 */
export function canManageMember(
  ownRole: string | null | undefined,
  targetRole: string | null | undefined,
): boolean {
  const own = roleRank(ownRole);
  if (own >= OWNER_RANK) return true;
  return roleRank(targetRole) < own;
}

/** Whether a role sits at Admin level or above — the tier the warning UX guards. */
export function isPrivilegedRole(role: string | null | undefined): boolean {
  return roleRank(role) >= ADMIN_RANK;
}

/**
 * Whether changing a member from `from` to `to` deserves a confirmation
 * dialog: granting Admin or Owner, or demoting a member who holds either.
 * Read↔write traffic passes silently, exactly as before D39.
 */
export function roleChangeNeedsWarning(
  from: string | null | undefined,
  to: string | null | undefined,
): boolean {
  return isPrivilegedRole(to) || (isPrivilegedRole(from) && roleRank(to) < roleRank(from));
}

/**
 * Whether the pending change is a demotion of an Admin/Owner holder — picks
 * the demotion copy over the grant copy when both would apply (owner → admin
 * is first of all the loss of an Owner).
 */
export function isPrivilegedDemotion(
  from: string | null | undefined,
  to: string | null | undefined,
): boolean {
  return isPrivilegedRole(from) && roleRank(to) < roleRank(from);
}

/** Whether removing a member holding `role` deserves the warning dialog. */
export function removalNeedsWarning(role: string | null | undefined): boolean {
  return isPrivilegedRole(role);
}

/** Whether inviting somebody at `role` deserves the warning dialog. */
export function inviteNeedsWarning(role: string | null | undefined): boolean {
  return isPrivilegedRole(role);
}
