import { describe, expect, test } from "bun:test";
import { roleRank } from "@pub/api/types";
import {
  assignableRoles,
  canManageMember,
  inviteNeedsWarning,
  isPrivilegedDemotion,
  isPrivilegedRole,
  removalNeedsWarning,
  roleChangeNeedsWarning,
} from "../src/app/org-roles";

/*
 * The role-grant ceiling and the Admin/Owner warning UX (decision 19's D39
 * addendum). The server's org service is the authority; these helpers only
 * decide what the screen OFFERS and what it WARNS about, so the tests are
 * written against the decided rule — a non-Owner manages strictly below their
 * own level, Owners are exempt, and every Admin/Owner transition confirms —
 * with unknown role names pinned to the most restrictive reading (rank 0).
 */

describe("roleRank", () => {
  test("mirrors decision 19's ladder", () => {
    expect(roleRank("read")).toBe(50);
    expect(roleRank("write")).toBe(100);
    expect(roleRank("admin")).toBe(200);
    expect(roleRank("owner")).toBe(250);
  });

  test("an unknown or absent role ranks 0 — never an escalation", () => {
    expect(roleRank("maintainer")).toBe(0);
    expect(roleRank("")).toBe(0);
    expect(roleRank(null)).toBe(0);
    expect(roleRank(undefined)).toBe(0);
  });
});

describe("assignableRoles", () => {
  test("an owner offers every role, including admin and owner", () => {
    expect(assignableRoles("owner")).toEqual(["read", "write", "admin", "owner"]);
  });

  test("an admin offers only read and write — never their own level or above", () => {
    expect(assignableRoles("admin")).toEqual(["read", "write"]);
  });

  test("a write member could only grant read; a read member nothing", () => {
    // Below Admin the screen is a 403 anyway, but the helper must not invent
    // authority the gate happens to be the only thing withholding.
    expect(assignableRoles("write")).toEqual(["read"]);
    expect(assignableRoles("read")).toEqual([]);
  });

  test("an unknown or absent own role offers nothing — the most restrictive view", () => {
    expect(assignableRoles("superuser")).toEqual([]);
    expect(assignableRoles(null)).toEqual([]);
    expect(assignableRoles(undefined)).toEqual([]);
  });
});

describe("canManageMember", () => {
  test("an owner manages every level, other owners included (the exemption)", () => {
    for (const target of ["read", "write", "admin", "owner"]) {
      expect(canManageMember("owner", target)).toBe(true);
    }
  });

  test("an admin manages strictly below: read and write yes, admin and owner no", () => {
    expect(canManageMember("admin", "read")).toBe(true);
    expect(canManageMember("admin", "write")).toBe(true);
    expect(canManageMember("admin", "admin")).toBe(false);
    expect(canManageMember("admin", "owner")).toBe(false);
  });

  test("an admin cannot manage their own row — same level is above the ceiling", () => {
    // The self row is just a member at the caller's level; the strict `<`
    // makes self-demotion an Owner-only move without a special case.
    expect(canManageMember("admin", "admin")).toBe(false);
    expect(canManageMember("owner", "owner")).toBe(true);
  });

  test("an unknown or absent OWN role manages nobody", () => {
    expect(canManageMember(undefined, "read")).toBe(false);
    expect(canManageMember(null, "read")).toBe(false);
    expect(canManageMember("superuser", "read")).toBe(false);
  });

  test("an unknown TARGET role ranks 0 and shows as manageable — the server still decides", () => {
    // Display-only: worst case is a control the request 403s on, never a
    // grant. Hiding it instead would need a rank the client cannot know.
    expect(canManageMember("admin", "maintainer")).toBe(true);
    expect(canManageMember("owner", "maintainer")).toBe(true);
  });
});

describe("roleChangeNeedsWarning — the four role-change cases of the decided six", () => {
  test("granting admin warns", () => {
    expect(roleChangeNeedsWarning("read", "admin")).toBe(true);
    expect(roleChangeNeedsWarning("write", "admin")).toBe(true);
  });

  test("granting owner warns", () => {
    expect(roleChangeNeedsWarning("read", "owner")).toBe(true);
    expect(roleChangeNeedsWarning("write", "owner")).toBe(true);
    expect(roleChangeNeedsWarning("admin", "owner")).toBe(true);
  });

  test("demoting an admin holder warns", () => {
    expect(roleChangeNeedsWarning("admin", "write")).toBe(true);
    expect(roleChangeNeedsWarning("admin", "read")).toBe(true);
  });

  test("demoting an owner holder warns, including owner → admin", () => {
    expect(roleChangeNeedsWarning("owner", "admin")).toBe(true);
    expect(roleChangeNeedsWarning("owner", "write")).toBe(true);
    expect(roleChangeNeedsWarning("owner", "read")).toBe(true);
  });

  test("read↔write traffic passes silently, exactly as before D39", () => {
    expect(roleChangeNeedsWarning("read", "write")).toBe(false);
    expect(roleChangeNeedsWarning("write", "read")).toBe(false);
  });

  test("unknown roles rank 0 and are safe: no warning, no crash", () => {
    expect(roleChangeNeedsWarning("maintainer", "write")).toBe(false);
    expect(roleChangeNeedsWarning("write", "maintainer")).toBe(false);
    expect(roleChangeNeedsWarning("maintainer", "maintainer")).toBe(false);
    expect(roleChangeNeedsWarning(undefined, undefined)).toBe(false);
    // But a KNOWN privileged side still warns even when the other is unknown.
    expect(roleChangeNeedsWarning("maintainer", "owner")).toBe(true);
    expect(roleChangeNeedsWarning("admin", "maintainer")).toBe(true);
  });
});

describe("isPrivilegedDemotion — which copy the dialog shows", () => {
  test("owner → admin is first of all the loss of an owner", () => {
    expect(isPrivilegedDemotion("owner", "admin")).toBe(true);
    expect(isPrivilegedDemotion("admin", "read")).toBe(true);
  });

  test("a grant is not a demotion", () => {
    expect(isPrivilegedDemotion("read", "admin")).toBe(false);
    expect(isPrivilegedDemotion("admin", "owner")).toBe(false);
    expect(isPrivilegedDemotion("write", "read")).toBe(false);
  });
});

describe("removalNeedsWarning — the fifth and sixth decided cases", () => {
  test("removing an admin or owner warns", () => {
    expect(removalNeedsWarning("admin")).toBe(true);
    expect(removalNeedsWarning("owner")).toBe(true);
  });

  test("removing a read or write member keeps the plain dialog", () => {
    expect(removalNeedsWarning("read")).toBe(false);
    expect(removalNeedsWarning("write")).toBe(false);
    expect(removalNeedsWarning("maintainer")).toBe(false);
    expect(removalNeedsWarning(undefined)).toBe(false);
  });
});

describe("inviteNeedsWarning — an invitation grants on acceptance", () => {
  test("inviting as admin or owner warns", () => {
    expect(inviteNeedsWarning("admin")).toBe(true);
    expect(inviteNeedsWarning("owner")).toBe(true);
  });

  test("inviting as read or write does not", () => {
    expect(inviteNeedsWarning("read")).toBe(false);
    expect(inviteNeedsWarning("write")).toBe(false);
  });
});

describe("isPrivilegedRole", () => {
  test("admin and owner are the guarded tier; everything else is not", () => {
    expect(isPrivilegedRole("admin")).toBe(true);
    expect(isPrivilegedRole("owner")).toBe(true);
    expect(isPrivilegedRole("write")).toBe(false);
    expect(isPrivilegedRole("read")).toBe(false);
    expect(isPrivilegedRole("maintainer")).toBe(false);
    expect(isPrivilegedRole(null)).toBe(false);
  });
});
