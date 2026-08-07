import type { InvitationDto, MemberDto, OrgRole } from "@pub/api/types";
import { roleAtLeast, UPSTREAM_POLICIES } from "@pub/api/types";
import { t, tp } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { Alert } from "@pub/ui/alert";
import { Badge } from "@pub/ui/badge";
import { Button } from "@pub/ui/button";
import { Card, CardContent, CardHeader } from "@pub/ui/card";
import { CopyButton } from "@pub/ui/copy-button";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@pub/ui/dialog";
import { EmptyState } from "@pub/ui/empty-state";
import { Input } from "@pub/ui/input";
import { Label } from "@pub/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeaderCell, TableRow } from "@pub/ui/table";
import { A, createAsync, query, revalidate, useParams } from "@solidjs/router";
import { createSignal, For, type JSX, Show } from "solid-js";
import { formatDate } from "../format";
import {
  assignableRoles,
  canManageMember,
  inviteNeedsWarning,
  isPrivilegedDemotion,
  removalNeedsWarning,
  roleChangeNeedsWarning,
} from "../org-roles";
import { api, describeError, withStepUp } from "../state/api";
import { pushToast } from "../state/toast-store";

/*
 * Organization management: profile, members, invitations (Admin+).
 *
 * Four server rules this screen exists to make visible rather than to
 * discover through errors:
 *
 *   - **The slug is not editable.** It IS the virtual registry base
 *     (`/o/{slug}/pub`, decision 01), so renaming it would break every
 *     `PUB_HOSTED_URL`, every stored `archive_url`, and every CI token at
 *     once. The field is shown read-only next to the editable ones, because
 *     "where did the slug field go" is the question a missing field asks.
 *   - **Granting Write or above is step-up-gated** (S-06), and a demotion
 *     REVOKES the affected user's sessions (S-09) — the response says how
 *     many, and the toast repeats it, because "why was I signed out" deserves
 *     an answer on both ends.
 *   - **A non-Owner manages only levels strictly below their own** (decision
 *     19's role-grant ceiling, D39): the pickers offer only roles the caller
 *     may grant, and a member at or above the caller's level renders as a
 *     read-only row — the select and the Remove button are gone, mirroring
 *     the 403 the server would answer. On top of that, Admin/Owner
 *     transitions (granting either, demoting or removing a holder of either)
 *     confirm through a dialog before the mutation fires.
 *   - **An invitation token is shown once.** It is mailed too, but an instance
 *     with no SMTP configured has no other delivery channel, so the panel
 *     stays until dismissed.
 */

const profileQuery = query((slug: string) => api.orgs.profile(slug, { limit: 1 }), "org-manage");
const membersQuery = query((slug: string) => api.orgs.members(slug), "org-manage-members");
const invitationsQuery = query((slug: string) => api.orgs.invitations(slug), "org-invitations");

function ProfileCard(props: { readonly slug: string }): JSX.Element {
  const profile = createAsync(() => profileQuery(props.slug));
  const [name, setName] = createSignal<string | null>(null);
  const [description, setDescription] = createSignal<string | null>(null);
  const [policy, setPolicy] = createSignal<string | null>(null);
  const [busy, setBusy] = createSignal(false);

  const nameValue = (): string => name() ?? profile()?.org.name ?? "";
  const descriptionValue = (): string => description() ?? profile()?.org.description ?? "";
  const policyValue = (): string => policy() ?? profile()?.org.upstream_policy ?? "allow";

  const submit = async (event: Event): Promise<void> => {
    event.preventDefault();
    if (busy()) return;
    setBusy(true);
    try {
      await api.orgs.update(props.slug, {
        name: nameValue().trim(),
        description: descriptionValue().trim(),
        upstream_policy: policyValue(),
      });
      pushToast(t(app.orgManageSaved), "success");
      await revalidate("org-manage");
      await revalidate("org-profile");
      await revalidate("shell-orgs");
    } catch (error) {
      pushToast(describeError(error), "danger");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <h2 class="text-lg font-semibold text-ink">{t(app.orgManageProfileTitle)}</h2>
      </CardHeader>
      <CardContent>
        <form class="flex flex-col gap-5" onSubmit={(event) => void submit(event)}>
          <div class="grid gap-1.5">
            <Label for="org-manage-name">{t(app.orgsNameField)}</Label>
            <Input
              id="org-manage-name"
              value={nameValue()}
              onInput={(event) => setName(event.currentTarget.value)}
            />
          </div>
          <div class="grid gap-1.5">
            <Label for="org-manage-slug">{t(app.orgsSlugField)}</Label>
            <Input id="org-manage-slug" class="font-mono" value={props.slug} readOnly disabled />
            <p class="text-xs text-ink-muted">{t(app.orgManageSlugLocked)}</p>
          </div>
          <div class="grid gap-1.5">
            <Label for="org-manage-description">{t(app.orgManageDescription)}</Label>
            <Input
              id="org-manage-description"
              value={descriptionValue()}
              onInput={(event) => setDescription(event.currentTarget.value)}
            />
          </div>
          <div class="grid gap-1.5">
            <Label for="org-manage-policy">{t(app.orgManageUpstream)}</Label>
            <select
              id="org-manage-policy"
              value={policyValue()}
              onChange={(event) => setPolicy(event.currentTarget.value)}
              class="h-10 w-full max-w-xs rounded-md border border-line bg-surface px-3 text-sm text-ink outline-none focus-visible:border-accent focus-visible:ring-2 focus-visible:ring-accent/30"
            >
              <For each={UPSTREAM_POLICIES}>
                {(value) => (
                  <option value={value}>
                    {value === "allow" ? t(app.orgUpstreamAllow) : t(app.orgUpstreamBlock)}
                  </option>
                )}
              </For>
            </select>
            <p class="text-xs text-ink-muted">{t(app.orgManageUpstreamHint)}</p>
          </div>
          <Button type="submit" class="self-start" disabled={busy()}>
            {t(app.save)}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}

function MembersCard(props: {
  readonly slug: string;
  readonly role: string | null | undefined;
}): JSX.Element {
  const members = createAsync(() => membersQuery(props.slug));
  const [busyId, setBusyId] = createSignal<string | null>(null);
  const [pendingRemove, setPendingRemove] = createSignal<MemberDto | null>(null);
  const [pendingChange, setPendingChange] = createSignal<{
    readonly member: MemberDto;
    readonly to: OrgRole;
  } | null>(null);
  const rows = (): readonly MemberDto[] => members()?.items ?? [];

  // The current role joins the ceiling-limited options when it is outside them
  // (a future role name this build does not know), so the select keeps telling
  // the truth about what the member holds today.
  const roleOptions = (member: MemberDto): readonly string[] => {
    const grantable = assignableRoles(props.role);
    return grantable.some((role) => role === member.role) ? grantable : [member.role, ...grantable];
  };

  const changeRole = async (member: MemberDto, role: OrgRole): Promise<void> => {
    if (busyId() !== null || member.role === role) return;
    setBusyId(member.user_id);
    try {
      const result = await withStepUp(() =>
        api.orgs.setMemberRole(props.slug, member.user_id, role),
      );
      pushToast(
        result.sessions_revoked > 0
          ? tp(app.orgMemberRoleChangedRevoked, result.sessions_revoked)
          : t(app.orgMemberRoleChanged),
        "success",
      );
      if (result.tokens_revoked > 0) {
        pushToast(tp(app.orgMemberTokensRevoked, result.tokens_revoked));
      }
      setPendingChange(null);
      await revalidate("org-manage-members");
    } catch (error) {
      pushToast(describeError(error), "danger");
      // Resynchronize the row: Solid will not repaint a select whose bound
      // member.role did not change, and the snap-back above may have raced a
      // dialog-confirmed change that the server then refused.
      await revalidate("org-manage-members");
    } finally {
      setBusyId(null);
    }
  };

  const remove = async (): Promise<void> => {
    const member = pendingRemove();
    if (member === null || busyId() !== null) return;
    setBusyId(member.user_id);
    try {
      const result = await withStepUp(() => api.orgs.removeMember(props.slug, member.user_id));
      pushToast(t(app.orgMemberRemoved), "success");
      if (result.tokens_revoked > 0) {
        pushToast(tp(app.orgMemberTokensRevokedRemoved, result.tokens_revoked));
      }
      setPendingRemove(null);
      await revalidate("org-manage-members");
    } catch (error) {
      pushToast(describeError(error), "danger");
    } finally {
      setBusyId(null);
    }
  };

  return (
    <section class="flex flex-col gap-4">
      <h2 class="text-xl font-semibold text-ink">{t(app.orgMembersTitle)}</h2>
      <Alert intent="info">{t(app.orgMemberStepUpNotice)}</Alert>
      <Show when={rows().length > 0} fallback={<EmptyState title={t(app.orgMembersEmpty)} />}>
        <Table label={t(app.orgMembersTitle)}>
          <TableHead>
            <TableRow>
              <TableHeaderCell>{t(app.orgMemberName)}</TableHeaderCell>
              <TableHeaderCell>{t(app.accountEmail)}</TableHeaderCell>
              <TableHeaderCell>{t(app.orgsRole)}</TableHeaderCell>
              <TableHeaderCell>
                <span class="sr-only">{t(app.remove)}</span>
              </TableHeaderCell>
            </TableRow>
          </TableHead>
          <TableBody>
            <For each={rows()}>
              {(member) => (
                <TableRow>
                  <TableCell class="font-medium">{member.display_name}</TableCell>
                  <TableCell class="font-mono text-xs text-ink-muted">
                    {member.email ?? "—"}
                  </TableCell>
                  <TableCell>
                    <Show
                      when={canManageMember(props.role, member.role)}
                      fallback={<span>{member.role}</span>}
                    >
                      <select
                        value={member.role}
                        aria-label={t(app.orgsRole)}
                        disabled={busyId() === member.user_id}
                        onChange={(event) => {
                          const to = event.currentTarget.value as OrgRole;
                          // The row shows server truth only. Snap the select back
                          // BEFORE anything else: a successful change repaints the
                          // real role via revalidate("org-manage-members"), while a
                          // failed request, a busy-skipped pick, or a cancelled
                          // dialog leaves no phantom role on screen.
                          event.currentTarget.value = member.role;
                          if (to === member.role) return;
                          if (roleChangeNeedsWarning(member.role, to)) {
                            setPendingChange({ member, to });
                          } else {
                            void changeRole(member, to);
                          }
                        }}
                        class="h-8 rounded-md border border-line bg-surface px-2 text-sm text-ink outline-none focus-visible:border-accent focus-visible:ring-2 focus-visible:ring-accent/30"
                      >
                        <For each={roleOptions(member)}>
                          {(role) => <option value={role}>{role}</option>}
                        </For>
                      </select>
                    </Show>
                  </TableCell>
                  <TableCell class="text-right">
                    <Show when={canManageMember(props.role, member.role)}>
                      <Button
                        intent="ghost"
                        size="sm"
                        disabled={busyId() === member.user_id}
                        onClick={() => setPendingRemove(member)}
                      >
                        {t(app.remove)}
                      </Button>
                    </Show>
                  </TableCell>
                </TableRow>
              )}
            </For>
          </TableBody>
        </Table>
      </Show>

      <Dialog
        open={pendingRemove() !== null}
        onOpenChange={(open) => !open && setPendingRemove(null)}
      >
        <DialogContent>
          <DialogTitle>{t(app.orgMemberRemoveTitle)}</DialogTitle>
          <DialogDescription>
            {t(app.orgMemberRemoveBody, { name: pendingRemove()?.display_name ?? "" })}
          </DialogDescription>
          <Show when={removalNeedsWarning(pendingRemove()?.role)}>
            <Alert intent="warning">
              {t(app.orgMemberRemovePrivilegedWarning, { role: pendingRemove()?.role ?? "" })}
            </Alert>
          </Show>
          <div class="flex justify-end gap-3">
            <Button intent="ghost" onClick={() => setPendingRemove(null)}>
              {t(app.cancel)}
            </Button>
            <Button intent="danger" onClick={() => void remove()}>
              {t(app.remove)}
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      {/* Opens only for the warn-worthy transitions of decision 19's ceiling
          addendum: granting Admin/Owner, or demoting a holder of either. */}
      <Dialog
        open={pendingChange() !== null}
        onOpenChange={(open) => !open && setPendingChange(null)}
      >
        <DialogContent>
          <DialogTitle>{t(app.orgRoleChangeConfirmTitle)}</DialogTitle>
          <DialogDescription>
            {t(app.orgRoleChangeConfirmBody, {
              name: pendingChange()?.member.display_name ?? "",
              from: pendingChange()?.member.role ?? "",
              to: pendingChange()?.to ?? "",
            })}
          </DialogDescription>
          <Alert intent="warning">
            {isPrivilegedDemotion(pendingChange()?.member.role, pendingChange()?.to)
              ? t(app.orgRoleDemoteWarning)
              : t(app.orgRoleGrantWarning)}
          </Alert>
          <div class="flex justify-end gap-3">
            <Button intent="ghost" onClick={() => setPendingChange(null)}>
              {t(app.cancel)}
            </Button>
            <Button
              intent="danger"
              onClick={() => {
                const pending = pendingChange();
                if (pending !== null) void changeRole(pending.member, pending.to);
              }}
            >
              {t(app.orgRoleChangeConfirmAction)}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </section>
  );
}

function InvitationsCard(props: {
  readonly slug: string;
  readonly role: string | null | undefined;
}): JSX.Element {
  const invitations = createAsync(() => invitationsQuery(props.slug));
  const [email, setEmail] = createSignal("");
  const [role, setRole] = createSignal<OrgRole>("read");
  const [busy, setBusy] = createSignal(false);
  const [token, setToken] = createSignal<string | null>(null);
  const [pendingInvite, setPendingInvite] = createSignal<{
    readonly email: string;
    readonly role: OrgRole;
  } | null>(null);
  const rows = (): readonly InvitationDto[] => invitations()?.items ?? [];

  const sendInvite = async (address: string, invited: OrgRole): Promise<void> => {
    if (busy()) return;
    setBusy(true);
    try {
      const created = await withStepUp(() => api.orgs.invite(props.slug, address, invited));
      setToken(created.token);
      setEmail("");
      setPendingInvite(null);
      pushToast(t(app.orgInviteSent), "success");
      await revalidate("org-invitations");
    } catch (error) {
      pushToast(describeError(error), "danger");
    } finally {
      setBusy(false);
    }
  };

  const invite = (event: Event): void => {
    event.preventDefault();
    const address = email().trim();
    if (busy() || address === "") return;
    // An Admin/Owner invitation grants the role the moment it is accepted, so
    // it confirms through the same dialog tier as a direct grant (D39).
    if (inviteNeedsWarning(role())) {
      setPendingInvite({ email: address, role: role() });
    } else {
      void sendInvite(address, role());
    }
  };

  const revoke = async (invitation: InvitationDto): Promise<void> => {
    if (busy()) return;
    setBusy(true);
    try {
      await withStepUp(() => api.orgs.revokeInvitation(props.slug, invitation.id));
      pushToast(t(app.orgInviteRevoked), "success");
      await revalidate("org-invitations");
    } catch (error) {
      pushToast(describeError(error), "danger");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section class="flex flex-col gap-4">
      <h2 class="text-xl font-semibold text-ink">{t(app.orgInvitationsTitle)}</h2>

      <Show when={token()}>
        {(value) => (
          <Card class="border-warning-soft bg-warning-soft/40">
            <CardHeader>
              <h3 class="text-base font-semibold text-ink">{t(app.orgInviteTokenTitle)}</h3>
              <p class="text-sm text-warning-ink">{t(app.orgInviteTokenBody)}</p>
            </CardHeader>
            <CardContent class="flex flex-col gap-3">
              <div class="flex flex-wrap items-center gap-3">
                <code class="min-w-0 flex-1 overflow-x-auto rounded-lg border border-line bg-surface px-3 py-2 font-mono text-sm text-ink">
                  {value()}
                </code>
                <CopyButton value={value()} />
              </div>
              <Button intent="outline" class="self-start" onClick={() => setToken(null)}>
                {t(app.securityRecoveryDone)}
              </Button>
            </CardContent>
          </Card>
        )}
      </Show>

      <form class="flex flex-wrap items-end gap-3" onSubmit={invite}>
        <div class="grid min-w-56 flex-1 gap-1.5">
          <Label for="invite-email">{t(app.accountEmail)}</Label>
          <Input
            id="invite-email"
            type="email"
            value={email()}
            onInput={(event) => setEmail(event.currentTarget.value)}
          />
        </div>
        <div class="grid gap-1.5">
          <Label for="invite-role">{t(app.orgsRole)}</Label>
          <select
            id="invite-role"
            value={role()}
            onChange={(event) => setRole(event.currentTarget.value as OrgRole)}
            class="h-10 rounded-md border border-line bg-surface px-3 text-sm text-ink outline-none focus-visible:border-accent focus-visible:ring-2 focus-visible:ring-accent/30"
          >
            <For each={assignableRoles(props.role)}>
              {(value) => <option value={value}>{value}</option>}
            </For>
          </select>
        </div>
        <Button type="submit" disabled={busy()}>
          {t(app.orgInviteAction)}
        </Button>
      </form>

      {/* Same warning tier as a direct Admin/Owner grant (D39). */}
      <Dialog
        open={pendingInvite() !== null}
        onOpenChange={(open) => !open && setPendingInvite(null)}
      >
        <DialogContent>
          <DialogTitle>{t(app.orgInviteConfirmTitle)}</DialogTitle>
          <DialogDescription>
            {t(app.orgInviteConfirmBody, {
              email: pendingInvite()?.email ?? "",
              role: pendingInvite()?.role ?? "",
            })}
          </DialogDescription>
          <Alert intent="warning">{t(app.orgRoleGrantWarning)}</Alert>
          <div class="flex justify-end gap-3">
            <Button intent="ghost" onClick={() => setPendingInvite(null)}>
              {t(app.cancel)}
            </Button>
            <Button
              intent="danger"
              onClick={() => {
                const pending = pendingInvite();
                if (pending !== null) void sendInvite(pending.email, pending.role);
              }}
            >
              {t(app.orgInviteAction)}
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      <Show when={rows().length > 0} fallback={<EmptyState title={t(app.orgInvitationsEmpty)} />}>
        <Table label={t(app.orgInvitationsTitle)}>
          <TableHead>
            <TableRow>
              <TableHeaderCell>{t(app.accountEmail)}</TableHeaderCell>
              <TableHeaderCell>{t(app.orgsRole)}</TableHeaderCell>
              <TableHeaderCell>{t(app.orgInviteStatus)}</TableHeaderCell>
              <TableHeaderCell>{t(app.orgInviteExpires)}</TableHeaderCell>
              <TableHeaderCell>
                <span class="sr-only">{t(app.revoke)}</span>
              </TableHeaderCell>
            </TableRow>
          </TableHead>
          <TableBody>
            <For each={rows()}>
              {(invitation) => (
                <TableRow>
                  <TableCell class="font-mono text-xs">{invitation.email}</TableCell>
                  <TableCell>{invitation.role}</TableCell>
                  <TableCell>
                    <Badge variant={invitation.status === "pending" ? "accent" : "neutral"}>
                      {invitation.status}
                    </Badge>
                  </TableCell>
                  <TableCell class="whitespace-nowrap text-ink-muted">
                    {formatDate(invitation.expires_at)}
                  </TableCell>
                  <TableCell class="text-right">
                    <Show when={invitation.status === "pending"}>
                      <Button
                        intent="ghost"
                        size="sm"
                        disabled={busy()}
                        onClick={() => void revoke(invitation)}
                      >
                        {t(app.revoke)}
                      </Button>
                    </Show>
                  </TableCell>
                </TableRow>
              )}
            </For>
          </TableBody>
        </Table>
      </Show>
    </section>
  );
}

export function OrgManageScreen(): JSX.Element {
  const params = useParams<{ slug: string }>();
  const profile = createAsync(() => profileQuery(params.slug));

  return (
    <section class="flex flex-col gap-8">
      <header class="flex flex-col gap-2">
        <A
          href={`/orgs/${encodeURIComponent(params.slug)}`}
          class="w-fit rounded-sm text-sm text-ink-muted outline-none hover:text-accent focus-visible:ring-2 focus-visible:ring-accent"
        >
          ← {profile()?.org.name ?? params.slug}
        </A>
        <h1 class="text-3xl font-bold tracking-tight text-ink">{t(app.orgManageTitle)}</h1>
      </header>

      {/*
        A Read/Write member who guessed the URL gets the server's answer, not a
        blank page: org management is a 403 rather than a 404 because slugs are
        not secret (decision 19's addendum).
      */}
      <Show
        when={roleAtLeast(profile()?.role, "admin")}
        fallback={<Alert intent="danger">{t(app.orgManageForbidden)}</Alert>}
      >
        <ProfileCard slug={params.slug} />
        <MembersCard slug={params.slug} role={profile()?.role} />
        <InvitationsCard slug={params.slug} role={profile()?.role} />
      </Show>
    </section>
  );
}
