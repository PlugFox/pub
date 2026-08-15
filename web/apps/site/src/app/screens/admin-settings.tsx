import {
  REGISTRATION_MODES,
  SMTP_SECURITY_MODES,
  type SmtpTestResultDto,
  UPSTREAM_POLICIES,
} from "@pub/api/types";
import { t } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { Alert, AlertTitle } from "@pub/ui/alert";
import { Badge } from "@pub/ui/badge";
import { Button } from "@pub/ui/button";
import { Card, CardContent, CardHeader } from "@pub/ui/card";
import { Input } from "@pub/ui/input";
import { Label } from "@pub/ui/label";
import { createAsync, revalidate } from "@solidjs/router";
import { createSignal, For, type JSX, Show } from "solid-js";
import {
  formToPatch,
  hasErrors,
  type SettingsErrors,
  type SettingsFieldError,
  type SettingsForm,
  settingsToForm,
  validateSettings,
} from "../admin-form";
import { formatBytes } from "../format";
import { ADMIN_SETTINGS_KEY, adminSettingsQuery } from "../state/admin-queries";
import { api, describeError } from "../state/api";
import { pushToast } from "../state/toast-store";
import { parseQuotaBytes } from "../storage-quota";

/*
 * Runtime instance settings (decision 09 + decision 17 branding).
 *
 * Grouped by area because that is how the server stores them: `PATCH
 * /admin/settings` replaces each SECTION wholesale, so the form is built from
 * the loaded document and submits complete sections — a diff would clear
 * whatever it left out.
 *
 * THE SMTP PASSWORD IS WRITE-ONLY (S-26). The document carries `password_set`
 * and never a value, so there is nothing to prefill and a masked "••••••" in
 * the field would be a lie the operator would try to keep. Instead: a badge
 * saying whether one is stored, and an explicit "set a new password"
 * affordance that is the ONLY thing that puts the key in the patch. Omitting
 * it keeps the stored secret; `""` clears it — both reachable, neither by
 * accident.
 *
 * WHICH IS WHY THERE IS A TEST-MAIL BUTTON. A write-only credential feeding a
 * transport that is rebuilt lazily, per instance, on its next send (decision
 * 09's mailer amendment) is otherwise undiagnosable from here: "saved" says
 * nothing about "delivers". The action is diagnosis, not a save step — it
 * exercises what the server has STORED, so an unsaved edit is not what it
 * tests, and its recipient is fixed server-side to the acting administrator.
 *
 * Validation mirrors `crates/admin/src/instance.rs` (see `admin-form.ts`) and
 * is a pre-flight only; the server re-checks everything. The require-a-token
 * switch is likewise only a picture of a flag: the pub-protocol extractor
 * reads it per request and is the thing that refuses anonymous callers.
 */

const ERROR_MESSAGES: Record<string, { readonly id: string; readonly en: string }> = {
  required: app.adminFieldRequired,
  positive: app.adminFieldPositive,
  domain: app.adminFieldDomain,
  bytes: app.adminFieldBytes,
};

/**
 * Id of a field's inline error, so the control can point at it.
 *
 * `aria-invalid` alone tells a screen-reader user that something is wrong and
 * not what — the gap D33 records for nine fields on this very form. Every
 * control below that can turn invalid now carries `aria-describedby`, pointed
 * at this id and dropped again when the error clears (a dangling reference is
 * its own defect).
 */
function errorId(field: SettingsFieldError): string {
  return `settings-error-${field}`;
}

/** The described-by value for a field: its error id, or nothing when it is valid. */
function describedBy(errors: SettingsErrors, field: SettingsFieldError): string | undefined {
  return errors[field] === undefined ? undefined : errorId(field);
}

function FieldError(props: {
  readonly errors: SettingsErrors;
  readonly field: SettingsFieldError;
}): JSX.Element {
  return (
    <Show when={props.errors[props.field]}>
      {(kind) => (
        <p id={errorId(props.field)} class="text-xs text-danger-ink">
          {t(ERROR_MESSAGES[kind()] ?? app.adminFieldRequired)}
        </p>
      )}
    </Show>
  );
}

/**
 * A numeric rate-limit row: label, input, inline error.
 *
 * `min={1}` is the contract of every field that uses it — this component is
 * for the numbers where a zero is a lockout. The storage quota does NOT use
 * it: `0` is that field's shipped value and means unlimited (S-20.b).
 */
function LimitField(props: {
  readonly id: string;
  readonly label: string;
  readonly value: string;
  readonly errors: SettingsErrors;
  readonly field: SettingsFieldError;
  readonly onInput: (value: string) => void;
}): JSX.Element {
  return (
    <div class="grid gap-1.5">
      <Label for={props.id}>{props.label}</Label>
      <Input
        id={props.id}
        type="number"
        min={1}
        value={props.value}
        aria-invalid={props.errors[props.field] !== undefined}
        aria-describedby={describedBy(props.errors, props.field)}
        onInput={(event) => props.onInput(event.currentTarget.value)}
      />
      <FieldError errors={props.errors} field={props.field} />
    </div>
  );
}

/**
 * Echoes the typed byte count back as a size, or names the `0` case.
 *
 * Empty while the field does not parse — the inline error is what speaks then,
 * and a stale size next to a rejected value would contradict it.
 */
function quotaEcho(raw: string): string {
  const bytes = parseQuotaBytes(raw);
  if (bytes === null) return "";
  return bytes === 0 ? t(app.adminStorageUnlimited) : formatBytes(bytes);
}

/**
 * The outcome of one probe send.
 *
 * `delivered: true` with no host is NOT a green tick: the server accepted the
 * message into its in-memory outbox because no SMTP host is configured
 * anywhere, so nothing left the process — that case gets its own warning, or
 * the screen would report working mail on an instance that sends none.
 *
 * `detail` is the mail server's own text ("535 authentication failed"), which
 * is the answer the operator came for. It is rendered verbatim and
 * untranslated, as plain text — Solid escapes it, and nothing here ever builds
 * markup from a server string.
 */
function TestMailResult(props: { readonly result: SmtpTestResultDto }): JSX.Element {
  const host = (): string => props.result.host ?? "";
  const nowhere = (): boolean => props.result.delivered && host() === "";
  const intent = (): "success" | "warning" | "danger" => {
    if (!props.result.delivered) return "danger";
    return nowhere() ? "warning" : "success";
  };
  const heading = (): string => {
    if (!props.result.delivered) return t(app.adminSmtpTestFailed);
    return nowhere() ? t(app.adminSmtpTestNowhere) : t(app.adminSmtpTestOk);
  };
  return (
    <Alert intent={intent()} class="flex-col gap-1">
      <AlertTitle>{heading()}</AlertTitle>
      <Show when={host() !== ""}>
        <p>{t(app.adminSmtpTestVia, { host: host(), security: props.result.security })}</p>
      </Show>
      <p>
        {props.result.credentialed
          ? t(app.adminSmtpTestCredentialed)
          : t(app.adminSmtpTestAnonymous)}
      </p>
      <Show when={props.result.detail}>
        {(detail) => <p class="font-mono text-xs break-words">{detail()}</p>}
      </Show>
    </Alert>
  );
}

export function AdminSettingsPanel(): JSX.Element {
  const settings = createAsync(() => adminSettingsQuery());
  const [draft, setDraft] = createSignal<SettingsForm | null>(null);
  const [errors, setErrors] = createSignal<SettingsErrors>({});
  const [busy, setBusy] = createSignal(false);
  const [testing, setTesting] = createSignal(false);
  const [testResult, setTestResult] = createSignal<SmtpTestResultDto | null>(null);

  const form = (): SettingsForm | null => {
    const current = draft();
    if (current !== null) return current;
    const loaded = settings();
    return loaded === undefined ? null : settingsToForm(loaded);
  };

  const patch = (fields: Partial<SettingsForm>): void => {
    const current = form();
    if (current === null) return;
    setDraft({ ...current, ...fields });
  };

  const submit = async (event: Event): Promise<void> => {
    event.preventDefault();
    const current = form();
    if (current === null || busy()) return;
    const found = validateSettings(current);
    setErrors(found);
    if (hasErrors(found)) return;
    setBusy(true);
    try {
      const updated = await api.admin.updateSettings(formToPatch(current));
      setDraft(settingsToForm(updated));
      // A previous diagnosis described the configuration that was just
      // replaced; keeping it on screen would let it be read as a verdict on
      // the new one.
      setTestResult(null);
      pushToast(t(app.adminSettingsSaved, { version: updated.version }), "success");
      await revalidate(ADMIN_SETTINGS_KEY);
      // The landing payload carries branding; a rename must not wait for a
      // reload to reach the header.
      await revalidate("home");
    } catch (error) {
      pushToast(describeError(error), "danger");
    } finally {
      setBusy(false);
    }
  };

  /**
   * A refused delivery is a `200` carrying the reason, so only a transport or
   * authorization failure lands in `catch` — the SMTP diagnosis belongs in the
   * card, not in a toast that scrolls away.
   */
  const sendTestMail = async (): Promise<void> => {
    if (testing()) return;
    setTesting(true);
    try {
      setTestResult(await api.admin.testSmtp());
    } catch (error) {
      setTestResult(null);
      pushToast(describeError(error), "danger");
    } finally {
      setTesting(false);
    }
  };

  return (
    <Show when={form()}>
      {(current) => (
        <form class="flex flex-col gap-6" onSubmit={(event) => void submit(event)}>
          <Show when={hasErrors(errors())}>
            <Alert intent="danger">{t(app.adminSettingsInvalid)}</Alert>
          </Show>

          <Card>
            <CardHeader>
              <h2 class="text-lg font-semibold text-ink">{t(app.adminBrandingTitle)}</h2>
              <p class="text-sm text-ink-muted">{t(app.adminBrandingBody)}</p>
            </CardHeader>
            <CardContent class="grid gap-5 sm:grid-cols-2">
              <div class="grid gap-1.5">
                <Label for="branding-name">{t(app.adminBrandingName)}</Label>
                <Input
                  id="branding-name"
                  value={current().brandingName}
                  aria-invalid={errors().brandingName !== undefined}
                  aria-describedby={describedBy(errors(), "brandingName")}
                  onInput={(event) => patch({ brandingName: event.currentTarget.value })}
                />
                <FieldError errors={errors()} field="brandingName" />
              </div>
              <div class="grid gap-1.5">
                <Label for="branding-tagline">{t(app.adminBrandingTagline)}</Label>
                <Input
                  id="branding-tagline"
                  value={current().brandingTagline}
                  onInput={(event) => patch({ brandingTagline: event.currentTarget.value })}
                />
              </div>
              <div class="grid gap-1.5">
                <Label for="branding-logo">{t(app.adminBrandingLogo)}</Label>
                <Input
                  id="branding-logo"
                  class="font-mono"
                  value={current().brandingLogoUrl}
                  onInput={(event) => patch({ brandingLogoUrl: event.currentTarget.value })}
                />
              </div>
              <div class="grid gap-1.5">
                <Label for="branding-color">{t(app.adminBrandingColor)}</Label>
                <Input
                  id="branding-color"
                  class="font-mono"
                  value={current().brandingPrimaryColor}
                  onInput={(event) => patch({ brandingPrimaryColor: event.currentTarget.value })}
                />
                <p class="text-xs text-ink-muted">{t(app.adminBrandingColorHint)}</p>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <h2 class="text-lg font-semibold text-ink">{t(app.adminRegistrationTitle)}</h2>
              <p class="text-sm text-ink-muted">{t(app.adminRegistrationBody)}</p>
            </CardHeader>
            <CardContent class="flex flex-col gap-5">
              <div class="grid gap-1.5">
                <Label for="registration-mode">{t(app.adminRegistrationMode)}</Label>
                <select
                  id="registration-mode"
                  value={current().registrationMode}
                  onChange={(event) => patch({ registrationMode: event.currentTarget.value })}
                  class="h-10 w-full max-w-xs rounded-md border border-line bg-surface px-3 text-sm text-ink outline-none focus-visible:border-accent focus-visible:ring-2 focus-visible:ring-accent/30"
                >
                  <For each={REGISTRATION_MODES}>
                    {(mode) => <option value={mode}>{mode}</option>}
                  </For>
                </select>
              </div>
              <div class="grid gap-1.5">
                <Label for="registration-domains">{t(app.adminAllowedDomains)}</Label>
                <textarea
                  id="registration-domains"
                  rows={4}
                  value={current().allowedDomains}
                  aria-invalid={errors().allowedDomains !== undefined}
                  aria-describedby={describedBy(errors(), "allowedDomains")}
                  onInput={(event) => patch({ allowedDomains: event.currentTarget.value })}
                  class="w-full rounded-md border border-line bg-surface px-3 py-2 font-mono text-sm text-ink outline-none focus-visible:border-accent focus-visible:ring-2 focus-visible:ring-accent/30"
                />
                <p class="text-xs text-ink-muted">{t(app.adminAllowedDomainsHint)}</p>
                <FieldError errors={errors()} field="allowedDomains" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <h2 class="text-lg font-semibold text-ink">{t(app.adminLimitsTitle)}</h2>
              <p class="text-sm text-ink-muted">{t(app.adminLimitsBody)}</p>
            </CardHeader>
            <CardContent class="grid gap-5 sm:grid-cols-2">
              <LimitField
                id="limit-otp-email"
                label={t(app.adminLimitOtpEmail)}
                value={current().otpPerEmailHour}
                errors={errors()}
                field="otpPerEmailHour"
                onInput={(value) => patch({ otpPerEmailHour: value })}
              />
              <LimitField
                id="limit-otp-ip"
                label={t(app.adminLimitOtpIp)}
                value={current().otpPerIpHour}
                errors={errors()}
                field="otpPerIpHour"
                onInput={(value) => patch({ otpPerIpHour: value })}
              />
              <LimitField
                id="limit-login-ip"
                label={t(app.adminLimitLoginIp)}
                value={current().loginPerIpMinute}
                errors={errors()}
                field="loginPerIpMinute"
                onInput={(value) => patch({ loginPerIpMinute: value })}
              />
              <LimitField
                id="limit-token-fail"
                label={t(app.adminLimitTokenFail)}
                value={current().tokenAuthFailPerIpMinute}
                errors={errors()}
                field="tokenAuthFailPerIpMinute"
                onInput={(value) => patch({ tokenAuthFailPerIpMinute: value })}
              />
              <LimitField
                id="limit-publish"
                label={t(app.adminLimitPublish)}
                value={current().publishPerHourOrg}
                errors={errors()}
                field="publishPerHourOrg"
                onInput={(value) => patch({ publishPerHourOrg: value })}
              />
              <LimitField
                id="limit-read-ip"
                label={t(app.adminLimitReadIp)}
                value={current().readPerIpMinute}
                errors={errors()}
                field="readPerIpMinute"
                onInput={(value) => patch({ readPerIpMinute: value })}
              />
              <LimitField
                id="limit-read-identity"
                label={t(app.adminLimitReadIdentity)}
                value={current().readPerIdentityMinute}
                errors={errors()}
                field="readPerIdentityMinute"
                onInput={(value) => patch({ readPerIdentityMinute: value })}
              />
              {/* S-24.g: the write buckets. Deliberately an order of magnitude
                  below the read numbers beside them — writes are that much
                  rarer in every legitimate shape — and, like the reads, they
                  fail OPEN, so these are quotas on cost and not access gates. */}
              <LimitField
                id="limit-write-ip"
                label={t(app.adminLimitWriteIp)}
                value={current().writePerIpMinute}
                errors={errors()}
                field="writePerIpMinute"
                onInput={(value) => patch({ writePerIpMinute: value })}
              />
              <LimitField
                id="limit-write-identity"
                label={t(app.adminLimitWriteIdentity)}
                value={current().writePerIdentityMinute}
                errors={errors()}
                field="writePerIdentityMinute"
                onInput={(value) => patch({ writePerIdentityMinute: value })}
              />
              {/* S-24.h: not buckets at all — exact rolling 24-hour database
                  counts. They live in this section because they are limits an
                  administrator changes, not because they share a mechanism. */}
              <LimitField
                id="limit-invitations-org"
                label={t(app.adminLimitInvitationsOrg)}
                value={current().invitationsPerDayOrg}
                errors={errors()}
                field="invitationsPerDayOrg"
                onInput={(value) => patch({ invitationsPerDayOrg: value })}
              />
              <LimitField
                id="limit-invitations-actor"
                label={t(app.adminLimitInvitationsActor)}
                value={current().invitationsPerDayActor}
                errors={errors()}
                field="invitationsPerDayActor"
                onInput={(value) => patch({ invitationsPerDayActor: value })}
              />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <div class="flex flex-wrap items-center gap-3">
                <h2 class="text-lg font-semibold text-ink">{t(app.adminSmtpTitle)}</h2>
                <Badge variant={settings()?.smtp.password_set === true ? "success" : "neutral"}>
                  {settings()?.smtp.password_set === true
                    ? t(app.adminSmtpPasswordSet)
                    : t(app.adminSmtpPasswordUnset)}
                </Badge>
              </div>
              <p class="text-sm text-ink-muted">{t(app.adminSmtpBody)}</p>
            </CardHeader>
            <CardContent class="grid gap-5 sm:grid-cols-2">
              <div class="grid gap-1.5">
                <Label for="smtp-host">{t(app.adminSmtpHost)}</Label>
                <Input
                  id="smtp-host"
                  class="font-mono"
                  value={current().smtpHost}
                  onInput={(event) => patch({ smtpHost: event.currentTarget.value })}
                />
                <p class="text-xs text-ink-muted">{t(app.adminSmtpHostHint)}</p>
              </div>
              <LimitField
                id="smtp-port"
                label={t(app.adminSmtpPort)}
                value={current().smtpPort}
                errors={errors()}
                field="smtpPort"
                onInput={(value) => patch({ smtpPort: value })}
              />
              <div class="grid gap-1.5">
                <Label for="smtp-username">{t(app.adminSmtpUsername)}</Label>
                <Input
                  id="smtp-username"
                  class="font-mono"
                  value={current().smtpUsername}
                  onInput={(event) => patch({ smtpUsername: event.currentTarget.value })}
                />
              </div>
              <div class="grid gap-1.5">
                <Label for="smtp-from">{t(app.adminSmtpFrom)}</Label>
                <Input
                  id="smtp-from"
                  class="font-mono"
                  value={current().smtpFrom}
                  aria-invalid={errors().smtpFrom !== undefined}
                  aria-describedby={describedBy(errors(), "smtpFrom")}
                  onInput={(event) => patch({ smtpFrom: event.currentTarget.value })}
                />
                <FieldError errors={errors()} field="smtpFrom" />
              </div>
              <div class="grid gap-1.5">
                <Label for="smtp-security">{t(app.adminSmtpSecurity)}</Label>
                <select
                  id="smtp-security"
                  value={current().smtpSecurity}
                  onChange={(event) => patch({ smtpSecurity: event.currentTarget.value })}
                  class="h-10 w-full rounded-md border border-line bg-surface px-3 text-sm text-ink outline-none focus-visible:border-accent focus-visible:ring-2 focus-visible:ring-accent/30"
                >
                  <For each={SMTP_SECURITY_MODES}>
                    {(mode) => <option value={mode}>{mode}</option>}
                  </For>
                </select>
              </div>
              <div class="flex flex-col gap-2 sm:col-span-2">
                <label class="flex cursor-pointer items-center gap-2 text-sm text-ink">
                  <input
                    type="checkbox"
                    checked={current().smtpSetPassword}
                    onChange={(event) =>
                      patch({
                        smtpSetPassword: event.currentTarget.checked,
                        smtpPassword: "",
                      })
                    }
                    class="size-4 accent-accent outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-surface"
                  />
                  <span>{t(app.adminSmtpSetPassword)}</span>
                </label>
                <Show when={current().smtpSetPassword}>
                  <div class="grid gap-1.5">
                    <Label for="smtp-password">{t(app.adminSmtpPassword)}</Label>
                    <Input
                      id="smtp-password"
                      type="password"
                      autocomplete="new-password"
                      value={current().smtpPassword}
                      onInput={(event) => patch({ smtpPassword: event.currentTarget.value })}
                    />
                    <p class="text-xs text-ink-muted">{t(app.adminSmtpPasswordHint)}</p>
                  </div>
                </Show>
              </div>
              <div class="flex flex-col gap-3 border-t border-line pt-5 sm:col-span-2">
                <div class="flex flex-wrap items-center gap-x-4 gap-y-2">
                  <Button intent="outline" disabled={testing()} onClick={() => void sendTestMail()}>
                    {testing() ? t(app.adminSmtpTestSending) : t(app.adminSmtpTest)}
                  </Button>
                  <p class="text-xs text-ink-muted">{t(app.adminSmtpTestHint)}</p>
                </div>
                <Show when={testResult()}>{(result) => <TestMailResult result={result()} />}</Show>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <h2 class="text-lg font-semibold text-ink">{t(app.adminUpstreamTitle)}</h2>
              <p class="text-sm text-ink-muted">{t(app.adminUpstreamBody)}</p>
            </CardHeader>
            <CardContent class="flex flex-col gap-5">
              <label class="flex cursor-pointer items-center gap-2 text-sm text-ink">
                <input
                  type="checkbox"
                  checked={current().upstreamEnabled}
                  onChange={(event) => patch({ upstreamEnabled: event.currentTarget.checked })}
                  class="size-4 accent-accent outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-surface"
                />
                <span>{t(app.adminUpstreamEnabled)}</span>
              </label>
              <div class="grid gap-1.5">
                <Label for="upstream-policy">{t(app.adminUpstreamDefault)}</Label>
                <select
                  id="upstream-policy"
                  value={current().upstreamDefaultPolicy}
                  onChange={(event) => patch({ upstreamDefaultPolicy: event.currentTarget.value })}
                  class="h-10 w-full max-w-xs rounded-md border border-line bg-surface px-3 text-sm text-ink outline-none focus-visible:border-accent focus-visible:ring-2 focus-visible:ring-accent/30"
                >
                  <For each={UPSTREAM_POLICIES}>
                    {(policy) => <option value={policy}>{policy}</option>}
                  </For>
                </select>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <h2 class="text-lg font-semibold text-ink">{t(app.adminRegistryTitle)}</h2>
              <p class="text-sm text-ink-muted">{t(app.adminRegistryBody)}</p>
            </CardHeader>
            <CardContent class="flex flex-col gap-2">
              <label class="flex cursor-pointer items-center gap-2 text-sm text-ink">
                <input
                  type="checkbox"
                  checked={current().registryRequireAuthForRead}
                  onChange={(event) =>
                    patch({ registryRequireAuthForRead: event.currentTarget.checked })
                  }
                  class="size-4 accent-accent outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-surface"
                />
                <span>{t(app.adminRegistryRequireAuth)}</span>
              </label>
              <p class="text-xs text-ink-muted">{t(app.adminRegistryRequireAuthHint)}</p>
            </CardContent>
          </Card>

          {/*
            THE QUOTA IS NOT A RATE LIMIT, so it is not in that card.

            It rides the `registry` wire section together with the flag above —
            two cards, one section, which the wholesale patch handles because
            `formToPatch` always builds the section from the whole form. They
            are separate cards because they answer different questions: the one
            above is who may READ, this one is how much an org may STORE.

            Keeping it out of "Rate limits" is the load-bearing part. That card
            promises "every value at least 1"; here `0` is the shipped value and
            means unlimited, and a refusal is a permanent 400 rather than a 429
            with a Retry-After (S-20.b) — no amount of waiting frees storage.
          */}
          <Card>
            <CardHeader>
              <h2 class="text-lg font-semibold text-ink">{t(app.adminStorageTitle)}</h2>
              <p class="text-sm text-ink-muted">{t(app.adminStorageBody)}</p>
            </CardHeader>
            <CardContent class="flex flex-col gap-2">
              <div class="grid max-w-sm gap-1.5">
                <Label for="registry-storage-quota">{t(app.adminStorageQuota)}</Label>
                <Input
                  id="registry-storage-quota"
                  type="number"
                  min={0}
                  value={current().storageQuotaBytes}
                  aria-invalid={errors().storageQuotaBytes !== undefined}
                  aria-describedby={describedBy(errors(), "storageQuotaBytes")}
                  onInput={(event) => patch({ storageQuotaBytes: event.currentTarget.value })}
                />
                {/* The number is bytes, which nobody reads at a glance: the
                    echo turns 10737418240 into "10.0 GiB" while it is typed,
                    and names the 0 case rather than leaving it to be
                    discovered. */}
                <Show when={quotaEcho(current().storageQuotaBytes)}>
                  {(echo) => <p class="text-xs font-medium text-ink">{echo()}</p>}
                </Show>
                <FieldError errors={errors()} field="storageQuotaBytes" />
                <p class="text-xs text-ink-muted">{t(app.adminStorageQuotaHint)}</p>
              </div>
            </CardContent>
          </Card>

          <div class="flex flex-wrap items-center gap-4">
            <Button type="submit" disabled={busy()}>
              {t(app.save)}
            </Button>
            <p class="text-xs text-ink-muted">
              {t(app.adminSettingsVersion, { version: settings()?.version ?? 0 })}
            </p>
          </div>
        </form>
      )}
    </Show>
  );
}
