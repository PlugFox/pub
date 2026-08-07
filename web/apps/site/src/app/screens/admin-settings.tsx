import { REGISTRATION_MODES, SMTP_SECURITY_MODES, UPSTREAM_POLICIES } from "@pub/api/types";
import { t } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { Alert } from "@pub/ui/alert";
import { Badge } from "@pub/ui/badge";
import { Button } from "@pub/ui/button";
import { Card, CardContent, CardHeader } from "@pub/ui/card";
import { Input } from "@pub/ui/input";
import { Label } from "@pub/ui/label";
import { createAsync, query, revalidate } from "@solidjs/router";
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
import { api, describeError } from "../state/api";
import { pushToast } from "../state/toast-store";

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
 * Validation mirrors `crates/admin/src/instance.rs` (see `admin-form.ts`) and
 * is a pre-flight only; the server re-checks everything.
 */

const settingsQuery = query(() => api.admin.settings(), "admin-settings");

const ERROR_MESSAGES: Record<string, { readonly id: string; readonly en: string }> = {
  required: app.adminFieldRequired,
  positive: app.adminFieldPositive,
  domain: app.adminFieldDomain,
};

function FieldError(props: {
  readonly errors: SettingsErrors;
  readonly field: SettingsFieldError;
}): JSX.Element {
  return (
    <Show when={props.errors[props.field]}>
      {(kind) => (
        <p class="text-xs text-danger-ink">{t(ERROR_MESSAGES[kind()] ?? app.adminFieldRequired)}</p>
      )}
    </Show>
  );
}

/** A numeric rate-limit row: label, input, inline error. */
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
        onInput={(event) => props.onInput(event.currentTarget.value)}
      />
      <FieldError errors={props.errors} field={props.field} />
    </div>
  );
}

export function AdminSettingsPanel(): JSX.Element {
  const settings = createAsync(() => settingsQuery());
  const [draft, setDraft] = createSignal<SettingsForm | null>(null);
  const [errors, setErrors] = createSignal<SettingsErrors>({});
  const [busy, setBusy] = createSignal(false);

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
      pushToast(t(app.adminSettingsSaved, { version: updated.version }), "success");
      await revalidate("admin-settings");
      // The landing payload carries branding; a rename must not wait for a
      // reload to reach the header.
      await revalidate("home");
    } catch (error) {
      pushToast(describeError(error), "danger");
    } finally {
      setBusy(false);
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
