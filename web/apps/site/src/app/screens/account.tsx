import type { TotpEnrollDto } from "@pub/api/types";
import { t } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { Alert } from "@pub/ui/alert";
import { Badge } from "@pub/ui/badge";
import { Button } from "@pub/ui/button";
import { Card, CardContent, CardHeader } from "@pub/ui/card";
import { CopyButton } from "@pub/ui/copy-button";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@pub/ui/dialog";
import { Input } from "@pub/ui/input";
import { Label } from "@pub/ui/label";
import { QrCode } from "@pub/ui/qr-code";
import { Spinner } from "@pub/ui/spinner";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@pub/ui/tabs";
import { createSignal, For, type JSX, Show } from "solid-js";
import { formatDate } from "../format";
import { api, describeError, withStepUp } from "../state/api";
import { currentUser } from "../state/session-store";
import { pushToast } from "../state/toast-store";

/*
 * Account: profile summary and the security tab (TOTP enrollment, recovery
 * codes, disabling 2FA behind the step-up gate).
 *
 * KNOWN GAP: the committed API has no endpoint that reports whether a TOTP
 * credential exists, so the tab tracks what happened in THIS session
 * (enrolled / disabled) and otherwise offers enrollment. `POST /auth/totp/enroll`
 * on an already-enrolled account is refused by the server, which is the
 * authority; replace this local flag with the profile's `totp_enabled` as soon
 * as the app API exposes it.
 */

type EnrollmentState =
  | { readonly phase: "idle" }
  | { readonly phase: "enrolling"; readonly enrollment: TotpEnrollDto }
  | { readonly phase: "recovery"; readonly codes: readonly string[] };

function ProfileTab(): JSX.Element {
  const user = currentUser;
  return (
    <Card>
      <CardHeader>
        <h2 class="text-lg font-semibold">{t(app.accountTabProfile)}</h2>
      </CardHeader>
      <CardContent>
        <dl class="grid gap-5 sm:grid-cols-2">
          <div class="flex flex-col gap-1">
            <dt class="text-sm text-ink-muted">{t(app.accountDisplayName)}</dt>
            <dd class="text-ink">{user()?.display_name ?? "—"}</dd>
          </div>
          <div class="flex flex-col gap-1">
            <dt class="text-sm text-ink-muted">{t(app.accountEmail)}</dt>
            <dd class="flex flex-wrap items-center gap-2 text-ink">
              <span class="font-mono text-sm">{user()?.email ?? t(app.accountEmailMissing)}</span>
              <Show when={user()?.email !== null && user()?.email !== undefined}>
                <Badge variant={user()?.email_verified === true ? "success" : "warning"}>
                  {user()?.email_verified === true
                    ? t(app.accountEmailVerified)
                    : t(app.accountEmailUnverified)}
                </Badge>
              </Show>
            </dd>
          </div>
          <div class="flex flex-col gap-1">
            <dt class="text-sm text-ink-muted">{t(app.accountMemberSince)}</dt>
            <dd class="text-ink">{formatDate(user()?.created_at)}</dd>
          </div>
        </dl>
      </CardContent>
    </Card>
  );
}

function SecurityTab(): JSX.Element {
  const [state, setState] = createSignal<EnrollmentState>({ phase: "idle" });
  const [enabled, setEnabled] = createSignal(false);
  const [code, setCode] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);
  const [busy, setBusy] = createSignal(false);
  const [confirmDisable, setConfirmDisable] = createSignal(false);

  const beginEnrollment = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      const enrollment = await api.auth.enrollTotp();
      setState({ phase: "enrolling", enrollment });
      setCode("");
    } catch (failure) {
      setError(describeError(failure));
    } finally {
      setBusy(false);
    }
  };

  const confirmEnrollment = async (event: Event): Promise<void> => {
    event.preventDefault();
    const current = state();
    if (current.phase !== "enrolling" || busy()) return;
    setBusy(true);
    setError(null);
    try {
      const confirmed = await api.auth.confirmTotp(code().trim());
      setState({ phase: "recovery", codes: confirmed.recovery_codes });
      setEnabled(true);
      setCode("");
    } catch {
      setError(t(app.loginInvalidCode));
    } finally {
      setBusy(false);
    }
  };

  const disable = async (): Promise<void> => {
    if (busy()) return;
    setBusy(true);
    try {
      await withStepUp(() => api.auth.disableTotp());
      setEnabled(false);
      setState({ phase: "idle" });
      setConfirmDisable(false);
      pushToast(t(app.securityTotpDisabled), "success");
    } catch (failure) {
      pushToast(describeError(failure), "danger");
    } finally {
      setBusy(false);
    }
  };

  /**
   * Saves the recovery codes as a text file.
   *
   * The anchor is attached to the document before the click and the object URL
   * is revoked on the next macrotask: Safari ignores `download` on a detached
   * element, and revoking synchronously can cancel a download the browser has
   * not started reading yet. The blob URL is same-origin and short-lived — it
   * is the only place these codes exist outside the panel, and nothing logs it.
   */
  const downloadCodes = (codes: readonly string[]): void => {
    const blob = new Blob([`${codes.join("\n")}\n`], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "pub-recovery-codes.txt";
    link.hidden = true;
    document.body.append(link);
    link.click();
    setTimeout(() => {
      link.remove();
      URL.revokeObjectURL(url);
    }, 0);
  };

  return (
    <div class="flex flex-col gap-6">
      <Card>
        <CardHeader>
          <div class="flex flex-wrap items-center justify-between gap-3">
            <h2 class="text-lg font-semibold">{t(app.securityTotpTitle)}</h2>
            <Show when={enabled()}>
              <Badge variant="success">{t(app.securityTotpEnabled)}</Badge>
            </Show>
          </div>
          <p class="text-sm text-ink-muted">{t(app.securityTotpBody)}</p>
        </CardHeader>
        <CardContent class="flex flex-col gap-6">
          <Show when={error()}>{(message) => <Alert intent="danger">{message()}</Alert>}</Show>

          <Show when={state().phase === "idle"}>
            <div class="flex flex-wrap gap-3">
              <Button disabled={busy()} onClick={() => void beginEnrollment()}>
                <Show when={busy()}>
                  <Spinner />
                </Show>
                {t(app.securityTotpEnable)}
              </Button>
              <Show when={enabled()}>
                <Button intent="danger" onClick={() => setConfirmDisable(true)}>
                  {t(app.securityTotpDisable)}
                </Button>
              </Show>
            </div>
          </Show>

          <Show
            when={state().phase === "enrolling" ? (state() as { enrollment: TotpEnrollDto }) : null}
          >
            {(current) => (
              <div class="flex flex-col gap-6">
                <p class="text-sm text-ink">{t(app.securityTotpScan)}</p>
                {/*
                  A QR must be dark-on-light to be scannable, so the well keeps
                  a light background in BOTH themes — this is the documented
                  exception to "tokens flip automatically" (web/DESIGN.md §7).
                */}
                <div class="w-fit rounded-xl border border-line bg-qr-surface p-4 text-qr-ink">
                  <QrCode
                    value={current().enrollment.otpauth_url}
                    label={t(app.securityTotpScan)}
                    fallback={<p class="max-w-48 text-sm">{t(app.securityTotpManual)}</p>}
                  />
                </div>
                <div class="flex flex-col gap-2">
                  <p class="text-sm text-ink-muted">{t(app.securityTotpManual)}</p>
                  <div class="flex flex-wrap items-center gap-3">
                    <code class="min-w-0 flex-1 overflow-x-auto rounded-lg border border-line bg-canvas px-3 py-2 font-mono text-sm tracking-widest text-ink">
                      {current().enrollment.secret}
                    </code>
                    <CopyButton value={current().enrollment.secret} />
                  </div>
                </div>
                <form
                  class="flex flex-col gap-5"
                  onSubmit={(event) => void confirmEnrollment(event)}
                >
                  <div class="grid max-w-xs gap-1.5">
                    <Label for="totp-confirm">{t(app.securityTotpConfirmLabel)}</Label>
                    <Input
                      id="totp-confirm"
                      autocomplete="one-time-code"
                      inputmode="numeric"
                      maxlength={6}
                      value={code()}
                      class="font-mono tracking-widest"
                      onInput={(event) => setCode(event.currentTarget.value.replace(/\D/g, ""))}
                    />
                  </div>
                  <Button type="submit" class="self-start" disabled={busy() || code().length < 6}>
                    <Show when={busy()}>
                      <Spinner />
                    </Show>
                    {t(app.securityTotpConfirm)}
                  </Button>
                </form>
              </div>
            )}
          </Show>

          <Show
            when={state().phase === "recovery" ? (state() as { codes: readonly string[] }) : null}
          >
            {(current) => (
              <div class="flex flex-col gap-4 rounded-xl border border-warning-soft bg-warning-soft/40 p-6">
                <h3 class="text-base font-semibold text-ink">{t(app.securityRecoveryTitle)}</h3>
                <p class="text-sm text-warning-ink">{t(app.securityRecoveryBody)}</p>
                <ul class="grid gap-2 font-mono text-sm text-ink sm:grid-cols-2">
                  <For each={current().codes}>
                    {(recoveryCode) => (
                      <li class="rounded-md border border-line bg-surface px-3 py-1.5">
                        {recoveryCode}
                      </li>
                    )}
                  </For>
                </ul>
                <div class="flex flex-wrap gap-3">
                  <CopyButton value={current().codes.join("\n")} />
                  <Button intent="outline" onClick={() => downloadCodes(current().codes)}>
                    {t(app.securityRecoveryDownload)}
                  </Button>
                  <Button onClick={() => setState({ phase: "idle" })}>
                    {t(app.securityRecoveryDone)}
                  </Button>
                </div>
              </div>
            )}
          </Show>
        </CardContent>
      </Card>

      <Dialog open={confirmDisable()} onOpenChange={setConfirmDisable}>
        <DialogContent>
          <DialogTitle>{t(app.securityDisableTitle)}</DialogTitle>
          <DialogDescription>{t(app.securityDisableBody)}</DialogDescription>
          <div class="flex justify-end gap-3">
            <Button intent="ghost" onClick={() => setConfirmDisable(false)}>
              {t(app.cancel)}
            </Button>
            <Button intent="danger" disabled={busy()} onClick={() => void disable()}>
              {t(app.securityTotpDisable)}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

export function AccountScreen(): JSX.Element {
  return (
    <section class="flex flex-col gap-6">
      <h1 class="text-3xl font-bold tracking-tight text-ink">{t(app.accountTitle)}</h1>
      <Tabs defaultValue="profile">
        <TabsList>
          <TabsTrigger value="profile">{t(app.accountTabProfile)}</TabsTrigger>
          <TabsTrigger value="security">{t(app.accountTabSecurity)}</TabsTrigger>
        </TabsList>
        <TabsContent value="profile">
          <ProfileTab />
        </TabsContent>
        <TabsContent value="security">
          <SecurityTab />
        </TabsContent>
      </Tabs>
    </section>
  );
}
