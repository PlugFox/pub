import type { MeDto, TotpEnrollDto } from "@pub/api/types";
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
import { createAsync, query, revalidate, useNavigate } from "@solidjs/router";
import { createSignal, For, type JSX, Show } from "solid-js";
import { formatDate } from "../format";
import { api, describeError, forgetSession, withStepUp } from "../state/api";
import { adoptProfile } from "../state/session-store";
import { pushToast } from "../state/toast-store";

/*
 * Account (S-29, decision 39): profile, security, privacy.
 *
 * Everything on this screen reads `GET /me` rather than the login payload. The
 * access token deliberately carries only `sub`/`sid`/org levels/timestamps
 * (S-07), so `totp_enabled` and `is_instance_admin` are facts a token cannot
 * hold — which is why the security tab used to track enrollment in a
 * session-local flag that was wrong on every device but the enrolling one.
 * That flag is gone.
 *
 * Four of the actions here are step-up gated and therefore wrapped in
 * `withStepUp`; the rename is not, because S-06's list is about escalation and
 * a prompt to fix a typo is how a prompt becomes noise.
 */

const ME_KEY = "account-me";
const meQuery = query(() => api.account.me(), ME_KEY);

type EnrollmentState =
  | { readonly phase: "idle" }
  | { readonly phase: "enrolling"; readonly enrollment: TotpEnrollDto }
  | { readonly phase: "recovery"; readonly codes: readonly string[] };

/** The email-change dialog is a two-step flow; the step is the state. */
type EmailChangeState =
  | { readonly phase: "closed" }
  | { readonly phase: "address" }
  | { readonly phase: "code"; readonly pendingId: string; readonly email: string };

function ProfileTab(props: { readonly me: MeDto | undefined }): JSX.Element {
  const [name, setName] = createSignal<string | null>(null);
  const [saving, setSaving] = createSignal(false);
  const [emailChange, setEmailChange] = createSignal<EmailChangeState>({ phase: "closed" });
  const [address, setAddress] = createSignal("");
  const [code, setCode] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  // `null` means "untouched", so the field follows the server until the user
  // types — otherwise a rename made elsewhere would be overwritten by a stale
  // signal the moment this tab re-rendered.
  const displayName = (): string => name() ?? props.me?.display_name ?? "";

  const save = async (event: Event): Promise<void> => {
    event.preventDefault();
    if (saving()) return;
    setSaving(true);
    try {
      const updated = await api.account.update(displayName());
      adoptProfile(updated);
      setName(null);
      await revalidate(ME_KEY);
      pushToast(t(app.accountNameSaved), "success");
    } catch (failure) {
      pushToast(describeError(failure), "danger");
    } finally {
      setSaving(false);
    }
  };

  const sendCode = async (event: Event): Promise<void> => {
    event.preventDefault();
    if (busy()) return;
    setBusy(true);
    setError(null);
    try {
      const started = await withStepUp(() => api.account.startEmailChange(address()));
      setEmailChange({ phase: "code", pendingId: started.pending_id, email: started.email });
      setCode("");
    } catch (failure) {
      setError(describeError(failure));
    } finally {
      setBusy(false);
    }
  };

  const confirmCode = async (event: Event): Promise<void> => {
    event.preventDefault();
    const current = emailChange();
    if (current.phase !== "code" || busy()) return;
    setBusy(true);
    setError(null);
    try {
      const updated = await withStepUp(() =>
        api.account.confirmEmailChange(current.pendingId, code().trim()),
      );
      adoptProfile(updated);
      setEmailChange({ phase: "closed" });
      await revalidate(ME_KEY);
      pushToast(t(app.accountEmailChanged), "success");
    } catch (failure) {
      setError(describeError(failure));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <h2 class="text-lg font-semibold">{t(app.accountTabProfile)}</h2>
      </CardHeader>
      <CardContent class="flex flex-col gap-6">
        <form class="grid max-w-sm gap-1.5" onSubmit={(event) => void save(event)}>
          <Label for="account-name">{t(app.accountDisplayName)}</Label>
          <Input
            id="account-name"
            value={displayName()}
            maxlength={80}
            onInput={(event) => setName(event.currentTarget.value)}
          />
          <Button
            type="submit"
            class="mt-2 self-start"
            disabled={saving() || displayName().trim().length === 0}
          >
            <Show when={saving()}>
              <Spinner />
            </Show>
            {t(app.accountNameSave)}
          </Button>
        </form>

        <dl class="grid gap-5 sm:grid-cols-2">
          <div class="flex flex-col gap-1">
            <dt class="text-sm text-ink-muted">{t(app.accountEmail)}</dt>
            <dd class="flex flex-wrap items-center gap-2 text-ink">
              <span class="font-mono text-sm">{props.me?.email ?? t(app.accountEmailMissing)}</span>
              <Show when={props.me?.email !== null && props.me?.email !== undefined}>
                <Badge variant={props.me?.email_verified === true ? "success" : "warning"}>
                  {props.me?.email_verified === true
                    ? t(app.accountEmailVerified)
                    : t(app.accountEmailUnverified)}
                </Badge>
              </Show>
              <Button
                intent="outline"
                onClick={() => {
                  setAddress("");
                  setError(null);
                  setEmailChange({ phase: "address" });
                }}
              >
                {t(app.accountEmailChange)}
              </Button>
            </dd>
          </div>
          <div class="flex flex-col gap-1">
            <dt class="text-sm text-ink-muted">{t(app.accountMemberSince)}</dt>
            <dd class="text-ink">{formatDate(props.me?.created_at)}</dd>
          </div>
        </dl>
      </CardContent>

      <Dialog
        open={emailChange().phase !== "closed"}
        onOpenChange={(open) => {
          if (!open) setEmailChange({ phase: "closed" });
        }}
      >
        <DialogContent>
          <DialogTitle>{t(app.accountEmailChangeTitle)}</DialogTitle>
          <Show when={emailChange().phase === "address"}>
            <DialogDescription>{t(app.accountEmailChangeBody)}</DialogDescription>
            <form class="flex flex-col gap-5" onSubmit={(event) => void sendCode(event)}>
              <Show when={error()}>{(message) => <Alert intent="danger">{message()}</Alert>}</Show>
              <div class="grid gap-1.5">
                <Label for="account-new-email">{t(app.accountEmailChangeNewLabel)}</Label>
                <Input
                  id="account-new-email"
                  type="email"
                  autocomplete="email"
                  value={address()}
                  onInput={(event) => setAddress(event.currentTarget.value)}
                />
              </div>
              <Button type="submit" class="self-end" disabled={busy() || address().trim() === ""}>
                <Show when={busy()}>
                  <Spinner />
                </Show>
                {t(app.accountEmailChangeSend)}
              </Button>
            </form>
          </Show>
          <Show when={emailChange().phase === "code" ? (emailChange() as { email: string }) : null}>
            {(pending) => (
              <>
                <DialogDescription>
                  {t(app.accountEmailChangeSent, { email: pending().email })}
                </DialogDescription>
                <form class="flex flex-col gap-5" onSubmit={(event) => void confirmCode(event)}>
                  <Show when={error()}>
                    {(message) => <Alert intent="danger">{message()}</Alert>}
                  </Show>
                  <div class="grid gap-1.5">
                    <Label for="account-email-code">{t(app.accountEmailChangeCodeLabel)}</Label>
                    <Input
                      id="account-email-code"
                      autocomplete="one-time-code"
                      inputmode="numeric"
                      maxlength={8}
                      class="font-mono tracking-widest"
                      value={code()}
                      onInput={(event) => setCode(event.currentTarget.value.replace(/\D/g, ""))}
                    />
                  </div>
                  <Button type="submit" class="self-end" disabled={busy() || code().length < 8}>
                    <Show when={busy()}>
                      <Spinner />
                    </Show>
                    {t(app.accountEmailChangeConfirm)}
                  </Button>
                </form>
              </>
            )}
          </Show>
        </DialogContent>
      </Dialog>
    </Card>
  );
}

function SecurityTab(props: { readonly me: MeDto | undefined }): JSX.Element {
  const [state, setState] = createSignal<EnrollmentState>({ phase: "idle" });
  const [code, setCode] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);
  const [busy, setBusy] = createSignal(false);
  const [confirmDisable, setConfirmDisable] = createSignal(false);

  /*
   * The server's answer, not a local guess: `/me` reports whether a credential
   * exists, so a factor enrolled on another device shows here too. The old
   * session-local flag was this screen's oldest known gap.
   */
  const enabled = (): boolean => props.me?.totp_enabled === true;

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
      setCode("");
      await revalidate(ME_KEY);
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
      setState({ phase: "idle" });
      setConfirmDisable(false);
      await revalidate(ME_KEY);
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
    downloadBlob(
      new Blob([`${codes.join("\n")}\n`], { type: "text/plain" }),
      "pub-recovery-codes.txt",
    );
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
              <Show when={!enabled()}>
                <Button disabled={busy()} onClick={() => void beginEnrollment()}>
                  <Show when={busy()}>
                    <Spinner />
                  </Show>
                  {t(app.securityTotpEnable)}
                </Button>
              </Show>
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

function PrivacyTab(props: { readonly me: MeDto | undefined }): JSX.Element {
  const navigate = useNavigate();
  const [exporting, setExporting] = createSignal(false);
  const [confirmDelete, setConfirmDelete] = createSignal(false);
  const [confirmation, setConfirmation] = createSignal("");
  const [deleting, setDeleting] = createSignal(false);

  const exportData = async (): Promise<void> => {
    if (exporting()) return;
    setExporting(true);
    try {
      const blob = await withStepUp(() => api.account.export());
      downloadBlob(blob, "pub-account-export.ndjson");
    } catch (failure) {
      pushToast(describeError(failure), "danger");
    } finally {
      setExporting(false);
    }
  };

  const deleteAccount = async (): Promise<void> => {
    if (deleting()) return;
    setDeleting(true);
    try {
      await withStepUp(() => api.account.delete(confirmation().trim()));
      // The credential is dead on the server; clearing locally is what stops
      // the app from firing a refresh with a token nothing will honour.
      forgetSession();
      setConfirmDelete(false);
      pushToast(t(app.accountDeleted), "success");
      navigate("/");
    } catch (failure) {
      pushToast(describeError(failure), "danger");
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div class="flex flex-col gap-6">
      <Card>
        <CardHeader>
          <h2 class="text-lg font-semibold">{t(app.accountExportTitle)}</h2>
          <p class="text-sm text-ink-muted">{t(app.accountExportBody)}</p>
        </CardHeader>
        <CardContent>
          <Button disabled={exporting()} onClick={() => void exportData()}>
            <Show when={exporting()}>
              <Spinner />
            </Show>
            {t(app.accountExportButton)}
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <h2 class="text-lg font-semibold text-danger-ink">{t(app.accountDeleteTitle)}</h2>
          <p class="text-sm text-ink-muted">{t(app.accountDeleteBody)}</p>
        </CardHeader>
        <CardContent>
          <Button
            intent="danger"
            onClick={() => {
              setConfirmation("");
              setConfirmDelete(true);
            }}
          >
            {t(app.accountDeleteButton)}
          </Button>
        </CardContent>
      </Card>

      <Dialog open={confirmDelete()} onOpenChange={setConfirmDelete}>
        <DialogContent>
          <DialogTitle>{t(app.accountDeleteTitle)}</DialogTitle>
          <DialogDescription>{t(app.accountDeleteBody)}</DialogDescription>
          <div class="grid gap-1.5">
            <Label for="account-delete-confirm">{t(app.accountDeleteConfirmLabel)}</Label>
            <Input
              id="account-delete-confirm"
              autocomplete="off"
              value={confirmation()}
              onInput={(event) => setConfirmation(event.currentTarget.value)}
            />
          </div>
          <div class="flex justify-end gap-3">
            <Button intent="ghost" onClick={() => setConfirmDelete(false)}>
              {t(app.cancel)}
            </Button>
            <Button
              intent="danger"
              // The server checks this too (and is the authority); matching here
              // keeps the button from being a trap while the field is empty.
              disabled={
                deleting() ||
                confirmation().trim().toLowerCase() !== (props.me?.email ?? "").toLowerCase() ||
                (props.me?.email ?? "") === ""
              }
              onClick={() => void deleteAccount()}
            >
              <Show when={deleting()}>
                <Spinner />
              </Show>
              {t(app.accountDeleteButton)}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

/**
 * Hands a blob to the browser as a download.
 *
 * Shared by the recovery codes and the S-29.b export: the anchor is attached
 * before the click (Safari ignores `download` on a detached element) and the
 * object URL is revoked on the next macrotask, because revoking synchronously
 * can cancel a download the browser has not started reading.
 */
function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.hidden = true;
  document.body.append(link);
  link.click();
  setTimeout(() => {
    link.remove();
    URL.revokeObjectURL(url);
  }, 0);
}

export function AccountScreen(): JSX.Element {
  const me = createAsync(() => meQuery());

  return (
    <section class="flex flex-col gap-6">
      <h1 class="text-3xl font-bold tracking-tight text-ink">{t(app.accountTitle)}</h1>
      <Tabs defaultValue="profile">
        <TabsList>
          <TabsTrigger value="profile">{t(app.accountTabProfile)}</TabsTrigger>
          <TabsTrigger value="security">{t(app.accountTabSecurity)}</TabsTrigger>
          <TabsTrigger value="privacy">{t(app.accountTabPrivacy)}</TabsTrigger>
        </TabsList>
        <TabsContent value="profile">
          <ProfileTab me={me()} />
        </TabsContent>
        <TabsContent value="security">
          <SecurityTab me={me()} />
        </TabsContent>
        <TabsContent value="privacy">
          <PrivacyTab me={me()} />
        </TabsContent>
      </Tabs>
    </section>
  );
}
