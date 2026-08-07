import { isRateLimited, NetworkError } from "@pub/api/errors";
import { t } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { Alert } from "@pub/ui/alert";
import { Button } from "@pub/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@pub/ui/dialog";
import { Input } from "@pub/ui/input";
import { Label } from "@pub/ui/label";
import { Spinner } from "@pub/ui/spinner";
import { createSignal, type JSX, Show } from "solid-js";
import { api } from "../state/api";
import { markStepUpFresh } from "../state/session-store";
import { isStepUpOpen, resolveStepUp } from "../state/step-up-store";

/*
 * The single step-up prompt (S-06), mounted once by the shell.
 *
 * It is deliberately global rather than per-screen: any call anywhere can hit
 * the gate, and the caller that triggered it is already suspended waiting on
 * `promptStepUp()`. Dismissing resolves `false`, which makes the blocked
 * action surface its original 403 rather than hang.
 */

export function StepUpDialog(): JSX.Element {
  const [code, setCode] = createSignal("");
  const [useRecovery, setUseRecovery] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [busy, setBusy] = createSignal(false);

  const close = (satisfied: boolean): void => {
    setCode("");
    setError(null);
    setBusy(false);
    setUseRecovery(false);
    resolveStepUp(satisfied);
  };

  const submit = async (event: Event): Promise<void> => {
    event.preventDefault();
    if (busy() || code().trim() === "") return;
    setBusy(true);
    setError(null);
    try {
      const value = code().trim();
      const result = await api.auth.stepUp(
        useRecovery() ? { recoveryCode: value } : { code: value },
      );
      markStepUpFresh(result.valid_until);
      close(true);
    } catch (failure) {
      if (failure instanceof NetworkError) setError(t(app.networkError));
      else if (isRateLimited(failure)) {
        setError(t(app.rateLimited, { seconds: 60 }));
      } else setError(t(app.loginInvalidCode));
      setBusy(false);
    }
  };

  return (
    <Dialog open={isStepUpOpen()} onOpenChange={(open) => !open && close(false)}>
      <DialogContent>
        <DialogTitle>{t(app.stepUpTitle)}</DialogTitle>
        <DialogDescription>{t(app.stepUpBody)}</DialogDescription>
        <form class="flex flex-col gap-5" onSubmit={(event) => void submit(event)}>
          <div class="grid gap-1.5">
            <Label for="step-up-code">
              {useRecovery() ? t(app.loginMfaRecoveryLabel) : t(app.loginMfaCodeLabel)}
            </Label>
            <Input
              id="step-up-code"
              value={code()}
              autofocus
              autocomplete="one-time-code"
              inputmode={useRecovery() ? "text" : "numeric"}
              aria-invalid={error() === null ? undefined : "true"}
              class="font-mono tracking-widest"
              onInput={(event) => setCode(event.currentTarget.value)}
            />
          </div>
          <Show when={error()}>{(message) => <Alert intent="danger">{message()}</Alert>}</Show>
          <div class="flex items-center justify-between gap-3">
            <button
              type="button"
              class="cursor-pointer rounded-md text-sm text-accent underline outline-none focus-visible:ring-2 focus-visible:ring-accent"
              onClick={() => setUseRecovery((value) => !value)}
            >
              {useRecovery() ? t(app.loginMfaUseApp) : t(app.loginMfaUseRecovery)}
            </button>
            <div class="flex items-center gap-3">
              <Button intent="ghost" onClick={() => close(false)}>
                {t(app.cancel)}
              </Button>
              <Button type="submit" disabled={busy() || code().trim() === ""}>
                <Show when={busy()}>
                  <Spinner />
                </Show>
                {t(app.stepUpConfirm)}
              </Button>
            </div>
          </div>
          {/*
            S-06.a: accounts with no enrolled second factor cannot call the
            step-up endpoint at all — their re-auth path is a fresh sign-in.
            Saying so here turns an otherwise unexplainable refusal into an
            instruction.
          */}
          <p class="text-xs text-ink-muted">{t(app.stepUpNoFactor)}</p>
        </form>
      </DialogContent>
    </Dialog>
  );
}
