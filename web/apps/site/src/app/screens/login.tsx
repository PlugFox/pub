import type { LoginDto } from "@pub/api/types";
import { t } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { Alert } from "@pub/ui/alert";
import { Button } from "@pub/ui/button";
import { Card, CardContent, CardHeader } from "@pub/ui/card";
import { Input } from "@pub/ui/input";
import { Label } from "@pub/ui/label";
import { Separator } from "@pub/ui/separator";
import { Spinner } from "@pub/ui/spinner";
import { createAsync, query, useLocation, useNavigate, useSearchParams } from "@solidjs/router";
import { createSignal, For, type JSX, onCleanup, onMount, Show, Suspense } from "solid-js";
import { api, completeLogin } from "../state/api";
import {
  classifyLoginError,
  initialLoginState,
  type LoginError,
  type LoginEvent,
  type LoginState,
  loginReducer,
  resendAvailableAt,
} from "../state/login-machine";
import { safeReturnTo } from "../urls";
import { OIDC_FLOW_STORAGE_PREFIX } from "./oidc-callback";

/*
 * Sign-in: email OTP always, configured OIDC providers when the instance has
 * any, and the second factor when the first one is not enough.
 *
 * All branching lives in `login-machine.ts`; this file renders a state and
 * dispatches events. The failure text is uniform across "wrong code",
 * "expired code", and "unknown account" (S-04) — the only distinctions the
 * user sees are "throttled" (actionable, with a live countdown) and "offline"
 * (actionable, and emphatically not a rejection).
 */

const providersQuery = query(() => api.auth.providers(), "auth-providers");

type EmailState = Extract<LoginState, { step: "email" }>;
type CodeState = Extract<LoginState, { step: "code" }>;
type MfaState = Extract<LoginState, { step: "mfa" }>;

/** Live countdown in whole seconds until `target`; 0 once it has passed. */
function createCountdown(target: () => number): () => number {
  const remaining = (): number => Math.max(0, Math.ceil((target() - Date.now()) / 1000));
  const [seconds, setSeconds] = createSignal(remaining());
  const timer = setInterval(() => setSeconds(remaining()), 250);
  onCleanup(() => clearInterval(timer));
  return seconds;
}

function ErrorMessage(props: { readonly error: LoginError }): JSX.Element {
  const text = (): string => {
    switch (props.error.kind) {
      case "emailRequired":
        return t(app.loginEmailRequired);
      case "invalidCode":
        return t(app.loginInvalidCode);
      case "rateLimited":
        return t(app.rateLimited, { seconds: props.error.retryAfter ?? 60 });
      case "network":
        return t(app.networkError);
      default:
        return t(app.genericError);
    }
  };
  return <Alert intent="danger">{text()}</Alert>;
}

function OidcButtons(props: { readonly returnTo: string }): JSX.Element {
  const providers = createAsync(() => providersQuery());
  const [failed, setFailed] = createSignal(false);

  const start = async (provider: string): Promise<void> => {
    setFailed(false);
    try {
      const started = await api.auth.startOidc(provider);
      // S-01.a: the flow handle binds this browser to the flow. It has to
      // survive a full-page navigation to the IdP and back, and it must NOT
      // outlive the tab — sessionStorage is exactly that lifetime.
      sessionStorage.setItem(`${OIDC_FLOW_STORAGE_PREFIX}${provider}`, started.flow_id);
      sessionStorage.setItem(`${OIDC_FLOW_STORAGE_PREFIX}return_to`, props.returnTo);
      window.location.assign(started.authorize_url);
    } catch {
      setFailed(true);
    }
  };

  return (
    <Suspense>
      {/* An instance with no configured provider shows no divider and no buttons. */}
      <Show when={(providers()?.providers.length ?? 0) > 0}>
        <div class="flex items-center gap-3">
          <Separator class="flex-1" />
          <span class="text-xs text-ink-muted">{t(app.loginOidcDivider)}</span>
          <Separator class="flex-1" />
        </div>
        <div class="flex flex-col gap-3">
          <For each={providers()?.providers ?? []}>
            {(provider) => (
              <Button intent="outline" onClick={() => void start(provider.id)}>
                {t(app.loginOidcButton, { provider: provider.display_name })}
              </Button>
            )}
          </For>
        </div>
        <Show when={failed()}>
          <Alert intent="warning">{t(app.loginProvidersUnavailable)}</Alert>
        </Show>
      </Show>
    </Suspense>
  );
}

export function LoginScreen(): JSX.Element {
  const navigate = useNavigate();
  const location = useLocation();
  const [params] = useSearchParams();
  const returnTo = (): string =>
    safeReturnTo(typeof params.return_to === "string" ? params.return_to : null);

  const [state, setState] = createSignal<LoginState>(initialLoginState());
  const dispatch = (event: LoginEvent): void => {
    setState((current) => loginReducer(current, event));
  };
  const [code, setCode] = createSignal("");

  const asEmail = (): EmailState | null =>
    state().step === "email" ? (state() as EmailState) : null;
  const asCode = (): CodeState | null => (state().step === "code" ? (state() as CodeState) : null);
  const asMfa = (): MfaState | null => (state().step === "mfa" ? (state() as MfaState) : null);

  // An OIDC first factor can also answer `mfa_required` (S-05.a). The callback
  // route hands the pending handle over in the router state rather than the
  // URL — it is a live credential and has no business in history or a referrer
  // — and the machine starts on the second-factor step instead of re-asking
  // for an email the user never typed.
  onMount(() => {
    const handed = (location.state as { mfaToken?: unknown } | undefined)?.mfaToken;
    if (typeof handed === "string" && handed !== "") {
      dispatch({ type: "loginResolved", login: { mfa_required: true, mfa_token: handed } });
    }
  });

  const finish = (login: LoginDto): void => {
    if (completeLogin(login)) navigate(returnTo(), { replace: true });
  };

  const requestCode = async (email: string): Promise<void> => {
    const before = state();
    dispatch({ type: "submit" });
    try {
      const pending = await api.auth.requestOtp(email);
      setCode("");
      dispatch({
        type: "codeSent",
        email,
        pendingId: pending.pending_id,
        resendAvailableAt: resendAvailableAt(undefined),
      });
    } catch (error) {
      const classified = classifyLoginError(error);
      // A throttled resend must move the cool-down forward, or the button
      // invites the user straight into another refusal (S-24 Retry-After).
      if (classified.kind === "rateLimited" && before.step === "code") {
        dispatch({
          type: "codeSent",
          email: before.email,
          pendingId: before.pendingId,
          resendAvailableAt: resendAvailableAt(classified.retryAfter),
        });
      }
      dispatch({ type: "failed", error: classified });
    }
  };

  const submitEmail = (event: Event): void => {
    event.preventDefault();
    const current = asEmail();
    if (current === null || current.busy) return;
    const email = current.email.trim();
    if (email === "") {
      dispatch({ type: "failed", error: { kind: "emailRequired" } });
      return;
    }
    void requestCode(email);
  };

  const submitCode = async (event: Event): Promise<void> => {
    event.preventDefault();
    const current = asCode();
    if (current === null || current.busy) return;
    dispatch({ type: "submit" });
    try {
      const login = await api.auth.verifyOtp({
        pendingId: current.pendingId,
        email: current.email,
        code: code().trim(),
      });
      dispatch({ type: "loginResolved", login });
      setCode("");
      if (!login.mfa_required) finish(login);
    } catch (error) {
      dispatch({ type: "failed", error: classifyLoginError(error) });
    }
  };

  const submitMfa = async (event: Event): Promise<void> => {
    event.preventDefault();
    const current = asMfa();
    if (current === null || current.busy) return;
    dispatch({ type: "submit" });
    const value = code().trim();
    try {
      const login = await api.auth.verifyTotp({
        mfaToken: current.mfaToken,
        code: current.mode === "totp" ? value : undefined,
        recoveryCode: current.mode === "recovery" ? value : undefined,
      });
      dispatch({ type: "loginResolved", login });
      finish(login);
    } catch (error) {
      dispatch({ type: "failed", error: classifyLoginError(error) });
    }
  };

  return (
    <div class="mx-auto flex w-full max-w-md flex-col gap-6 py-6">
      <Card>
        <Show when={asEmail()}>
          {(current) => (
            <>
              <CardHeader>
                <h1 class="text-2xl font-bold tracking-tight">{t(app.loginTitle)}</h1>
                <p class="text-sm text-ink-muted">{t(app.loginSubtitle)}</p>
              </CardHeader>
              <CardContent class="flex flex-col gap-5">
                <form class="flex flex-col gap-5" onSubmit={submitEmail}>
                  <div class="grid gap-1.5">
                    <Label for="login-email">{t(app.loginEmailLabel)}</Label>
                    <Input
                      id="login-email"
                      type="email"
                      name="email"
                      autocomplete="email"
                      autofocus
                      placeholder={t(app.loginEmailPlaceholder)}
                      value={current().email}
                      aria-invalid={current().error === null ? undefined : "true"}
                      onInput={(event) =>
                        dispatch({ type: "editEmail", email: event.currentTarget.value })
                      }
                    />
                  </div>
                  <Show when={current().error}>{(error) => <ErrorMessage error={error()} />}</Show>
                  <Button type="submit" disabled={current().busy}>
                    <Show when={current().busy}>
                      <Spinner />
                    </Show>
                    {t(app.loginContinue)}
                  </Button>
                </form>
                <OidcButtons returnTo={returnTo()} />
              </CardContent>
            </>
          )}
        </Show>

        <Show when={asCode()}>
          {(current) => {
            const seconds = createCountdown(() => current().resendAvailableAt);
            // `autofocus` is a document-load attribute: the HTML spec flushes
            // autofocus candidates once per document, so an input inserted by
            // a later step change is NOT focused by it. The step transition is
            // exactly the moment a keyboard user must land on the new field,
            // so move focus explicitly when the branch mounts.
            let codeInput: HTMLInputElement | undefined;
            onMount(() => codeInput?.focus());
            return (
              <>
                <CardHeader>
                  <h1 class="text-2xl font-bold tracking-tight">{t(app.loginCodeTitle)}</h1>
                  <p class="text-sm text-ink-muted">
                    {t(app.loginCodeSubtitle, { email: current().email })}
                  </p>
                </CardHeader>
                <CardContent class="flex flex-col gap-5">
                  <form class="flex flex-col gap-5" onSubmit={(event) => void submitCode(event)}>
                    <div class="grid gap-1.5">
                      <Label for="login-code">{t(app.loginCodeLabel)}</Label>
                      <Input
                        id="login-code"
                        ref={codeInput}
                        // `one-time-code` lets the OS offer the emailed code
                        // from its notification; `numeric` brings up the digit
                        // keypad without blocking a paste of the whole code.
                        autocomplete="one-time-code"
                        inputmode="numeric"
                        maxlength={8}
                        value={code()}
                        aria-invalid={current().error === null ? undefined : "true"}
                        class="font-mono text-base tracking-widest"
                        onInput={(event) => {
                          // Paste-friendly: strip whatever the mail client
                          // wrapped around the digits instead of refusing it.
                          const digits = event.currentTarget.value.replace(/\D/g, "").slice(0, 8);
                          event.currentTarget.value = digits;
                          setCode(digits);
                        }}
                      />
                    </div>
                    <Show when={current().error}>
                      {(error) => <ErrorMessage error={error()} />}
                    </Show>
                    <Button type="submit" disabled={current().busy || code().length !== 8}>
                      <Show when={current().busy}>
                        <Spinner />
                      </Show>
                      {t(app.loginVerify)}
                    </Button>
                  </form>
                  <div class="flex flex-wrap items-center justify-between gap-3 text-sm">
                    {/*
                      The ticking countdown sits OUTSIDE the live region and
                      the resend button INSIDE it. A screen reader can read the
                      remaining seconds on demand but is not told about them
                      once a second; the one thing worth announcing — that a
                      new code can now be requested — arrives exactly once,
                      when the button appears in the empty region.
                    */}
                    <Show when={seconds() > 0}>
                      <span class="text-ink-muted">
                        {t(app.loginResendIn, { seconds: seconds() })}
                      </span>
                    </Show>
                    <div role="status">
                      <Show when={seconds() === 0}>
                        <button
                          type="button"
                          class="cursor-pointer rounded-md text-accent underline outline-none focus-visible:ring-2 focus-visible:ring-accent"
                          onClick={() => void requestCode(current().email)}
                        >
                          {t(app.loginResend)}
                        </button>
                      </Show>
                    </div>
                    <button
                      type="button"
                      class="cursor-pointer rounded-md text-ink-muted underline outline-none hover:text-ink focus-visible:ring-2 focus-visible:ring-accent"
                      onClick={() => dispatch({ type: "changeEmail" })}
                    >
                      {t(app.loginUseAnotherEmail)}
                    </button>
                  </div>
                </CardContent>
              </>
            );
          }}
        </Show>

        <Show when={asMfa()}>
          {(current) => {
            // Same reason as the code step: a field that appears with a step
            // change has to be focused explicitly, not by `autofocus`.
            let mfaInput: HTMLInputElement | undefined;
            onMount(() => mfaInput?.focus());
            return (
              <>
                <CardHeader>
                  <h1 class="text-2xl font-bold tracking-tight">{t(app.loginMfaTitle)}</h1>
                  <p class="text-sm text-ink-muted">
                    {current().mode === "totp"
                      ? t(app.loginMfaSubtitle)
                      : t(app.loginMfaRecoverySubtitle)}
                  </p>
                </CardHeader>
                <CardContent class="flex flex-col gap-5">
                  <form class="flex flex-col gap-5" onSubmit={(event) => void submitMfa(event)}>
                    <div class="grid gap-1.5">
                      <Label for="login-mfa">
                        {current().mode === "totp"
                          ? t(app.loginMfaCodeLabel)
                          : t(app.loginMfaRecoveryLabel)}
                      </Label>
                      <Input
                        id="login-mfa"
                        ref={mfaInput}
                        autocomplete="one-time-code"
                        inputmode={current().mode === "totp" ? "numeric" : "text"}
                        value={code()}
                        aria-invalid={current().error === null ? undefined : "true"}
                        class="font-mono tracking-widest"
                        onInput={(event) => setCode(event.currentTarget.value)}
                      />
                    </div>
                    <Show when={current().error}>
                      {(error) => <ErrorMessage error={error()} />}
                    </Show>
                    <Button type="submit" disabled={current().busy || code().trim() === ""}>
                      <Show when={current().busy}>
                        <Spinner />
                      </Show>
                      {t(app.loginVerify)}
                    </Button>
                  </form>
                  <button
                    type="button"
                    class="cursor-pointer self-start rounded-md text-sm text-accent underline outline-none focus-visible:ring-2 focus-visible:ring-accent"
                    onClick={() => {
                      setCode("");
                      dispatch({
                        type: "setMfaMode",
                        mode: current().mode === "totp" ? "recovery" : "totp",
                      });
                    }}
                  >
                    {current().mode === "totp" ? t(app.loginMfaUseRecovery) : t(app.loginMfaUseApp)}
                  </button>
                </CardContent>
              </>
            );
          }}
        </Show>
      </Card>
    </div>
  );
}
