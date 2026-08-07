import { t } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { Alert } from "@pub/ui/alert";
import { buttonVariants } from "@pub/ui/button";
import { Card, CardContent, CardHeader } from "@pub/ui/card";
import { Spinner } from "@pub/ui/spinner";
import { A, useNavigate, useParams, useSearchParams } from "@solidjs/router";
import { createSignal, type JSX, onMount, Show } from "solid-js";
import { api, completeLogin } from "../state/api";
import { safeReturnTo } from "../urls";

/*
 * OIDC redirect landing (`/app/auth/callback/{provider}`).
 *
 * The IdP sends the browser here with `code` and `state` in the query. The
 * third input — the `flow_id` that binds this browser to the flow (S-01.a) —
 * never travels through the IdP: it was parked in sessionStorage by the login
 * screen, so a `state` intercepted in transit redeems nothing on another
 * machine.
 *
 * The handle is removed BEFORE the exchange, whatever the outcome: the server
 * burns its record on first presentation regardless of success, so keeping a
 * spent id around could only produce a confusing second attempt.
 */

export const OIDC_FLOW_STORAGE_PREFIX = "pub_oidc_flow:";

type CallbackState =
  | { readonly phase: "working" }
  | { readonly phase: "failed"; readonly reason: string };

function takeSessionValue(key: string): string | null {
  try {
    const value = sessionStorage.getItem(key);
    sessionStorage.removeItem(key);
    return value;
  } catch {
    return null;
  }
}

export function OidcCallbackScreen(): JSX.Element {
  const params = useParams<{ provider: string }>();
  const [search] = useSearchParams();
  const navigate = useNavigate();
  const [state, setState] = createSignal<CallbackState>({ phase: "working" });

  onMount(() => {
    const provider = params.provider ?? "";
    const code = typeof search.code === "string" ? search.code : null;
    const oauthState = typeof search.state === "string" ? search.state : null;
    const flowId = takeSessionValue(`${OIDC_FLOW_STORAGE_PREFIX}${provider}`);
    const returnTo = safeReturnTo(takeSessionValue(`${OIDC_FLOW_STORAGE_PREFIX}return_to`));

    if (provider === "" || code === null || oauthState === null || flowId === null) {
      setState({ phase: "failed", reason: t(app.callbackMissingFlow) });
      return;
    }

    void (async () => {
      try {
        const login = await api.auth.finishOidc({ provider, flowId, code, state: oauthState });
        if (completeLogin(login)) {
          navigate(returnTo, { replace: true });
          return;
        }
        // `mfa_required`: the first factor passed but yields no tokens (S-05.a).
        // The second factor is collected on the sign-in screen, which owns that
        // step of the machine. The pending handle travels in the ROUTER STATE,
        // never the URL — it is a live credential, and a query string ends up
        // in history, in a referrer, and in the user's clipboard. `return_to`
        // is not a credential, so it stays a normal query parameter.
        navigate(`/login?return_to=${encodeURIComponent(returnTo)}`, {
          replace: true,
          state: { mfaToken: login.mfa_token },
        });
      } catch {
        setState({ phase: "failed", reason: t(app.genericError) });
      }
    })();
  });

  return (
    <div class="mx-auto flex w-full max-w-md flex-col gap-6 py-6">
      <Card>
        <Show
          when={state().phase === "failed" ? state() : null}
          fallback={
            <CardHeader class="flex-row items-center gap-3">
              <Spinner size="md" />
              <h1 class="text-lg font-semibold">{t(app.callbackTitle)}</h1>
            </CardHeader>
          }
        >
          {(failure) => (
            <>
              <CardHeader>
                <h1 class="text-2xl font-bold tracking-tight">{t(app.callbackFailed)}</h1>
              </CardHeader>
              <CardContent class="flex flex-col gap-5">
                <Alert intent="danger">
                  {failure().phase === "failed" ? (failure() as { reason: string }).reason : ""}
                </Alert>
                <A href="/login" class={buttonVariants({ intent: "outline", size: "md" })}>
                  {t(app.callbackBackToLogin)}
                </A>
              </CardContent>
            </>
          )}
        </Show>
      </Card>
    </div>
  );
}
