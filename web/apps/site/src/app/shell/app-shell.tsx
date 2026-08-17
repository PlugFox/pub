import { t, tp } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { buttonVariants } from "@pub/ui/button";
import { cn } from "@pub/ui/cn";
import { Input } from "@pub/ui/input";
import { Menu, MenuContent, MenuItem, MenuLabel, MenuSeparator, MenuTrigger } from "@pub/ui/menu";
import { ThemePicker } from "@pub/ui/theme-picker";
import { ToastRegion } from "@pub/ui/toast";
import { A, createAsync, query, useLocation, useNavigate } from "@solidjs/router";
import { createEffect, ErrorBoundary, For, type JSX, onCleanup, Show, Suspense } from "solid-js";
import { api, seedUnreadCount, signOut } from "../state/api";
import { instanceName, primeInstance } from "../state/instance-store";
import { resetUnread, unreadCount } from "../state/notification-store";
import { currentUser, isAuthenticated } from "../state/session-store";
import { pauseEventStream, startEventStream, stopEventStream, streamStatus } from "../state/sse";
import { dismissToast, toasts } from "../state/toast-store";
import { createVisibilityPauser } from "../state/visibility";
import { StepUpDialog } from "./step-up-dialog";

/*
 * The app chrome: header (wordmark, search, org switcher, user menu) plus the
 * primary navigation, the toast region, and the one global step-up prompt.
 *
 * BRANDING (decision 17) comes from `GET /api/v1/home`. The shell primes that
 * query on mount — not the landing screen, which would leave every deep link
 * showing the product default for the rest of the session — and reads the
 * result out of `instance-store`. It never suspends on it: until the payload
 * lands the wordmark reads "Pub", which is the product default rather than a
 * placeholder, so there is nothing to show a skeleton for.
 *
 * THE EVENT STREAM'S LIFECYCLE LIVES HERE, in one effect keyed on
 * authentication plus one listener keyed on document visibility. It is the one
 * place that sees every transition — sign-in, sign-out, a refresh the server
 * refused (which clears the session store from an interceptor callback that has
 * no component around it), and a tab going away. Putting it in `state/api.ts`
 * instead would make the api module import the SSE module, which imports the
 * api module; putting the visibility half in `state/sse.ts` would make that
 * module reach for `seedUnreadCount` and close the same cycle.
 */

const orgsQuery = query(() => api.orgs.list(), "shell-orgs");

type NavEntry = {
  readonly href: string;
  readonly label: { readonly id: string; readonly en: string };
  /** Renders the unread badge next to the label. */
  readonly badge?: boolean;
};

const NAV: readonly NavEntry[] = [
  { href: "/", label: app.navOverview },
  { href: "/search", label: app.navSearch },
  { href: "/orgs", label: app.navOrgs },
  { href: "/tokens", label: app.navTokens },
  { href: "/sessions", label: app.navSessions },
  { href: "/notifications", label: app.navNotifications, badge: true },
  { href: "/account", label: app.navAccount },
  { href: "/admin", label: app.navAdmin },
];

function initials(name: string): string {
  const trimmed = name.trim();
  if (trimmed === "") return "?";
  return [...trimmed][0]?.toUpperCase() ?? "?";
}

function OrgSwitcher(): JSX.Element {
  const orgs = createAsync(() => orgsQuery());
  const navigate = useNavigate();
  return (
    <Menu>
      <MenuTrigger
        aria-label={t(app.orgSwitcher)}
        class={cn(buttonVariants({ intent: "outline", size: "sm" }), "max-w-40")}
      >
        <span class="truncate">{t(app.orgSwitcherAll)}</span>
        <svg aria-hidden="true" viewBox="0 0 16 16" class="size-3 shrink-0" fill="none">
          <path d="M4 6l4 4 4-4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
        </svg>
      </MenuTrigger>
      <MenuContent>
        <MenuLabel>{t(app.orgSwitcher)}</MenuLabel>
        <MenuItem onSelect={() => navigate("/orgs")}>{t(app.orgSwitcherAll)}</MenuItem>
        {/*
          A refused org list is a menu that cannot list organizations, not a
          shell that cannot render. Without this boundary the rejection escapes
          to the root one and takes the whole chrome with it — every screen,
          because the header is on all of them.
        */}
        <ErrorBoundary fallback={<MenuLabel>{t(app.genericError)}</MenuLabel>}>
          <Suspense>
            <For each={orgs()?.items ?? []}>
              {(membership) => (
                <MenuItem onSelect={() => navigate(`/orgs/${membership.org.slug}`)}>
                  <span class="truncate">{membership.org.name}</span>
                </MenuItem>
              )}
            </For>
          </Suspense>
        </ErrorBoundary>
      </MenuContent>
    </Menu>
  );
}

function UserMenu(): JSX.Element {
  const navigate = useNavigate();
  return (
    <Menu>
      <MenuTrigger
        aria-label={t(app.userMenu)}
        class={cn(
          "relative inline-flex size-8 cursor-pointer items-center justify-center rounded-full",
          "bg-accent-soft text-sm font-medium text-accent outline-none transition-colors",
          "hover:bg-accent hover:text-on-accent focus-visible:ring-2 focus-visible:ring-accent",
        )}
      >
        {initials(currentUser()?.display_name ?? currentUser()?.email ?? "?")}
      </MenuTrigger>
      <MenuContent>
        <MenuLabel>{currentUser()?.email ?? currentUser()?.display_name ?? ""}</MenuLabel>
        <MenuItem onSelect={() => navigate("/account")}>{t(app.navAccount)}</MenuItem>
        <MenuItem onSelect={() => navigate("/notifications")}>{t(app.navNotifications)}</MenuItem>
        <MenuSeparator />
        <MenuItem onSelect={() => void signOut().then(() => navigate("/login"))}>
          {t(app.signOut)}
        </MenuItem>
      </MenuContent>
    </Menu>
  );
}

function SearchField(): JSX.Element {
  const navigate = useNavigate();
  return (
    // No `role="search"`: the accessible name lives on the input, and the
    // landmark would duplicate the header's own navigation structure.
    <form
      class="hidden flex-1 sm:block sm:max-w-sm"
      onSubmit={(event) => {
        event.preventDefault();
        const data = new FormData(event.currentTarget);
        const value = String(data.get("q") ?? "").trim();
        navigate(value === "" ? "/search" : `/search?q=${encodeURIComponent(value)}`);
      }}
    >
      <Input
        type="search"
        name="q"
        size="sm"
        placeholder={t(app.searchPlaceholder)}
        aria-label={t(app.searchPlaceholder)}
      />
    </form>
  );
}

/** Unread count as a pill. Hidden at zero — an empty badge is noise. */
function UnreadBadge(): JSX.Element {
  return (
    <Show when={unreadCount() > 0}>
      <span
        class={cn(
          "ml-auto inline-flex min-w-5 shrink-0 items-center justify-center rounded-full",
          "bg-accent px-1.5 py-0.5 text-xs font-medium text-on-accent",
        )}
      >
        {/* The number is decorative next to the label the sr-only text spells out. */}
        <span aria-hidden="true">{unreadCount() > 99 ? "99+" : unreadCount()}</span>
        <span class="sr-only">{tp(app.notifUnreadCount, unreadCount())}</span>
      </span>
    </Show>
  );
}

function PrimaryNav(): JSX.Element {
  const location = useLocation();
  const isActive = (href: string): boolean =>
    href === "/" ? location.pathname === "/" : location.pathname.startsWith(href);
  return (
    <nav aria-label={t(app.navPrimary)} class="w-full">
      <ul class="flex gap-1 overflow-x-auto pb-2 lg:flex-col lg:overflow-visible lg:pb-0">
        <For each={NAV}>
          {(entry) => (
            <li class="shrink-0 lg:w-full">
              <A
                href={entry.href}
                aria-current={isActive(entry.href) ? "page" : undefined}
                class={cn(
                  "flex items-center gap-2 rounded-lg px-3 py-2 text-sm whitespace-nowrap",
                  "text-ink-muted transition-colors outline-none hover:bg-line/40 hover:text-ink",
                  "focus-visible:ring-2 focus-visible:ring-accent",
                  isActive(entry.href) && "bg-accent-soft font-medium text-accent",
                )}
              >
                {t(entry.label)}
                <Show when={entry.badge === true}>
                  <UnreadBadge />
                </Show>
              </A>
            </li>
          )}
        </For>
      </ul>
    </nav>
  );
}

export type AppShellProps = { readonly children?: JSX.Element };

export function AppShell(props: AppShellProps): JSX.Element {
  // The instance's identity is needed by the header on EVERY screen, so the
  // shell asks for it rather than the landing screen (decision 17). It does not
  // suspend on the answer: the wordmark's fallback is the product default.
  primeInstance();

  const accessToken = (): string | null => api.storage.read()?.accessToken ?? null;

  /*
   * The one repair the transport refuses to make itself.
   *
   * The server ends every stream at the access token's `exp` (S-32), and the
   * reconnect then presents whatever is in storage. On a tab with no REST
   * traffic that token is the expired one — the proactive refresh rides on
   * requests, and an idle tab makes none — so the reconnect is answered 401
   * and the transport stops, correctly: a loop against a revoked session is a
   * client turning its own logout into a denial of service. What was missing
   * is the other half. The refresh belongs to the api client, so the repair
   * belongs where both are reachable, and it is tried ONCE per healthy
   * connection: a session the server keeps refusing must not become a refresh
   * loop, which is the failure the transport's rule exists to prevent.
   */
  let repairAttempted = false;
  createEffect(() => {
    if (streamStatus() === "open") repairAttempted = false;
  });
  const repairStream = (): void => {
    if (repairAttempted || !isAuthenticated()) return;
    repairAttempted = true;
    void api
      .renewAuth()
      .catch(() => false)
      .then((renewed) => {
        if (!renewed) return;
        startEventStream(accessToken, repairStream);
        // The resume point died with the refused credential, so the badge is
        // re-read rather than replayed.
        void seedUnreadCount();
      });
  };

  // A tab nobody is looking at gives back its S-32 slot (decision 40): the cap
  // is five streams per account, and tabs are how a person reaches it. The
  // pause keeps the last event id, so the resume replays the gap — and re-seeds
  // the badge, because replay is bounded by the instance's ring buffer.
  const pauser = createVisibilityPauser({
    onPause: pauseEventStream,
    onResume: () => {
      if (!isAuthenticated()) return;
      startEventStream(accessToken, repairStream);
      void seedUnreadCount();
    },
  });
  const onVisibilityChange = (): void => pauser.changed(document.hidden);
  document.addEventListener("visibilitychange", onVisibilityChange);
  onCleanup(() => {
    document.removeEventListener("visibilitychange", onVisibilityChange);
    pauser.dispose();
  });

  // One subscription per session, torn down the moment the credential goes.
  createEffect(() => {
    if (isAuthenticated()) {
      // Not while paused: signing in on a hidden tab would take a slot the
      // visible one wants, and the resume path opens it anyway.
      if (!pauser.paused()) startEventStream(accessToken, repairStream);
      // Seed the badge from the server. The stream only reports what happens
      // from now on, so without this a reader who signs in with a full inbox
      // sees a blank badge until they open the feed — which is precisely the
      // trip the badge exists to save them.
      void seedUnreadCount();
    } else {
      stopEventStream();
      resetUnread();
    }
  });

  return (
    <div class="flex min-h-dvh flex-col">
      <a
        href="#app-main"
        class={cn(
          buttonVariants({ intent: "primary", size: "sm" }),
          "sr-only focus:not-sr-only focus:absolute focus:top-3 focus:left-3 focus:z-50",
        )}
      >
        {t(app.skipToContent)}
      </a>

      <header class="sticky top-0 z-30 border-b border-line bg-surface">
        <div class="mx-auto flex w-full max-w-6xl items-center gap-3 px-6 py-3">
          <A href="/" class="flex shrink-0 items-center gap-2 font-semibold text-ink">
            <img src="/icons/icon.svg" alt="" class="size-6" />
            <span class="hidden sm:inline">{instanceName()}</span>
          </A>
          <SearchField />
          <div class="ml-auto flex items-center gap-2">
            {/*
              The theme picker lives in the header for both branches: it is a
              menu of its own now, and a menu nested inside the user menu
              would fight its parent over focus and dismissal.
            */}
            <ThemePicker />
            <Show
              when={isAuthenticated()}
              fallback={
                <A href="/login" class={buttonVariants({ intent: "outline", size: "sm" })}>
                  {t(app.loginTitle)}
                </A>
              }
            >
              <OrgSwitcher />
              <UserMenu />
            </Show>
          </div>
        </div>
      </header>

      <div class="mx-auto flex w-full max-w-6xl flex-1 flex-col gap-6 px-6 py-6 lg:flex-row lg:gap-10 lg:py-12">
        <Show when={isAuthenticated()}>
          <aside class="lg:w-52 lg:shrink-0">
            <PrimaryNav />
          </aside>
        </Show>
        <main id="app-main" class="min-w-0 flex-1">
          {props.children}
        </main>
      </div>

      <ToastRegion items={toasts()} onDismiss={dismissToast} label={t(app.toasts)} />
      <StepUpDialog />
    </div>
  );
}
