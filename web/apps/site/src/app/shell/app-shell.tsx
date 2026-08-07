import { t } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { common } from "@pub/i18n/generated/common";
import { buttonVariants } from "@pub/ui/button";
import { cn } from "@pub/ui/cn";
import { Input } from "@pub/ui/input";
import { Menu, MenuContent, MenuItem, MenuLabel, MenuSeparator, MenuTrigger } from "@pub/ui/menu";
import { ThemeToggle } from "@pub/ui/theme-toggle";
import { ToastRegion } from "@pub/ui/toast";
import { A, createAsync, query, useLocation, useNavigate } from "@solidjs/router";
import { For, type JSX, Show, Suspense } from "solid-js";
import { api, signOut } from "../state/api";
import { currentUser, isAuthenticated } from "../state/session-store";
import { dismissToast, toasts } from "../state/toast-store";
import { StepUpDialog } from "./step-up-dialog";

/*
 * The app chrome: header (wordmark, search, org switcher, user menu) plus the
 * primary navigation, the toast region, and the one global step-up prompt.
 *
 * BRANDING (decision 17): instances rebrand the wordmark, logo, and accent at
 * runtime through admin settings. This constant is the product default and is
 * a KNOWN STUB — a white-labelled instance still reads "Pub" in the app
 * header. The instance identity now exists on the wire as `InstanceDto`
 * (`name`, `logo_url`, `primary_color`) inside `GET /api/v1/home`; wiring it
 * here is a follow-up, not a missing endpoint.
 */
const INSTANCE_NAME = "Pub";

const orgsQuery = query(() => api.orgs.list(), "shell-orgs");

type NavEntry = {
  readonly href: string;
  readonly label: { readonly id: string; readonly en: string };
  /** Areas whose backend does not exist yet are still linked, but marked. */
  readonly placeholder?: boolean;
};

const NAV: readonly NavEntry[] = [
  { href: "/", label: app.navOverview },
  { href: "/packages", label: app.navPackages, placeholder: true },
  { href: "/search", label: app.navSearch, placeholder: true },
  { href: "/orgs", label: app.navOrgs },
  { href: "/tokens", label: app.navTokens },
  { href: "/sessions", label: app.navSessions },
  { href: "/notifications", label: app.navNotifications, placeholder: true },
  { href: "/account", label: app.navAccount },
  { href: "/admin", label: app.navAdmin, placeholder: true },
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
        <Suspense>
          <For each={orgs()?.items ?? []}>
            {(membership) => (
              <MenuItem onSelect={() => navigate(`/orgs/${membership.org.slug}`)}>
                <span class="truncate">{membership.org.name}</span>
              </MenuItem>
            )}
          </For>
        </Suspense>
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
          "inline-flex size-8 cursor-pointer items-center justify-center rounded-full",
          "bg-accent-soft text-sm font-medium text-accent outline-none transition-colors",
          "hover:bg-accent hover:text-on-accent focus-visible:ring-2 focus-visible:ring-accent",
        )}
      >
        {initials(currentUser()?.display_name ?? currentUser()?.email ?? "?")}
      </MenuTrigger>
      <MenuContent>
        <MenuLabel>{currentUser()?.email ?? currentUser()?.display_name ?? ""}</MenuLabel>
        <MenuItem onSelect={() => navigate("/account")}>{t(app.navAccount)}</MenuItem>
        <MenuSeparator />
        {/*
          The theme toggle sits INSIDE the menu item rather than being one:
          selecting a menu item closes the menu, and a theme switcher you have
          to reopen for every step of light → dark → system is a broken cycle.
        */}
        <div class="flex items-center justify-between gap-3 px-3 py-2 text-sm">
          <span>{t(common.themeToggle)}</span>
          <ThemeToggle />
        </div>
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

function PrimaryNav(): JSX.Element {
  const location = useLocation();
  const isActive = (href: string): boolean =>
    href === "/" ? location.pathname === "/" : location.pathname.startsWith(href);
  return (
    <nav aria-label={t(app.navPrimary)} class="w-full">
      <ul class="flex gap-1 overflow-x-auto pb-2 lg:flex-col lg:overflow-visible lg:pb-0">
        <For each={NAV}>
          {(entry) => (
            <li class="shrink-0">
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
                <Show when={entry.placeholder === true}>
                  {/*
                    The dot is a hover hint for sighted users; a screen reader
                    gets the same fact as text, or "coming soon" would be
                    information only one kind of user receives.
                  */}
                  <span
                    aria-hidden="true"
                    class="size-1.5 shrink-0 rounded-full bg-warning"
                    title={t(app.comingSoon)}
                  />
                  <span class="sr-only">{t(app.comingSoon)}</span>
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
            <span class="hidden sm:inline">{INSTANCE_NAME}</span>
          </A>
          <SearchField />
          <div class="ml-auto flex items-center gap-2">
            <Show when={isAuthenticated()} fallback={<ThemeToggle />}>
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
