import { Alert, AlertTitle } from "@pub/ui/alert";
import { Badge } from "@pub/ui/badge";
import { Button, buttonVariants } from "@pub/ui/button";
import { Card, CardContent, CardFooter, CardHeader } from "@pub/ui/card";
import { CopyButton } from "@pub/ui/copy-button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogTitle,
  DialogTrigger,
} from "@pub/ui/dialog";
import { EmptyState } from "@pub/ui/empty-state";
import { Input } from "@pub/ui/input";
import { Label } from "@pub/ui/label";
import {
  Menu,
  MenuContent,
  MenuItem,
  MenuLabel,
  MenuRadioGroup,
  MenuRadioItem,
  MenuSeparator,
  MenuTrigger,
} from "@pub/ui/menu";
import { Popover, PopoverContent, PopoverTrigger } from "@pub/ui/popover";
import { QrCode } from "@pub/ui/qr-code";
import { Separator } from "@pub/ui/separator";
import { Skeleton } from "@pub/ui/skeleton";
import { Spinner } from "@pub/ui/spinner";
import { Table, TableBody, TableCell, TableHead, TableHeaderCell, TableRow } from "@pub/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@pub/ui/tabs";
import { ThemePicker } from "@pub/ui/theme-picker";
import { Toast, ToastRegion } from "@pub/ui/toast";
import { Tooltip, TooltipContent, TooltipTrigger } from "@pub/ui/tooltip";
import { createSignal, For, type JSX } from "solid-js";

/*
 * Internal component showcase (/ui-kit, robots-disallowed). English-only by
 * design — this is a tool page for contributors, not a product screen.
 *
 * Registry pattern: every component in packages/ui adds one entry here
 * showing all variants, sizes, and states (docs/rules/web.md “Components”).
 * The page renders in every registered theme via the ThemePicker in the
 * header (light / dark / amoled + system).
 */

type ShowcaseEntry = {
  readonly name: string;
  readonly note: string;
  readonly render: () => JSX.Element;
};

const BUTTON_INTENTS = ["primary", "outline", "ghost", "danger"] as const;
const BUTTON_SIZES = ["sm", "md", "lg"] as const;
const BADGE_VARIANTS = ["neutral", "accent", "success", "warning", "danger"] as const;

const registry: readonly ShowcaseEntry[] = [
  {
    name: "Button",
    note: "Intents primary / outline / ghost / danger; sizes sm / md / lg; disabled state.",
    render: () => (
      <div class="flex flex-col gap-4">
        <For each={BUTTON_SIZES}>
          {(size) => (
            <div class="flex flex-wrap items-center gap-3">
              <For each={BUTTON_INTENTS}>
                {(intent) => (
                  <Button intent={intent} size={size}>
                    {intent} {size}
                  </Button>
                )}
              </For>
            </div>
          )}
        </For>
        <div class="flex flex-wrap items-center gap-3">
          <For each={BUTTON_INTENTS}>
            {(intent) => (
              <Button intent={intent} disabled>
                disabled
              </Button>
            )}
          </For>
        </div>
      </div>
    ),
  },
  {
    name: "Input & Label",
    note: "Sizes sm / md; placeholder, invalid (aria-invalid), and disabled states.",
    render: () => (
      <div class="grid w-full max-w-md gap-5">
        <div class="grid gap-1.5">
          <Label for="uikit-name">Package name</Label>
          <Input id="uikit-name" placeholder="my_package" />
        </div>
        <div class="grid gap-1.5">
          <Label for="uikit-sm">Small input</Label>
          <Input id="uikit-sm" size="sm" placeholder="0.1.0" />
        </div>
        <div class="grid gap-1.5">
          <Label for="uikit-invalid">Invalid</Label>
          <Input id="uikit-invalid" aria-invalid="true" value="not a version" />
        </div>
        <div class="grid gap-1.5">
          <Label for="uikit-disabled">Disabled</Label>
          <Input id="uikit-disabled" disabled value="read-only value" />
        </div>
      </div>
    ),
  },
  {
    name: "Card",
    note: "Header / content / footer slots; border, no shadow (static surface).",
    render: () => (
      <Card class="w-full max-w-md">
        <CardHeader>
          <h3 class="text-lg font-semibold">acme_design_system</h3>
          <p class="text-sm text-ink-muted">Shared widgets and tokens for Acme apps.</p>
        </CardHeader>
        <CardContent>
          <p class="font-mono text-sm text-ink-muted">v2.4.1 · sha256:9f86d081884c7d65</p>
        </CardContent>
        <CardFooter>
          <Button size="sm">Install</Button>
          <Button intent="ghost" size="sm">
            Changelog
          </Button>
        </CardFooter>
      </Card>
    ),
  },
  {
    name: "Badge",
    note: "Variants neutral / accent / success / warning / danger; soft tints only.",
    render: () => (
      <div class="flex flex-wrap items-center gap-3">
        <For each={BADGE_VARIANTS}>{(variant) => <Badge variant={variant}>{variant}</Badge>}</For>
        <Badge variant="accent" class="font-mono">
          v3.9.2
        </Badge>
      </div>
    ),
  },
  {
    name: "Skeleton",
    note: "Loading placeholders; caller sizes them to the content they replace.",
    render: () => (
      <div class="flex w-full max-w-md items-center gap-4">
        <Skeleton class="size-12 rounded-full" />
        <div class="flex flex-1 flex-col gap-2">
          <Skeleton class="h-4 w-3/5" />
          <Skeleton class="h-3 w-4/5" />
        </div>
      </div>
    ),
  },
  {
    name: "Separator",
    note: "Horizontal and vertical; always decorative (aria-hidden).",
    render: () => (
      <div class="flex w-full max-w-md flex-col gap-4">
        <p class="text-sm">Above</p>
        <Separator />
        <div class="flex h-6 items-center gap-4 text-sm">
          <span>pub.dev</span>
          <Separator orientation="vertical" />
          <span>proxy</span>
          <Separator orientation="vertical" />
          <span>mirror</span>
        </div>
      </div>
    ),
  },
  {
    name: "Dialog",
    note: "Kobalte-powered modal: focus trap, esc/overlay dismiss, portal + overlay.",
    render: () => (
      <Dialog>
        <DialogTrigger class={buttonVariants({ intent: "outline", size: "md" })}>
          Open dialog
        </DialogTrigger>
        <DialogContent>
          <DialogTitle>Retract version 1.2.3?</DialogTitle>
          <DialogDescription>
            The version stays downloadable but is excluded from new dependency resolutions. You can
            undo this within seven days.
          </DialogDescription>
          <div class="flex justify-end gap-3">
            <Button intent="ghost">Cancel</Button>
            <Button intent="danger">Retract</Button>
          </div>
        </DialogContent>
      </Dialog>
    ),
  },
  {
    name: "Tooltip",
    note: "Kobalte-powered; inverted surface, 300 ms open delay.",
    render: () => (
      <Tooltip>
        <TooltipTrigger class={buttonVariants({ intent: "outline", size: "md" })}>
          Hover me
        </TooltipTrigger>
        <TooltipContent>Published 2026-08-06 · 14 downloads</TooltipContent>
      </Tooltip>
    ),
  },
  {
    name: "ThemePicker",
    note: "Theme menu over the registry: system + light + dark + AMOLED radio items; persists to localStorage (pub_theme), stamps the resolved data-theme.",
    render: () => <ThemePicker />,
  },
  {
    name: "Alert",
    note: "Inline status block; intents info / success / warning / danger (danger renders role=alert).",
    render: () => (
      <div class="flex w-full max-w-lg flex-col gap-3">
        <For each={ALERT_INTENTS}>
          {(intent) => (
            <Alert intent={intent}>
              <div class="flex flex-col gap-1">
                <AlertTitle>{intent}</AlertTitle>
                <span>Retry-After: 42 s. The bucket refills on its own.</span>
              </div>
            </Alert>
          )}
        </For>
      </div>
    ),
  },
  {
    name: "Spinner",
    note: "Indeterminate busy indicator; sizes sm / md / lg, role=status with an accessible name.",
    render: () => (
      <div class="flex items-center gap-6">
        <For each={SPINNER_SIZES}>{(size) => <Spinner size={size} />}</For>
        <Button disabled>
          <Spinner />
          Publishing…
        </Button>
      </div>
    ),
  },
  {
    name: "Table",
    note: "Dense data surface; scrolls horizontally inside its own keyboard-reachable container.",
    render: () => (
      <Table label="Example tokens">
        <TableHead>
          <TableRow>
            <TableHeaderCell>Token</TableHeaderCell>
            <TableHeaderCell>Scopes</TableHeaderCell>
            <TableHeaderCell>Expires</TableHeaderCell>
          </TableRow>
        </TableHead>
        <TableBody>
          <For each={TABLE_ROWS}>
            {(row) => (
              <TableRow>
                <TableCell>
                  <div class="flex flex-col">
                    <span class="font-medium">{row.name}</span>
                    <span class="font-mono text-xs text-ink-muted">{row.hint}…</span>
                  </div>
                </TableCell>
                <TableCell>
                  <div class="flex gap-1">
                    <For each={row.scopes}>
                      {(scope) => (
                        <Badge
                          variant={scope === "publish" ? "warning" : "neutral"}
                          class="font-mono"
                        >
                          {scope}
                        </Badge>
                      )}
                    </For>
                  </div>
                </TableCell>
                <TableCell class="text-ink-muted">{row.expires}</TableCell>
              </TableRow>
            )}
          </For>
        </TableBody>
      </Table>
    ),
  },
  {
    name: "Tabs",
    note: "Kobalte-powered; roving focus, arrow-key navigation, animated underline indicator.",
    render: () => (
      <Tabs defaultValue="profile" class="w-full max-w-lg">
        <TabsList>
          <TabsTrigger value="profile">Profile</TabsTrigger>
          <TabsTrigger value="security">Security</TabsTrigger>
          <TabsTrigger value="disabled" disabled>
            Disabled
          </TabsTrigger>
        </TabsList>
        <TabsContent value="profile">
          <p class="text-sm text-ink-muted">Display name, email, member since.</p>
        </TabsContent>
        <TabsContent value="security">
          <p class="text-sm text-ink-muted">Two-factor authentication and recovery codes.</p>
        </TabsContent>
        <TabsContent value="disabled">unreachable</TabsContent>
      </Tabs>
    ),
  },
  {
    name: "Menu",
    note: "Kobalte dropdown: typeahead, roving focus, outside/escape dismissal; transient surface (shadow). MenuRadioGroup/MenuRadioItem for single-choice groups (menuitemradio + check indicator).",
    render: () => {
      const [sort, setSort] = createSignal("relevance");
      return (
        <div class="flex flex-wrap gap-3">
          <Menu>
            <MenuTrigger class={buttonVariants({ intent: "outline", size: "md" })}>
              Open menu
            </MenuTrigger>
            <MenuContent>
              <MenuLabel>ada@example.com</MenuLabel>
              <MenuItem>Account</MenuItem>
              <MenuItem>Sessions</MenuItem>
              <MenuSeparator />
              <MenuItem disabled>Admin (no permission)</MenuItem>
              <MenuItem>Sign out</MenuItem>
            </MenuContent>
          </Menu>
          <Menu>
            <MenuTrigger class={buttonVariants({ intent: "outline", size: "md" })}>
              Sort: {sort()}
            </MenuTrigger>
            <MenuContent>
              <MenuLabel>Sort by</MenuLabel>
              <MenuRadioGroup value={sort()} onChange={setSort}>
                <MenuRadioItem value="relevance">Relevance</MenuRadioItem>
                <MenuRadioItem value="updated">Recently updated</MenuRadioItem>
                <MenuRadioItem value="downloads">Downloads</MenuRadioItem>
              </MenuRadioGroup>
            </MenuContent>
          </Menu>
        </div>
      );
    },
  },
  {
    name: "Popover",
    note: "Click-opened panel that MAY hold headings, links, and copyable text — unlike Tooltip, which is a hover hint and holds none. Used for the search-syntax reference.",
    render: () => (
      <Popover>
        <PopoverTrigger class={buttonVariants({ intent: "outline", size: "md" })}>
          Search syntax
        </PopoverTrigger>
        <PopoverContent title="Search syntax">
          <dl class="flex flex-col gap-2">
            <div class="flex flex-col gap-0.5">
              <dt>
                <code class="rounded-sm bg-accent-soft px-1.5 py-0.5 font-mono text-xs text-accent">
                  org:acme
                </code>
              </dt>
              <dd class="text-xs text-ink-muted">Only packages owned by that organization.</dd>
            </div>
            <div class="flex flex-col gap-0.5">
              <dt>
                <code class="rounded-sm bg-accent-soft px-1.5 py-0.5 font-mono text-xs text-accent">
                  -is:discontinued
                </code>
              </dt>
              <dd class="text-xs text-ink-muted">A leading minus excludes matches.</dd>
            </div>
          </dl>
        </PopoverContent>
      </Popover>
    ),
  },
  {
    name: "Toast",
    note: "Transient message; the queue lives in the app store, this is the presentational half.",
    render: () => (
      <div class="flex w-full max-w-md flex-col gap-3">
        <For each={ALERT_INTENTS}>
          {(intent) => (
            <Toast intent={intent} onDismiss={() => undefined}>
              Token revoked.
            </Toast>
          )}
        </For>
        <p class="text-xs text-ink-muted">
          In the app these are stacked bottom-right by <span class="font-mono">ToastRegion</span>.
          The live region below holds one example.
        </p>
        <ToastRegionDemo />
      </div>
    ),
  },
  {
    name: "EmptyState",
    note: "Dashed hole in the layout with the action that fills it — never a dead end.",
    render: () => (
      <EmptyState
        class="w-full max-w-lg"
        title="No tokens yet"
        description="Create a token to publish packages or to let CI read your private registry."
      >
        <Button size="sm">New token</Button>
      </EmptyState>
    ),
  },
  {
    name: "CopyButton",
    note: "Copies a value and confirms in place for two seconds (clipboard denial is silent).",
    render: () => (
      <div class="flex w-full max-w-lg items-center gap-3">
        <code class="min-w-0 flex-1 overflow-x-auto rounded-lg border border-line bg-surface px-3 py-2 font-mono text-sm">
          dart pub token add https://pub.example.com/o/acme/pub
        </code>
        <CopyButton value="dart pub token add https://pub.example.com/o/acme/pub" />
      </div>
    ),
  },
  {
    name: "QrCode",
    note: "Dependency-free byte-mode QR (level M, versions 1–9); light well in BOTH themes so it stays scannable.",
    render: () => (
      <div class="flex flex-wrap items-start gap-6">
        <div class="w-fit rounded-xl border border-line bg-qr-surface p-4 text-qr-ink">
          <QrCode value={OTPAUTH_EXAMPLE} label="Example otpauth provisioning URL" />
        </div>
        <div class="w-fit rounded-xl border border-line bg-qr-surface p-4 text-qr-ink">
          <QrCode
            value={"x".repeat(400)}
            label="Payload too long"
            fallback={
              <p class="max-w-48 text-sm">Too long to encode — enter the secret manually.</p>
            }
          />
        </div>
      </div>
    ),
  },
];

const ALERT_INTENTS = ["info", "success", "warning", "danger"] as const;
const SPINNER_SIZES = ["sm", "md", "lg"] as const;
const OTPAUTH_EXAMPLE =
  "otpauth://totp/Pub:ada%40example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Pub";
const TABLE_ROWS = [
  {
    name: "CI — release pipeline",
    hint: "pub_9f86",
    scopes: ["read", "publish"],
    expires: "5 Nov 2026",
  },
  { name: "Local laptop", hint: "pub_2c26", scopes: ["read"], expires: "Never" },
] as const;

/** Live ToastRegion so the fixed positioning and live region can be inspected. */
function ToastRegionDemo(): JSX.Element {
  const [items, setItems] = createSignal([
    { id: 1, message: "Session revoked.", intent: "success" as const },
  ]);
  return (
    <>
      <Button
        size="sm"
        intent="outline"
        class="self-start"
        onClick={() =>
          setItems((current) =>
            current.length === 0 ? [{ id: 1, message: "Session revoked.", intent: "success" }] : [],
          )
        }
      >
        Toggle toast region
      </Button>
      <ToastRegion
        items={items()}
        label="Notifications"
        onDismiss={(id) => setItems((current) => current.filter((item) => item.id !== id))}
      />
    </>
  );
}

export function UiKitPage(): JSX.Element {
  return (
    <div class="mx-auto w-full max-w-5xl px-6 py-12">
      <header class="flex items-start justify-between gap-4">
        <div>
          <h1 class="text-3xl font-bold tracking-tight">UI Kit</h1>
          <p class="mt-2 text-ink-muted">
            Internal showcase of <span class="font-mono text-sm">packages/ui</span> — every
            component, every state, every theme.
          </p>
        </div>
        <ThemePicker />
      </header>
      <div class="mt-10 flex flex-col gap-10">
        <For each={registry}>
          {(entry) => (
            <section>
              <h2 class="text-xl font-semibold">{entry.name}</h2>
              <p class="mt-1 text-sm text-ink-muted">{entry.note}</p>
              <div class="mt-4 rounded-xl border border-line p-6">{entry.render()}</div>
            </section>
          )}
        </For>
      </div>
    </div>
  );
}
