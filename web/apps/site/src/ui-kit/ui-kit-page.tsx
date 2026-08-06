import { Badge } from "@pub/ui/badge";
import { Button, buttonVariants } from "@pub/ui/button";
import { Card, CardContent, CardFooter, CardHeader } from "@pub/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogTitle,
  DialogTrigger,
} from "@pub/ui/dialog";
import { Input } from "@pub/ui/input";
import { Label } from "@pub/ui/label";
import { Separator } from "@pub/ui/separator";
import { Skeleton } from "@pub/ui/skeleton";
import { ThemeToggle } from "@pub/ui/theme-toggle";
import { Tooltip, TooltipContent, TooltipTrigger } from "@pub/ui/tooltip";
import { For, type JSX } from "solid-js";

/*
 * Internal component showcase (/ui-kit, robots-disallowed). English-only by
 * design — this is a tool page for contributors, not a product screen.
 *
 * Registry pattern: every component in packages/ui adds one entry here
 * showing all variants, sizes, and states (docs/rules/web.md “Components”).
 * The page renders in both themes via the ThemeToggle in the header.
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
    name: "ThemeToggle",
    note: "Cycles light → dark → system; persists to localStorage (pub_theme).",
    render: () => <ThemeToggle />,
  },
];

export function UiKitPage(): JSX.Element {
  return (
    <div class="mx-auto w-full max-w-5xl px-6 py-12">
      <header class="flex items-start justify-between gap-4">
        <div>
          <h1 class="text-3xl font-bold tracking-tight">UI Kit</h1>
          <p class="mt-2 text-ink-muted">
            Internal showcase of <span class="font-mono text-sm">packages/ui</span> — every
            component, every state, both themes.
          </p>
        </div>
        <ThemeToggle />
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
