import { describe, expect, test } from "bun:test";
import { badgeVariants } from "@pub/ui/badge";
import { buttonVariants } from "@pub/ui/button";
import { inputVariants } from "@pub/ui/input";
import { separatorVariants } from "@pub/ui/separator";

describe("buttonVariants", () => {
  test("defaults to primary/md", () => {
    const classes = buttonVariants();
    expect(classes).toContain("bg-accent");
    expect(classes).toContain("text-on-accent");
    expect(classes).toContain("h-10");
  });

  test("every intent maps to its fill/text pair", () => {
    expect(buttonVariants({ intent: "primary" })).toContain("bg-accent");
    expect(buttonVariants({ intent: "ghost" })).toContain("bg-transparent");
    expect(buttonVariants({ intent: "outline" })).toContain("border-line");
    expect(buttonVariants({ intent: "danger" })).toContain("bg-danger");
    expect(buttonVariants({ intent: "danger" })).toContain("text-on-danger");
  });

  test("sizes set distinct heights", () => {
    expect(buttonVariants({ size: "sm" })).toContain("h-8");
    expect(buttonVariants({ size: "md" })).toContain("h-10");
    expect(buttonVariants({ size: "lg" })).toContain("h-12");
  });

  test("base classes carry the focus ring and disabled handling", () => {
    const classes = buttonVariants();
    expect(classes).toContain("focus-visible:ring-2");
    expect(classes).toContain("disabled:pointer-events-none");
  });
});

describe("badgeVariants", () => {
  test("defaults to neutral", () => {
    expect(badgeVariants()).toContain("bg-canvas");
  });

  test("status variants pair soft backgrounds with their AA ink tokens", () => {
    expect(badgeVariants({ variant: "accent" })).toContain("bg-accent-soft");
    expect(badgeVariants({ variant: "accent" })).toContain("text-accent");
    expect(badgeVariants({ variant: "success" })).toContain("bg-success-soft");
    expect(badgeVariants({ variant: "success" })).toContain("text-success-ink");
    expect(badgeVariants({ variant: "warning" })).toContain("bg-warning-soft");
    expect(badgeVariants({ variant: "warning" })).toContain("text-warning-ink");
    expect(badgeVariants({ variant: "danger" })).toContain("bg-danger-soft");
    expect(badgeVariants({ variant: "danger" })).toContain("text-danger-ink");
  });

  test("never uses solid status fills (those belong to buttons)", () => {
    for (const variant of ["accent", "success", "warning", "danger"] as const) {
      const classes = badgeVariants({ variant }).split(" ");
      expect(classes).not.toContain("bg-accent");
      expect(classes).not.toContain(`bg-${variant}`);
    }
  });
});

describe("inputVariants", () => {
  test("defaults to md height with aria-invalid danger styling", () => {
    const classes = inputVariants();
    expect(classes).toContain("h-10");
    expect(classes).toContain("aria-invalid:border-danger");
  });

  test("sm variant shrinks the control", () => {
    expect(inputVariants({ size: "sm" })).toContain("h-8");
  });
});

describe("separatorVariants", () => {
  test("horizontal is a full-width hairline, vertical stretches", () => {
    expect(separatorVariants({ orientation: "horizontal" })).toContain("h-px");
    expect(separatorVariants({ orientation: "vertical" })).toContain("w-px");
  });
});
