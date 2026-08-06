import { describe, expect, test } from "bun:test";
import { cn } from "@pub/ui/cn";

describe("cn", () => {
  test("joins plain class lists", () => {
    expect(cn("a", "b")).toBe("a b");
  });

  test("drops falsy conditionals and flattens arrays", () => {
    expect(cn("a", false, undefined, null, ["b", { c: true, d: false }])).toBe("a b c");
  });

  test("later Tailwind utility wins a conflict (the class-prop contract)", () => {
    expect(cn("p-2", "p-4")).toBe("p-4");
    expect(cn("bg-accent", "bg-canvas")).toBe("bg-canvas");
  });

  test("non-conflicting utilities are all kept", () => {
    expect(cn("px-2", "py-4")).toBe("px-2 py-4");
    expect(cn("text-ink", "bg-canvas")).toBe("text-ink bg-canvas");
  });

  test("variant-conflicting utilities do not clobber base ones", () => {
    // hover:p-2 and p-4 target different states — both must survive.
    expect(cn("p-4", "hover:p-2")).toBe("p-4 hover:p-2");
  });

  test("empty input yields an empty string", () => {
    expect(cn()).toBe("");
  });
});
