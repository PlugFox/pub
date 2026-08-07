import "@pub/ui/feedback.css";
import { Button } from "@pub/ui/button";
import type { JSX } from "solid-js";
import { render } from "solid-js/web";
import { afterEach, describe, expect, test } from "vitest";
import { userEvent } from "vitest/browser";

/*
 * The interaction-feedback layer in a REAL browser — the half the happy-dom
 * suite (test/feedback.test.ts) cannot honestly cover: actual layout
 * geometry feeding the wave size, the CSS animations from feedback.css
 * really running, `:hover` behind `@media (hover: hover)`, and the full
 * spawn → fade → removal lifecycle driven by trusted input events.
 */

let dispose: (() => void) | null = null;
let container: HTMLDivElement | null = null;

function mount(ui: () => JSX.Element): HTMLElement {
  container = document.createElement("div");
  document.body.append(container);
  dispose = render(ui, container);
  return container;
}

afterEach(() => {
  dispose?.();
  dispose = null;
  container?.remove();
  container = null;
});

function must<T>(value: T | null | undefined, what: string): T {
  if (value === null || value === undefined) throw new Error(`expected ${what}`);
  return value;
}

/** CSS animation names currently running on the element (and pseudo-elements
 * with `subtree`) — real-browser ground truth happy-dom has no equivalent of. */
function animationNames(el: Element, options?: { readonly subtree: boolean }): readonly string[] {
  return el
    .getAnimations({ subtree: options?.subtree ?? false })
    .map((animation) => (animation as CSSAnimation).animationName);
}

function pointerDownAt(el: HTMLElement, x: number, y: number): void {
  const rect = el.getBoundingClientRect();
  el.dispatchEvent(
    new PointerEvent("pointerdown", {
      clientX: rect.left + x,
      clientY: rect.top + y,
      button: 0,
      bubbles: true,
    }),
  );
}

describe("ripple on Button (real browser)", () => {
  test("pointerdown appends an aria-hidden wave covering the real layout, grow animation running", () => {
    const root = mount(() => <Button>Press</Button>);
    const button = must(root.querySelector("button"), "button");
    const rect = button.getBoundingClientRect();
    expect(rect.width).toBeGreaterThan(0); // real layout, unlike happy-dom's zero rects
    const x = 10;
    const y = 8;
    pointerDownAt(button, x, y);
    const wave = must(button.querySelector<HTMLElement>(".fx-ripple-wave"), "ripple wave");
    expect(wave.getAttribute("aria-hidden")).toBe("true");
    // The wave must reach the farthest corner of the button from the press point.
    const radius = Math.hypot(Math.max(x, rect.width - x), Math.max(y, rect.height - y));
    expect(Number.parseFloat(wave.style.width)).toBeCloseTo(radius * 2, 3);
    expect(Number.parseFloat(wave.style.height)).toBeCloseTo(radius * 2, 3);
    // feedback.css is genuinely applied: the grow keyframes are running.
    expect(animationNames(wave)).toContain("fx-ripple-grow");
  });

  test("release starts the real fade animation and the wave is removed after it", async () => {
    const root = mount(() => <Button>Press</Button>);
    const button = must(root.querySelector("button"), "button");
    pointerDownAt(button, 10, 8);
    const wave = must(button.querySelector<HTMLElement>(".fx-ripple-wave"), "ripple wave");
    expect(wave.classList.contains("fx-ripple-wave-out")).toBe(false);
    document.dispatchEvent(new PointerEvent("pointerup", { bubbles: true }));
    expect(wave.classList.contains("fx-ripple-wave-out")).toBe(true);
    expect(animationNames(wave)).toContain("fx-ripple-fade");
    // Removed on the fade's `animationend` (timer fallback exists, but here
    // the animation really runs). Polling, no arbitrary sleeps.
    await expect.poll(() => button.querySelector(".fx-ripple-wave")).toBeNull();
  });

  test("a real click drives the full lifecycle: spawn, fade, removal", async () => {
    const root = mount(() => <Button>Press me</Button>);
    const button = must(root.querySelector("button"), "button");
    let spawned = 0;
    const observer = new MutationObserver((records) => {
      for (const record of records) {
        for (const node of record.addedNodes) {
          if (node instanceof HTMLElement && node.classList.contains("fx-ripple-wave")) {
            spawned += 1;
          }
        }
      }
    });
    observer.observe(button, { childList: true });
    // Trusted input through the playwright provider — not a synthetic event.
    await userEvent.click(button);
    await expect.poll(() => spawned).toBe(1);
    await expect.poll(() => button.querySelector(".fx-ripple-wave")).toBeNull();
    observer.disconnect();
  });

  test("a disabled button spawns nothing for pointer or keyboard", () => {
    const root = mount(() => <Button disabled>Nope</Button>);
    const button = must(root.querySelector("button"), "button");
    pointerDownAt(button, 5, 5);
    button.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    expect(button.querySelector(".fx-ripple-wave")).toBeNull();
  });
});

describe("sheen on Button (real browser)", () => {
  test("hovering runs the sheen animation on the overlay and feeds the gradient center", async () => {
    const root = mount(() => <Button>Hover</Button>);
    const button = must(root.querySelector("button"), "button");
    // Real `:hover` behind `@media (hover: hover)` — untestable in happy-dom.
    await userEvent.hover(button);
    await expect.poll(() => animationNames(button, { subtree: true })).toContain("fx-sheen-in");
    // The pointermove that came with the hover fed the gradient center.
    expect(button.style.getPropertyValue("--fx-sheen-x")).not.toBe("");
    expect(button.style.getPropertyValue("--fx-sheen-y")).not.toBe("");
  });
});
