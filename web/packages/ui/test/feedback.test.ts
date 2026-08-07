import { describe, expect, test } from "bun:test";
import { feedback, ripple, sheen } from "@pub/ui/feedback";
import { Window } from "happy-dom";

/*
 * DOM contract of the interaction-feedback directives (web/DESIGN.md §5a,
 * decision 25). The visuals are CSS; what JS owes the DOM is pinned here:
 * the sheen feeds the gradient center through custom properties, the ripple
 * spawns one aria-hidden wave per press, fades it on release, and removes it
 * after the fade — with a timer fallback for reduced motion, where
 * `animation: none` means `animationend` never fires. Disabled hosts (native
 * `disabled`, `aria-disabled`, Kobalte `data-disabled`) spawn nothing.
 */

type Host = {
  readonly win: Window;
  readonly doc: Document;
  readonly host: HTMLElement;
};

function createHost(tag = "button"): Host {
  const win = new Window();
  // One boundary cast: the tests speak lib.dom, happy-dom implements it.
  const doc = win.document as unknown as Document;
  const host = doc.createElement(tag);
  doc.body.appendChild(host);
  return { win, doc, host };
}

/** happy-dom event classes structurally implement lib.dom events. */
function fire(target: EventTarget, event: unknown): void {
  target.dispatchEvent(event as Event);
}

function pointerDown(win: Window, target: EventTarget, x = 10, y = 5, button = 0): void {
  fire(
    target,
    new win.MouseEvent("pointerdown", { clientX: x, clientY: y, button, bubbles: true }),
  );
}

function fadeEnd(win: Window, wave: Element): void {
  const event = new win.Event("animationend");
  Object.assign(event, { animationName: "fx-ripple-fade" });
  fire(wave, event);
}

describe("sheen", () => {
  test("attaches the fx-sheen class to the host", () => {
    const { host } = createHost();
    sheen(host);
    expect(host.classList.contains("fx-sheen")).toBe(true);
  });

  test("pointermove feeds the gradient center through custom properties", () => {
    const { win, host } = createHost();
    sheen(host);
    fire(host, new win.MouseEvent("pointermove", { clientX: 12, clientY: 7 }));
    // happy-dom rects are all zeros, so the offset equals the client coords.
    expect(host.style.getPropertyValue("--fx-sheen-x")).toBe("12px");
    expect(host.style.getPropertyValue("--fx-sheen-y")).toBe("7px");
  });

  test("is a no-op on a disabled host", () => {
    const { win, host } = createHost();
    sheen(host);
    host.setAttribute("disabled", "");
    fire(host, new win.MouseEvent("pointermove", { clientX: 12, clientY: 7 }));
    expect(host.style.getPropertyValue("--fx-sheen-x")).toBe("");
  });
});

describe("ripple", () => {
  test("attaches the fx-ripple class to the host", () => {
    const { host } = createHost();
    ripple(host);
    expect(host.classList.contains("fx-ripple")).toBe(true);
  });

  test("pointerdown spawns one aria-hidden wave sized from the press point", () => {
    const { win, host } = createHost();
    ripple(host);
    pointerDown(win, host, 10, 5);
    const waves = host.querySelectorAll(".fx-ripple-wave");
    expect(waves.length).toBe(1);
    const wave = waves[0] as HTMLElement;
    expect(wave.getAttribute("aria-hidden")).toBe("true");
    // Zero rect ⇒ press point (10, 5) is the farthest-corner reference.
    const radius = Math.hypot(10, 5);
    expect(Number.parseFloat(wave.style.width)).toBeCloseTo(radius * 2);
    expect(Number.parseFloat(wave.style.height)).toBeCloseTo(radius * 2);
    expect(Number.parseFloat(wave.style.left)).toBeCloseTo(10 - radius);
    expect(Number.parseFloat(wave.style.top)).toBeCloseTo(5 - radius);
  });

  test("release fades the wave; the fade's animationend removes it", () => {
    const { win, doc, host } = createHost();
    ripple(host);
    pointerDown(win, host);
    const wave = host.querySelector(".fx-ripple-wave") as HTMLElement;
    expect(wave.classList.contains("fx-ripple-wave-out")).toBe(false);
    fire(doc, new win.Event("pointerup"));
    expect(wave.classList.contains("fx-ripple-wave-out")).toBe(true);
    fadeEnd(win, wave);
    expect(host.querySelector(".fx-ripple-wave")).toBeNull();
  });

  test("the grow animation ending does not remove the wave — only the fade does", () => {
    const { win, doc, host } = createHost();
    ripple(host);
    pointerDown(win, host);
    fire(doc, new win.Event("pointerup"));
    const wave = host.querySelector(".fx-ripple-wave") as HTMLElement;
    const event = new win.Event("animationend");
    Object.assign(event, { animationName: "fx-ripple-grow" });
    fire(wave, event);
    expect(host.querySelector(".fx-ripple-wave")).not.toBeNull();
  });

  test("without animationend the safety timer removes the wave (reduced motion)", async () => {
    // Under prefers-reduced-motion the global reset sets `animation: none`,
    // so no animation event ever fires — the timer is the cleanup then.
    const { win, doc, host } = createHost();
    ripple(host);
    pointerDown(win, host);
    fire(doc, new win.Event("pointerup"));
    await new Promise((resolve) => setTimeout(resolve, 450));
    expect(host.querySelector(".fx-ripple-wave")).toBeNull();
  });

  test("keyboard activation ripples from the center and fades on keyup", () => {
    const { win, host } = createHost();
    ripple(host);
    fire(host, new win.KeyboardEvent("keydown", { key: "Enter" }));
    const wave = host.querySelector(".fx-ripple-wave") as HTMLElement;
    expect(wave).not.toBeNull();
    // Zero rect ⇒ center is (0, 0).
    expect(Number.parseFloat(wave.style.width)).toBeCloseTo(0);
    fire(host, new win.KeyboardEvent("keyup", { key: "Enter" }));
    expect(wave.classList.contains("fx-ripple-wave-out")).toBe(true);
    fadeEnd(win, wave);
    expect(host.querySelector(".fx-ripple-wave")).toBeNull();
  });

  test("Space spawns a wave; other keys and key repeat do not", () => {
    const { win, host } = createHost();
    ripple(host);
    fire(host, new win.KeyboardEvent("keydown", { key: " " }));
    expect(host.querySelectorAll(".fx-ripple-wave").length).toBe(1);
    fire(host, new win.KeyboardEvent("keydown", { key: "a" }));
    expect(host.querySelectorAll(".fx-ripple-wave").length).toBe(1);
    fire(host, new win.KeyboardEvent("keydown", { key: "Enter", repeat: true }));
    expect(host.querySelectorAll(".fx-ripple-wave").length).toBe(1);
  });

  test("secondary pointer buttons spawn nothing", () => {
    const { win, host } = createHost();
    ripple(host);
    pointerDown(win, host, 10, 5, 2);
    expect(host.querySelector(".fx-ripple-wave")).toBeNull();
  });

  test.each([
    ["native disabled", "disabled", ""],
    ["aria-disabled", "aria-disabled", "true"],
    ["Kobalte data-disabled", "data-disabled", ""],
  ])("is a no-op on a disabled host (%s)", (_label, attribute, value) => {
    const { win, host } = createHost();
    ripple(host);
    host.setAttribute(attribute, value);
    pointerDown(win, host);
    fire(host, new win.KeyboardEvent("keydown", { key: "Enter" }));
    expect(host.querySelector(".fx-ripple-wave")).toBeNull();
  });

  test("a press on a nested control does not ripple the host row", () => {
    // A button inside a clickable row keeps its own feedback; the row must
    // not ripple underneath it.
    const { win, host } = createHost("tr");
    const inner = host.ownerDocument.createElement("button");
    host.appendChild(inner);
    ripple(host);
    pointerDown(win, inner);
    expect(host.querySelector(".fx-ripple-wave")).toBeNull();
    // Pressing the row itself still ripples.
    pointerDown(win, host);
    expect(host.querySelectorAll(".fx-ripple-wave").length).toBe(1);
  });

  test("keyboard events bubbling from a nested control do not ripple the host", () => {
    const { win, host } = createHost("tr");
    const inner = host.ownerDocument.createElement("button");
    host.appendChild(inner);
    ripple(host);
    fire(inner, new win.KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    expect(host.querySelector(".fx-ripple-wave")).toBeNull();
  });

  test("each press spawns its own wave — rapid presses stack", () => {
    const { win, doc, host } = createHost();
    ripple(host);
    pointerDown(win, host, 2, 2);
    fire(doc, new win.Event("pointerup"));
    pointerDown(win, host, 8, 3);
    expect(host.querySelectorAll(".fx-ripple-wave").length).toBe(2);
  });
});

describe("feedback", () => {
  test("wires both effects at once", () => {
    const { host } = createHost();
    feedback(host);
    expect(host.classList.contains("fx-sheen")).toBe(true);
    expect(host.classList.contains("fx-ripple")).toBe(true);
  });
});
