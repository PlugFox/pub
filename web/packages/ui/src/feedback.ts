import "solid-js";

/*
 * Interaction feedback directives — the two sanctioned dynamic effects
 * (web/DESIGN.md §5a, decision 25): `sheen`, a pointer-tracking specular
 * highlight on hover (every control), and `ripple`, a pointer-origin press
 * wave (genuinely interactive controls only). The visuals live entirely in
 * feedback.css; this module only tracks coordinates and manages the wave
 * lifecycle, so there is no motion media check in JS — the global unlayered
 * reduced-motion reset collapses both effects in CSS (§7a).
 *
 * Both functions have the Solid directive signature (`use:sheen`,
 * `use:ripple`); kit components attach them through `ref` callbacks instead
 * because a `use:` attribute is invisible to `noUnusedLocals` and Biome's
 * unused-import lint. The recipes also carry the `fx-*` classes statically so
 * a reactive `class` update cannot clobber them and server-rendered markup
 * shows the (center-anchored) sheen before hydration; the classList.add here
 * covers hosts that only apply the directive.
 */

declare module "solid-js" {
  namespace JSX {
    interface Directives {
      /** Pointer-tracking specular hover highlight — for all controls. */
      sheen: true;
      /** Pointer-origin press wave — for press-activated controls only. */
      ripple: true;
    }
  }
}

/**
 * The fade animation runs 250 ms (feedback.css); the timer is the wave's
 * cleanup of last resort for when `animationend` never fires — exactly what
 * happens under `prefers-reduced-motion`, where the global reset sets
 * `animation: none` and the wave stays invisible from spawn to removal.
 */
const WAVE_FADE_SAFETY_MS = 400;

/** Selector for controls whose own press feedback outranks the host's. */
const NESTED_CONTROLS = "a,button,input,select,textarea,[tabindex]";

function isDisabled(el: HTMLElement): boolean {
  return (
    (el as HTMLElement & { readonly disabled?: boolean }).disabled === true ||
    el.getAttribute("aria-disabled") === "true" ||
    el.hasAttribute("data-disabled")
  );
}

/** True when the event entered through an interactive descendant of `el`
 * (a button inside a clickable row must not ripple the row too). */
function throughNestedControl(el: HTMLElement, target: EventTarget | null): boolean {
  const node = target as Element | null;
  const control = node?.closest?.(NESTED_CONTROLS) ?? null;
  return control !== null && control !== el && el.contains(control);
}

/**
 * `use:sheen` — liquid-glass specular highlight following the pointer.
 * CSS shows it on hover only (`@media (hover: hover)`); this handler merely
 * feeds the gradient center. Without JS (or before hydration) the highlight
 * falls back to the element's center.
 */
export function sheen(el: HTMLElement, _value?: () => true): void {
  el.classList.add("fx-sheen");
  el.addEventListener("pointermove", (event: PointerEvent) => {
    if (isDisabled(el)) return;
    const rect = el.getBoundingClientRect();
    el.style.setProperty("--fx-sheen-x", `${event.clientX - rect.left}px`);
    el.style.setProperty("--fx-sheen-y", `${event.clientY - rect.top}px`);
  });
}

/**
 * `use:ripple` — press wave expanding from the pointer (or from the center
 * for keyboard activation), fading on release. Disabled hosts (native
 * `disabled`, `aria-disabled`, Kobalte `data-disabled`) spawn nothing.
 */
export function ripple(el: HTMLElement, _value?: () => true): void {
  el.classList.add("fx-ripple");

  const spawn = (x: number, y: number, awaitRelease: (onRelease: () => void) => void): void => {
    const rect = el.getBoundingClientRect();
    // The wave must cover the host from its origin: radius to farthest corner.
    const radius = Math.hypot(Math.max(x, rect.width - x), Math.max(y, rect.height - y));
    const wave = el.ownerDocument.createElement("span");
    wave.className = "fx-ripple-wave";
    wave.setAttribute("aria-hidden", "true");
    wave.style.width = `${radius * 2}px`;
    wave.style.height = `${radius * 2}px`;
    wave.style.left = `${x - radius}px`;
    wave.style.top = `${y - radius}px`;
    el.append(wave);
    awaitRelease(() => {
      wave.classList.add("fx-ripple-wave-out");
      wave.addEventListener("animationend", (event: AnimationEvent) => {
        if (event.animationName === "fx-ripple-fade") wave.remove();
      });
      setTimeout(() => wave.remove(), WAVE_FADE_SAFETY_MS);
    });
  };

  el.addEventListener("pointerdown", (event: PointerEvent) => {
    if (event.button !== 0 || isDisabled(el)) return;
    if (throughNestedControl(el, event.target)) return;
    const rect = el.getBoundingClientRect();
    spawn(event.clientX - rect.left, event.clientY - rect.top, (onRelease) => {
      // The press may end anywhere on the page, so release listens on the
      // document; AbortController drops whichever listener did not fire.
      const doc = el.ownerDocument;
      const controller = new AbortController();
      const release = (): void => {
        controller.abort();
        onRelease();
      };
      doc.addEventListener("pointerup", release, { signal: controller.signal });
      doc.addEventListener("pointercancel", release, { signal: controller.signal });
    });
  });

  el.addEventListener("keydown", (event: KeyboardEvent) => {
    if (event.repeat || (event.key !== "Enter" && event.key !== " ")) return;
    if (event.target !== el || isDisabled(el)) return;
    const rect = el.getBoundingClientRect();
    spawn(rect.width / 2, rect.height / 2, (onRelease) => {
      const controller = new AbortController();
      const release = (): void => {
        controller.abort();
        onRelease();
      };
      el.addEventListener("keyup", release, { signal: controller.signal });
      el.addEventListener("blur", release, { signal: controller.signal });
    });
  });
}

/** Both effects at once — the wiring every press-activated control uses. */
export function feedback(el: HTMLElement): void {
  sheen(el);
  ripple(el);
}
