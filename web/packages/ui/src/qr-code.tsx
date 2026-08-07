import { createMemo, type JSX, splitProps } from "solid-js";
import { cn } from "./cn";
import { encodeQr } from "./qr-encode";

/**
 * Renders a payload as an SVG QR code, or nothing when it does not fit.
 *
 * One `<path>` of `M x y h1v1h-1z` sub-paths rather than one `<rect>` per
 * module: a version-7 code is 45×45 = 2025 modules, and 2000 DOM nodes on the
 * 2FA screen is a measurable hydration cost for a picture.
 *
 * Colors are `currentColor` on a transparent background so the code inherits
 * the surrounding theme — but a QR reader needs contrast, so callers place it
 * on a light surface in both themes (see the account screen: the code sits in
 * a white well, since a dark-on-dark QR is unscannable by most phone cameras).
 *
 * `fallback` renders when the payload exceeds the encoder's capacity; the
 * account screen passes the manual-entry panel there, so a too-long
 * `otpauth://` URL degrades to typing the secret rather than to a blank box.
 */

export type QrCodeProps = Omit<JSX.SvgSVGAttributes<SVGSVGElement>, "children"> & {
  /** Text to encode (the `otpauth://` provisioning URL). */
  readonly value: string;
  /** Accessible description of what the code contains. */
  readonly label: string;
  /** Quiet-zone width in modules; the spec requires at least 4. */
  readonly margin?: number;
  /** Rendered instead of the code when the payload is too long to encode. */
  readonly fallback?: JSX.Element;
};

export function QrCode(props: QrCodeProps): JSX.Element {
  const [local, rest] = splitProps(props, ["class", "value", "label", "margin", "fallback"]);

  const encoded = createMemo(() => {
    try {
      return encodeQr(local.value);
    } catch {
      return null;
    }
  });

  return (
    <>
      {encoded() === null
        ? local.fallback
        : (() => {
            const matrix = encoded();
            if (matrix === null) return null;
            const margin = local.margin ?? 4;
            const extent = matrix.size + margin * 2;
            let path = "";
            for (let y = 0; y < matrix.size; y += 1) {
              for (let x = 0; x < matrix.size; x += 1) {
                if (matrix.modules[y * matrix.size + x] === true) {
                  path += `M${x + margin} ${y + margin}h1v1h-1z`;
                }
              }
            }
            return (
              <svg
                {...rest}
                role="img"
                aria-label={local.label}
                viewBox={`0 0 ${extent} ${extent}`}
                shape-rendering="crispEdges"
                class={cn("size-48", local.class)}
              >
                <path d={path} fill="currentColor" />
              </svg>
            );
          })()}
    </>
  );
}
