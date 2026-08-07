# Palette candidates

The three palette directions explored for the design foundation
(2026-08-07), kept as the repo record and as future-theme material:

- **`patina.css`** — warm graphite neutrals (hue 60–85 at whisper chroma),
  desaturated teal accent (hue 195). **Chosen** — its light/dark values are
  live in [`../theme.css`](../theme.css), which additionally carries the
  `amoled` true-black variant.
- **`iris.css`** — a refined evolution of the original indigo system
  (accent hue 278). Alternate; not applied.
- **`nocturne.css`** — cool night-blue grounds with a blurple accent
  (hues 268–288), dark theme leads. Alternate; not applied.

Each file is a complete drop-in for `theme.css` under the two-theme model it
was authored against: identical token names, radii, fonts, and semantic
mapping — only raw palette values differ, and all three pass the WCAG AA
contrast gate for their light and dark blocks. To promote one to a
registered theme instead of a replacement, lift its raw-palette blocks into
`theme.css` under a new `[data-theme="<name>"]` scope (see the THEME
REGISTRY note there); the gate discovers registered themes automatically.

Nothing imports these files; they are documentation-grade CSS.
