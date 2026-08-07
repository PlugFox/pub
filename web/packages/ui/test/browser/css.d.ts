/*
 * Side-effect CSS imports in browser tests (vite serves and injects them;
 * tsc only needs the module to resolve under `noUncheckedSideEffectImports`).
 */
declare module "*.css";
