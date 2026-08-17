import { describe, expect, test } from "bun:test";
import type { DistReader } from "../scripts/precache";
import { collectPrecache, PrecacheError } from "../scripts/precache";

/*
 * The precache manifest computed from the emitted build (decision 41).
 *
 * This is the piece D17 was actually about: the shell's eager graph is fifteen
 * content-hashed modules plus a stylesheet, none of which a committed file can
 * name. A generator that silently returned a short list would produce a green
 * build and the same blank offline page — so the refusals are asserted as
 * carefully as the closure is.
 */

/** A build described as a plain object; missing keys are missing files. */
function reader(files: Record<string, string>): DistReader {
  return {
    exists: (file) => Object.hasOwn(files, file),
    read: (file) => files[file] ?? null,
  };
}

const SHELL = { url: "/app/", file: "app/index.html" };

describe("the eager closure", () => {
  test("follows static imports transitively and stops at dynamic ones", () => {
    const manifest = collectPrecache(
      reader({
        "app/index.html":
          '<link rel="stylesheet" href="/_astro/base.css">' +
          '<script type="module" src="/_astro/App.js"></script>',
        "_astro/base.css": ".a{color:red}",
        "_astro/App.js": 'import{a}from"./core.js";import"./side.js";import("./screen.js")',
        "_astro/core.js": 'export*from"./deep.js"',
        "_astro/deep.js": "export const x=1",
        "_astro/side.js": "console.log(1)",
        // Present in the build, reachable only through `import(…)` — the route
        // splitting the app's `lazy()` entries exist for.
        "_astro/screen.js": "export const Screen=1",
      }),
      [SHELL],
    );

    expect(manifest).toEqual([
      "/_astro/App.js",
      "/_astro/base.css",
      "/_astro/core.js",
      "/_astro/deep.js",
      "/_astro/side.js",
      "/app/",
    ]);
    expect(manifest).not.toContain("/_astro/screen.js");
  });

  test("a modulepreload hint and a preloaded font are collected like anything else", () => {
    const manifest = collectPrecache(
      reader({
        "app/index.html":
          '<link rel="modulepreload" href="/_astro/client.js">' +
          '<link rel="preload" href="/_astro/inter.woff2" as="font" crossorigin>',
        "_astro/client.js": "export const c=1",
        "_astro/inter.woff2": "binary-ish",
      }),
      [SHELL],
    );

    expect(manifest).toContain("/_astro/client.js");
    expect(manifest).toContain("/_astro/inter.woff2");
  });

  test("a cycle between chunks terminates", () => {
    const manifest = collectPrecache(
      reader({
        "app/index.html": '<script type="module" src="/_astro/a.js"></script>',
        "_astro/a.js": 'from"./b.js"',
        "_astro/b.js": 'from"./a.js"',
      }),
      [SHELL],
    );

    expect(manifest).toEqual(["/_astro/a.js", "/_astro/b.js", "/app/"]);
  });

  test("a reference to a file that is not in the build is dropped, not fatal", () => {
    // The pattern reads inline island payloads as well as attributes, so a
    // string that merely looks like an asset URL must not fail a good build.
    const manifest = collectPrecache(
      reader({
        "app/index.html":
          '<script type="module" src="/_astro/App.js"></script>' +
          '<astro-island props=\'{"href":"/_astro/imaginary.js"}\'></astro-island>',
        "_astro/App.js": "export const a=1",
      }),
      [SHELL],
    );

    expect(manifest).toEqual(["/_astro/App.js", "/app/"]);
  });

  test("documents share chunks without duplicating them, and the list is sorted", () => {
    const manifest = collectPrecache(
      reader({
        "index.html": '<script type="module" src="/_astro/shared.js"></script>',
        "app/index.html":
          '<script type="module" src="/_astro/shared.js"></script>' +
          '<script type="module" src="/_astro/App.js"></script>',
        "_astro/shared.js": "export const s=1",
        "_astro/App.js": "export const a=1",
      }),
      [{ url: "/", file: "index.html" }, SHELL],
      ["/manifest.webmanifest"],
    );

    expect(manifest).toEqual([
      "/",
      "/_astro/App.js",
      "/_astro/shared.js",
      "/app/",
      "/manifest.webmanifest",
    ]);
  });
});

describe("what the generator refuses to ship", () => {
  test("a missing document fails the build", () => {
    expect(() => collectPrecache(reader({}), [SHELL])).toThrow(PrecacheError);
  });

  test("a document that references no hashed asset fails the build", () => {
    // The exact shape of the failure this item exists to fix: a cached
    // document whose stylesheet and island are not cached with it.
    expect(() =>
      collectPrecache(reader({ "app/index.html": "<html><body>hello</body></html>" }), [SHELL]),
    ).toThrow(PrecacheError);
  });

  test("a document whose only references are absent from the build fails too", () => {
    expect(() =>
      collectPrecache(
        reader({ "app/index.html": '<script type="module" src="/_astro/gone.js"></script>' }),
        [SHELL],
      ),
    ).toThrow(PrecacheError);
  });
});
