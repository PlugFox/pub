import { describe, expect, test } from "bun:test";
import {
  DEFAULT_PACKAGE_TAB,
  PACKAGE_TABS,
  packageTabPath,
  readPackageTab,
} from "../src/app/package-tabs";
import { packagePath, packageVersionPath, pubspecSnippet } from "../src/app/urls";

/*
 * Package-page routing.
 *
 * The tab is a path segment, so these functions decide what a pasted link
 * opens. The canonical-URL property (the default tab has NO segment) matters
 * because otherwise `/packages/http` and `/packages/http/readme` would be two
 * addresses for one page, which is a bug that only shows up in analytics and
 * in the back button.
 */

describe("readPackageTab", () => {
  test("no segment means the default tab", () => {
    expect(readPackageTab(undefined)).toBe(DEFAULT_PACKAGE_TAB);
    expect(readPackageTab("")).toBe(DEFAULT_PACKAGE_TAB);
  });

  test.each([...PACKAGE_TABS])("recognizes %s", (tab) => {
    expect(readPackageTab(tab)).toBe(tab);
  });

  test.each(["nope", "READ", "readme/", "../admin", "versions.json"])(
    "an unknown segment %p falls back to the default instead of 404-ing",
    (raw) => {
      // The package exists; showing it beats "not found" for a name that resolves.
      expect(readPackageTab(raw)).toBe(DEFAULT_PACKAGE_TAB);
    },
  );
});

describe("packageTabPath", () => {
  test("the default tab has no segment — one URL per page", () => {
    expect(packageTabPath("http", "readme")).toBe("/packages/http");
    expect(packagePath("http")).toBe("/packages/http");
  });

  test.each([...PACKAGE_TABS].filter((tab) => tab !== DEFAULT_PACKAGE_TAB))(
    "%s is addressable",
    (tab) => {
      expect(packageTabPath("http", tab)).toBe(`/packages/http/${tab}`);
    },
  );

  test("round-trips through readPackageTab for every tab", () => {
    for (const tab of PACKAGE_TABS) {
      const path = packageTabPath("http", tab);
      const segment = path.split("/")[3];
      expect(readPackageTab(segment)).toBe(tab);
    }
  });

  test("package names are percent-encoded", () => {
    // Pub names are `[a-z0-9_]+`, but the router hands us whatever is in the
    // URL bar, and an unencoded segment could change the route shape.
    expect(packageTabPath("a/b", "versions")).toBe("/packages/a%2Fb/versions");
  });
});

describe("version deep links", () => {
  test("point at the version under the package", () => {
    expect(packageVersionPath("http", "1.2.0")).toBe("/packages/http/versions/1.2.0");
  });

  test("encode a version with build metadata", () => {
    expect(packageVersionPath("http", "1.0.0+1")).toBe("/packages/http/versions/1.0.0%2B1");
  });

  test("do not collide with the versions tab", () => {
    expect(packageVersionPath("http", "1.0.0")).not.toBe(packageTabPath("http", "versions"));
  });
});

describe("pubspecSnippet", () => {
  const snippet = pubspecSnippet("acme_ui", "2.1.0", "https://pub.example.com/o/acme/pub");

  test("carries the hosted URL — without it the dependency resolves against pub.dev", () => {
    expect(snippet).toContain("hosted: https://pub.example.com/o/acme/pub");
  });

  test("uses a caret constraint, like `dart pub add`", () => {
    expect(snippet).toContain("version: ^2.1.0");
  });

  test("is a valid two-space-indented pubspec block", () => {
    expect(snippet.split("\n")).toEqual([
      "dependencies:",
      "  acme_ui:",
      "    hosted: https://pub.example.com/o/acme/pub",
      "    version: ^2.1.0",
    ]);
  });
});
