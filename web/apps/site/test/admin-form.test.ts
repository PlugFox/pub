import { describe, expect, test } from "bun:test";
import type { AdminSettingsDto } from "@pub/api/types";
import {
  formToPatch,
  hasErrors,
  isEmailDomain,
  parseDomains,
  type SettingsForm,
  settingsToForm,
  validateSettings,
} from "../src/app/admin-form";

/*
 * Instance-settings form validation.
 *
 * These rules mirror `server/crates/admin/src/instance.rs`, which stays the
 * authority — so the tests are written against the *server's* invariants
 * rather than against the form's convenience, and the SMTP password cases get
 * the most attention because that is the one field where a wrong default
 * destroys a credential (S-26: omit keeps, `""` clears).
 */

const SETTINGS: AdminSettingsDto = {
  version: 4,
  branding: {
    name: "Acme Registry",
    tagline: "Internal packages",
    logo_url: "",
    primary_color: "",
  },
  registration: { mode: "invite", allowed_email_domains: ["acme.com", "acme.dev"] },
  rate_limits: {
    otp_per_email_hour: 5,
    otp_per_ip_hour: 20,
    login_per_ip_minute: 10,
    token_auth_fail_per_ip_minute: 30,
    publish_per_hour_org: 60,
    read_per_ip_minute: 600,
    read_per_identity_minute: 3000,
  },
  smtp: {
    host: "smtp.acme.com",
    port: 587,
    username: "mailer",
    from: "pub@acme.com",
    security: "starttls",
    password_set: true,
  },
  upstream: { enabled: true, default_org_policy: "allow" },
  registry: { require_auth_for_read: true },
};

function form(overrides: Partial<SettingsForm> = {}): SettingsForm {
  return { ...settingsToForm(SETTINGS), ...overrides };
}

describe("settingsToForm", () => {
  test("round-trips the loaded document into editable strings", () => {
    const built = settingsToForm(SETTINGS);
    expect(built.brandingName).toBe("Acme Registry");
    expect(built.otpPerEmailHour).toBe("5");
    expect(built.allowedDomains).toBe("acme.com\nacme.dev");
  });

  test("never prefills the password — the API does not return one", () => {
    expect(settingsToForm(SETTINGS).smtpPassword).toBe("");
    expect(settingsToForm(SETTINGS).smtpSetPassword).toBe(false);
  });

  test("carries the registry flag through as a boolean, not a string", () => {
    expect(settingsToForm(SETTINGS).registryRequireAuthForRead).toBe(true);
    expect(
      settingsToForm({ ...SETTINGS, registry: { require_auth_for_read: false } })
        .registryRequireAuthForRead,
    ).toBe(false);
  });

  test("a null host and username become empty strings, not the word null", () => {
    const built = settingsToForm({
      ...SETTINGS,
      smtp: { ...SETTINGS.smtp, host: null, username: null },
    });
    expect(built.smtpHost).toBe("");
    expect(built.smtpUsername).toBe("");
  });
});

describe("validateSettings", () => {
  test("a form built from a valid document is valid", () => {
    expect(validateSettings(form())).toEqual({});
    expect(hasErrors(validateSettings(form()))).toBe(false);
  });

  test("the instance name cannot be empty or whitespace", () => {
    expect(validateSettings(form({ brandingName: "" })).brandingName).toBe("required");
    expect(validateSettings(form({ brandingName: "   " })).brandingName).toBe("required");
  });

  test.each([
    ["otpPerEmailHour"],
    ["otpPerIpHour"],
    ["loginPerIpMinute"],
    ["tokenAuthFailPerIpMinute"],
    ["publishPerHourOrg"],
  ] as const)(
    "%s must be at least 1 — a zero locks the instance out of its own sign-in",
    (field) => {
      expect(validateSettings(form({ [field]: "0" }))[field]).toBe("positive");
    },
  );

  test.each(["", " ", "-1", "1.5", "abc", "1e3", "0x10", " 1 2"])(
    "a rate limit of %p is refused",
    (raw) => {
      expect(validateSettings(form({ loginPerIpMinute: raw })).loginPerIpMinute).toBe("positive");
    },
  );

  test("a rate limit with surrounding whitespace is accepted", () => {
    expect(validateSettings(form({ loginPerIpMinute: " 12 " })).loginPerIpMinute).toBeUndefined();
  });

  test("the SMTP port must be positive and the From address non-empty", () => {
    const errors = validateSettings(form({ smtpPort: "0", smtpFrom: "  " }));
    expect(errors.smtpPort).toBe("positive");
    expect(errors.smtpFrom).toBe("required");
  });

  test("an empty domain allowlist is valid — it means every domain", () => {
    expect(validateSettings(form({ allowedDomains: "" })).allowedDomains).toBeUndefined();
  });

  test.each(["nope", "user@acme.com", "acme com", "acme.com/path\tx"])(
    "%p is not an email domain and a typo here is a lockout, not a filter",
    (domain) => {
      expect(validateSettings(form({ allowedDomains: `acme.com\n${domain}` })).allowedDomains).toBe(
        "domain",
      );
    },
  );

  test.each([" ", "@", "  @  "])(
    "%p normalizes to nothing and is skipped, exactly as the server skips it",
    (domain) => {
      expect(
        validateSettings(form({ allowedDomains: `acme.com\n${domain}` })).allowedDomains,
      ).toBeUndefined();
    },
  );

  test("reports every bad field at once, not just the first", () => {
    const errors = validateSettings(
      form({ brandingName: "", smtpPort: "x", otpPerIpHour: "0", allowedDomains: "bad" }),
    );
    expect(Object.keys(errors).sort()).toEqual([
      "allowedDomains",
      "brandingName",
      "otpPerIpHour",
      "smtpPort",
    ]);
  });
});

describe("parseDomains", () => {
  test("splits on newlines and commas, lowercases, and strips a leading @", () => {
    expect(parseDomains(" @ACME.com, acme.dev \n\n corp.example ")).toEqual([
      "acme.com",
      "acme.dev",
      "corp.example",
    ]);
  });

  test("drops blank lines", () => {
    expect(parseDomains("\n\n,,\n")).toEqual([]);
  });

  test("isEmailDomain mirrors the server's rule", () => {
    expect(isEmailDomain("acme.com")).toBe(true);
    expect(isEmailDomain("a@b.com")).toBe(false);
    expect(isEmailDomain("no-dot")).toBe(false);
    expect(isEmailDomain("with space.com")).toBe(false);
  });
});

describe("formToPatch", () => {
  test("submits every section whole — the API replaces sections, not fields", () => {
    const patch = formToPatch(form({ brandingName: "Renamed" }));
    expect(Object.keys(patch).sort()).toEqual([
      "branding",
      "rate_limits",
      "registration",
      "registry",
      "smtp",
      "upstream",
    ]);
    // Editing only the name must not blank the rest of the branding section.
    expect(patch.branding).toEqual({
      name: "Renamed",
      tagline: "Internal packages",
      logo_url: "",
      primary_color: "",
    });
  });

  test("omits the SMTP password entirely unless the operator opted in (S-26)", () => {
    const patch = formToPatch(form({ smtpPassword: "typed-but-not-armed" }));
    expect("password" in patch.smtp).toBe(false);
  });

  test("sends the password when armed", () => {
    const patch = formToPatch(form({ smtpSetPassword: true, smtpPassword: "hunter2" }));
    expect(patch.smtp.password).toBe("hunter2");
  });

  test("an armed but empty password clears the stored one — reachable, not accidental", () => {
    const patch = formToPatch(form({ smtpSetPassword: true, smtpPassword: "" }));
    expect(patch.smtp.password).toBe("");
  });

  test("an empty host becomes null, which disables runtime SMTP", () => {
    expect(formToPatch(form({ smtpHost: "  " })).smtp.host).toBeNull();
  });

  test("domains are normalized, de-duplicated, and sorted like the server does", () => {
    const patch = formToPatch(form({ allowedDomains: "B.com\n@a.com\na.com\n" }));
    expect(patch.registration.allowed_email_domains).toEqual(["a.com", "b.com"]);
  });

  test("rate limits come back as numbers, not strings", () => {
    const patch = formToPatch(form({ loginPerIpMinute: " 42 " }));
    expect(patch.rate_limits.login_per_ip_minute).toBe(42);
  });

  test("carries the registry flag both ways — editing anything else must not flip it", () => {
    expect(formToPatch(form()).registry).toEqual({ require_auth_for_read: true });
    expect(formToPatch(form({ registryRequireAuthForRead: false })).registry).toEqual({
      require_auth_for_read: false,
    });
    // The section is written wholesale on every save, so a branding edit
    // resubmits the loaded flag rather than an absent one that would reset it.
    expect(formToPatch(form({ brandingName: "Renamed" })).registry.require_auth_for_read).toBe(
      true,
    );
  });
});
