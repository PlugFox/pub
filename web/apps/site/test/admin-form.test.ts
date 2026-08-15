import { describe, expect, test } from "bun:test";
import type { AdminSettingsDto } from "@pub/api/types";
import {
  formToPatch,
  hasErrors,
  isEmailDomain,
  parseDomains,
  type SettingsFieldError,
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
    write_per_ip_minute: 60,
    write_per_identity_minute: 300,
    invitations_per_day_org: 20,
    invitations_per_day_actor: 10,
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
  registry: { require_auth_for_read: true, storage_quota_bytes: 10_737_418_240 },
};

function form(overrides: Partial<SettingsForm> = {}): SettingsForm {
  return { ...settingsToForm(SETTINGS), ...overrides };
}

/**
 * `read_per_ip_minute` → `readPerIpMinute`.
 *
 * The form's naming rule, applied rather than restated as a lookup table, so
 * the coverage tests below stay true for fields nobody has added yet.
 */
function camelCase(wire: string): string {
  return wire.replace(/_([a-z])/g, (_, letter: string) => letter.toUpperCase());
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
      settingsToForm({
        ...SETTINGS,
        registry: { ...SETTINGS.registry, require_auth_for_read: false },
      }).registryRequireAuthForRead,
    ).toBe(false);
  });

  test("the storage quota arrives as a byte string, and 0 stays 0", () => {
    expect(settingsToForm(SETTINGS).storageQuotaBytes).toBe("10737418240");
    expect(
      settingsToForm({ ...SETTINGS, registry: { ...SETTINGS.registry, storage_quota_bytes: 0 } })
        .storageQuotaBytes,
    ).toBe("0");
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

  // Every numeric field the server's `validate_rate_limits` covers, including
  // the two read limits the table forgot when they landed and the four
  // decision 32 added. The list is the whole rule, not a sample: a field that
  // is added to the form and left out of the validator is exactly the shape of
  // bug this table exists to refuse.
  test.each([
    ["otpPerEmailHour"],
    ["otpPerIpHour"],
    ["loginPerIpMinute"],
    ["tokenAuthFailPerIpMinute"],
    ["publishPerHourOrg"],
    ["readPerIpMinute"],
    ["readPerIdentityMinute"],
    ["writePerIpMinute"],
    ["writePerIdentityMinute"],
    ["invitationsPerDayOrg"],
    ["invitationsPerDayActor"],
  ] as const)(
    "%s must be at least 1 — a zero locks the instance out of its own sign-in",
    (field) => {
      expect(validateSettings(form({ [field]: "0" }))[field]).toBe("positive");
    },
  );

  test("every field the server validates as a rate limit is in that table", () => {
    // `validate_rate_limits` walks the whole `rate_limits` section, so a limit
    // the form does not check is a red field the operator never sees and a 400
    // they cannot explain. Derived from the DTO rather than restated, so an
    // eleventh limit fails here the day it is added — no table to remember.
    const unchecked = Object.keys(SETTINGS.rate_limits).filter((wire) => {
      const field = camelCase(wire) as SettingsFieldError;
      const errors = validateSettings(form({ [field]: "0" } as Partial<SettingsForm>));
      return errors[field] !== "positive";
    });
    expect(unchecked).toEqual([]);
  });

  test("the storage quota accepts 0 — the one number here where 0 is the shipped value", () => {
    // S-20.b: `registry.storage_quota_bytes` is `0 = unlimited`, so the
    // positive-integer rule its neighbours share would refuse the default a
    // fresh instance boots with.
    expect(validateSettings(form({ storageQuotaBytes: "0" })).storageQuotaBytes).toBeUndefined();
    expect(hasErrors(validateSettings(form({ storageQuotaBytes: "0" })))).toBe(false);
  });

  test.each(["-1", "-0", "", " ", "1.5", "1e9", "abc", "0x10", "1_000", "10 GiB"])(
    "a storage quota of %p is refused — 0 is unlimited, but a negative or fuzzy value is nothing",
    (raw) => {
      expect(validateSettings(form({ storageQuotaBytes: raw })).storageQuotaBytes).toBe("bytes");
    },
  );

  test("a storage quota beyond 2^53 is refused rather than silently rounded", () => {
    // JSON.stringify would send a DIFFERENT number than the one typed, storing
    // a wall the operator never asked for.
    expect(
      validateSettings(form({ storageQuotaBytes: "9007199254740993" })).storageQuotaBytes,
    ).toBe("bytes");
  });

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

  /*
   * THE REGRESSION THIS FILE EXISTS FOR.
   *
   * `PATCH /admin/settings` replaces each section WHOLESALE, so a field that
   * the server grows and the form never learns about is not a missing input —
   * it is a 400 (`missing field storage_quota_bytes`) on every save the
   * operator attempts, including saves that have nothing to do with the new
   * field. That is precisely what happened when decision 32 added four rate
   * limits and the storage quota: the form kept building sections from the
   * fields it knew, and every one of them was now incomplete.
   *
   * The assertion is written against the DTO's own keys rather than a list, so
   * the NEXT field to land fails here on the day the types are regenerated —
   * before anybody opens the screen.
   */
  test("every field of every section survives settingsToForm → formToPatch", () => {
    const patch = formToPatch(settingsToForm(SETTINGS));
    const missing: string[] = [];
    const changed: string[] = [];
    for (const section of [
      "branding",
      "registration",
      "rate_limits",
      "upstream",
      "registry",
    ] as const) {
      const before = SETTINGS[section] as Record<string, unknown>;
      const after = patch[section] as Record<string, unknown>;
      for (const key of Object.keys(before)) {
        if (!(key in after)) missing.push(`${section}.${key}`);
        else if (JSON.stringify(after[key]) !== JSON.stringify(before[key])) {
          changed.push(`${section}.${key}`);
        }
      }
    }
    expect(missing).toEqual([]);
    expect(changed).toEqual([]);
  });

  test("the SMTP section round-trips too, minus the two fields that cannot", () => {
    // `password_set` is a report, not a setting (S-26), and there is no
    // `password` to carry back — so this section is checked by name against
    // what it CAN carry rather than against the whole document.
    const patch = formToPatch(settingsToForm(SETTINGS));
    const { password_set: _reported, ...writable } = SETTINGS.smtp;
    expect(patch.smtp).toEqual(writable);
  });

  test("carries the registry flag both ways — editing anything else must not flip it", () => {
    expect(formToPatch(form()).registry).toEqual({
      require_auth_for_read: true,
      storage_quota_bytes: 10_737_418_240,
    });
    expect(formToPatch(form({ registryRequireAuthForRead: false })).registry).toEqual({
      require_auth_for_read: false,
      storage_quota_bytes: 10_737_418_240,
    });
    // The section is written wholesale on every save, so a branding edit
    // resubmits the loaded flag rather than an absent one that would reset it.
    expect(formToPatch(form({ brandingName: "Renamed" })).registry.require_auth_for_read).toBe(
      true,
    );
  });
});
