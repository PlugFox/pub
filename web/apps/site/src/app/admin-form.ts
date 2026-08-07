import type {
  AdminSettingsDto,
  BrandingSettingsDto,
  RateLimitSettingsDto,
  RegistrationSettingsDto,
  RegistrySettingsDto,
  SmtpSettingsPatchDto,
  UpstreamSettingsDto,
} from "@pub/api/types";

/*
 * Instance-settings form model and validation.
 *
 * PRE-FLIGHT ONLY. `crates/admin/src/instance.rs` re-validates every field and
 * is the authority; this exists so a typo is a red field next to the input
 * instead of a round trip and a toast. The rules below mirror that module
 * one-for-one — when it changes, this changes with it:
 *
 *   - every rate limit ≥ 1 (a zero locks the instance out of its own sign-in);
 *   - `smtp.port` ≥ 1, `smtp.security` ∈ {tls, starttls, none};
 *   - `branding.name` non-empty;
 *   - each allowed email domain lowercased, no `@`, no whitespace, one dot at
 *     least — a typo'd allowlist is a lockout, not a filter.
 *
 * One server rule is deliberately NOT mirrored: `smtp.username` requires a
 * password. Whether one is available depends on the boot `[smtp]` credential,
 * which applies only when host, port and username all match the boot values —
 * facts the credential-free document does not carry (`password_set` reports
 * only the *stored* secret). A pre-flight guess here would red-flag a
 * configuration the server accepts, so the 400 is left to speak for itself.
 *
 * PATCH SEMANTICS: each section is replaced WHOLESALE, so the form always
 * submits a complete section built from the loaded values, never a diff.
 * The SMTP password is the one field with a different contract: it is
 * write-only (S-26), so the form carries a "set a new password" affordance and
 * omits the field entirely unless the operator opted in.
 */

/** The editable shape of the settings form — flat strings, as the inputs hold them. */
export type SettingsForm = {
  readonly brandingName: string;
  readonly brandingTagline: string;
  readonly brandingLogoUrl: string;
  readonly brandingPrimaryColor: string;
  readonly registrationMode: string;
  /** One domain per line, as typed. */
  readonly allowedDomains: string;
  readonly otpPerEmailHour: string;
  readonly otpPerIpHour: string;
  readonly loginPerIpMinute: string;
  readonly tokenAuthFailPerIpMinute: string;
  readonly publishPerHourOrg: string;
  readonly smtpHost: string;
  readonly smtpPort: string;
  readonly smtpUsername: string;
  readonly smtpFrom: string;
  readonly smtpSecurity: string;
  /** Opt-in: only when `true` is a password sent at all. */
  readonly smtpSetPassword: boolean;
  readonly smtpPassword: string;
  readonly upstreamEnabled: boolean;
  readonly upstreamDefaultPolicy: string;
  readonly registryRequireAuthForRead: boolean;
};

/** Field keys the validator can flag; the screen maps them to i18n messages. */
export type SettingsFieldError =
  | "brandingName"
  | "allowedDomains"
  | "otpPerEmailHour"
  | "otpPerIpHour"
  | "loginPerIpMinute"
  | "tokenAuthFailPerIpMinute"
  | "publishPerHourOrg"
  | "smtpPort"
  | "smtpFrom";

export type SettingsErrors = Partial<
  Record<SettingsFieldError, "required" | "positive" | "domain">
>;

/** Builds the editable form from a loaded settings document. */
export function settingsToForm(settings: AdminSettingsDto): SettingsForm {
  return {
    brandingName: settings.branding.name,
    brandingTagline: settings.branding.tagline,
    brandingLogoUrl: settings.branding.logo_url,
    brandingPrimaryColor: settings.branding.primary_color,
    registrationMode: settings.registration.mode,
    allowedDomains: settings.registration.allowed_email_domains.join("\n"),
    otpPerEmailHour: String(settings.rate_limits.otp_per_email_hour),
    otpPerIpHour: String(settings.rate_limits.otp_per_ip_hour),
    loginPerIpMinute: String(settings.rate_limits.login_per_ip_minute),
    tokenAuthFailPerIpMinute: String(settings.rate_limits.token_auth_fail_per_ip_minute),
    publishPerHourOrg: String(settings.rate_limits.publish_per_hour_org),
    smtpHost: settings.smtp.host ?? "",
    smtpPort: String(settings.smtp.port),
    smtpUsername: settings.smtp.username ?? "",
    smtpFrom: settings.smtp.from,
    smtpSecurity: settings.smtp.security,
    smtpSetPassword: false,
    smtpPassword: "",
    upstreamEnabled: settings.upstream.enabled,
    upstreamDefaultPolicy: settings.upstream.default_org_policy,
    registryRequireAuthForRead: settings.registry.require_auth_for_read,
  };
}

/** Splits the textarea into domains, dropping blanks. Does not validate. */
export function parseDomains(raw: string): string[] {
  return raw
    .split(/[\n,]/)
    .map((line) => line.trim().replace(/^@/, "").toLowerCase())
    .filter((line) => line !== "");
}

/** Mirrors `normalize_registration`: no `@`, no whitespace, at least one dot. */
export function isEmailDomain(value: string): boolean {
  return !value.includes("@") && !/\s/.test(value) && value.includes(".");
}

/** Whole positive integer, as the rate-limit fields require. */
function positiveInt(raw: string): number | null {
  const trimmed = raw.trim();
  if (!/^\d+$/.test(trimmed)) return null;
  const value = Number.parseInt(trimmed, 10);
  return value >= 1 ? value : null;
}

export function validateSettings(form: SettingsForm): SettingsErrors {
  const errors: SettingsErrors = {};
  if (form.brandingName.trim() === "") errors.brandingName = "required";
  if (parseDomains(form.allowedDomains).some((domain) => !isEmailDomain(domain))) {
    errors.allowedDomains = "domain";
  }
  const limits: readonly [SettingsFieldError, string][] = [
    ["otpPerEmailHour", form.otpPerEmailHour],
    ["otpPerIpHour", form.otpPerIpHour],
    ["loginPerIpMinute", form.loginPerIpMinute],
    ["tokenAuthFailPerIpMinute", form.tokenAuthFailPerIpMinute],
    ["publishPerHourOrg", form.publishPerHourOrg],
  ];
  for (const [field, raw] of limits) {
    if (positiveInt(raw) === null) errors[field] = "positive";
  }
  if (positiveInt(form.smtpPort) === null) errors.smtpPort = "positive";
  if (form.smtpFrom.trim() === "") errors.smtpFrom = "required";
  return errors;
}

export function hasErrors(errors: SettingsErrors): boolean {
  return Object.keys(errors).length > 0;
}

export type SettingsPatch = {
  branding: BrandingSettingsDto;
  registration: RegistrationSettingsDto;
  rate_limits: RateLimitSettingsDto;
  smtp: SmtpSettingsPatchDto;
  upstream: UpstreamSettingsDto;
  registry: RegistrySettingsDto;
};

/**
 * Builds the wire patch. Call only on a form that validated.
 *
 * `smtp.password` is present only when the operator explicitly asked to set
 * one: omitting the key keeps the stored secret, and sending `""` would clear
 * it — so a form that always sent the field would wipe SMTP credentials every
 * time somebody edited the instance name.
 */
export function formToPatch(form: SettingsForm): SettingsPatch {
  const smtpHost = form.smtpHost.trim();
  const smtpUser = form.smtpUsername.trim();
  const smtp: SmtpSettingsPatchDto = {
    host: smtpHost === "" ? null : smtpHost,
    port: Number.parseInt(form.smtpPort.trim(), 10),
    username: smtpUser === "" ? null : smtpUser,
    from: form.smtpFrom.trim(),
    security: form.smtpSecurity,
    ...(form.smtpSetPassword ? { password: form.smtpPassword } : {}),
  };
  return {
    branding: {
      name: form.brandingName.trim(),
      tagline: form.brandingTagline.trim(),
      logo_url: form.brandingLogoUrl.trim(),
      primary_color: form.brandingPrimaryColor.trim(),
    },
    registration: {
      mode: form.registrationMode,
      allowed_email_domains: [...new Set(parseDomains(form.allowedDomains))].sort(),
    },
    rate_limits: {
      otp_per_email_hour: Number.parseInt(form.otpPerEmailHour.trim(), 10),
      otp_per_ip_hour: Number.parseInt(form.otpPerIpHour.trim(), 10),
      login_per_ip_minute: Number.parseInt(form.loginPerIpMinute.trim(), 10),
      token_auth_fail_per_ip_minute: Number.parseInt(form.tokenAuthFailPerIpMinute.trim(), 10),
      publish_per_hour_org: Number.parseInt(form.publishPerHourOrg.trim(), 10),
    },
    smtp,
    upstream: {
      enabled: form.upstreamEnabled,
      default_org_policy: form.upstreamDefaultPolicy,
    },
    registry: {
      require_auth_for_read: form.registryRequireAuthForRead,
    },
  };
}
