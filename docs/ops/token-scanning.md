# Token format for secret scanners (S-15)

This page is the published contract [S-15](../security.md#3-cliapi-tokens) promises: everything a secret-scanning tool needs to detect a leaked Pub CLI token **and verify it offline** — no API call, no oracle, near-zero false positives.

## Format

```
<prefix><random: 30 × base62><checksum: 6 × base62>
```

- **Prefix**: `pub_` by default ([decision 17](../decisions.md#17--branding-default-pub-white-label-token-prefix-pub_)). Instance-configurable; config validation requires lowercase alphanumerics ending in `_`.
- **Random part**: 30 characters drawn uniformly (rejection sampling, bias-free) from the base62 alphabet — ~178 bits of CSPRNG entropy.
- **Checksum**: CRC32 of the random part, encoded as exactly 6 base62 characters.
- **Alphabet** (base62, ASCII order): `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz`.

## Detection regex

```
pub_[0-9A-Za-z]{36}
```

Anchor with non-word boundaries as your engine allows (e.g. `(?<![0-9A-Za-z_])pub_[0-9A-Za-z]{36}(?![0-9A-Za-z])`) to avoid matching inside longer identifiers.

## Offline checksum verification

A regex hit can be confirmed as a genuine token (as opposed to a random identifier that happens to match) without contacting anything:

1. Strip the prefix; split the remaining 36 characters into `random` (first 30) and `checksum` (last 6).
2. Compute **CRC32** (the standard IEEE/zlib polynomial, as in `zlib.crc32`) over the 30 ASCII bytes of `random`.
3. Decode `checksum` as a big-endian base62 number using the alphabet above (`value = value * 62 + index` per character). The encoding is fixed-width: values are left-padded with `0`. A decoded value above `2^32 − 1` cannot be a genuine checksum — reject.
4. The candidate is a token iff the two values are equal. Chance of a random base62 string passing: 2⁻³².

Reference implementation (Python):

```python
import re, zlib

ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
TOKEN_RE = re.compile(r"pub_[0-9A-Za-z]{36}")

def is_pub_token(candidate: str, prefix: str = "pub_") -> bool:
    if not candidate.startswith(prefix):
        return False
    body = candidate[len(prefix):]
    if len(body) != 36:
        return False
    random_part, checksum = body[:30], body[30:]
    value = 0
    for ch in checksum:
        idx = ALPHABET.find(ch)
        if idx < 0:
            return False
        value = value * 62 + idx
    if value > 0xFFFFFFFF:
        return False
    return zlib.crc32(random_part.encode("ascii")) == value
```

The server itself runs these exact offline checks (prefix, length, charset, CRC32) before any database lookup, so fabricated strings never reach storage and the check cannot be used as a validity oracle ([decision 13](../decisions.md#13--cliapi-token-format)).

## Shipped tooling and caveats

- A **gitleaks rule** for this pattern ships in the repository (`.gitleaks.toml` at the repo root) and runs in the pre-commit hooks; reuse it in your own pipelines.
- **GitHub Secret Scanning partner registration** is future work (S-15 names it); until then, rely on gitleaks/CI scanning.
- **Custom prefixes trade away scanner coverage**: the published regex targets `pub_`, so an instance with `auth.token_prefix = "acme_"` must ship its own adjusted rule — and note that *changing* the prefix on a live instance invalidates every minted token ([security-runbook.md](security-runbook.md#the-token-prefix-is-not-a-rotation-lever)).

## When a scanner finds one

Treat any string passing the checksum as live. Tokens are stored server-side only as SHA-256 hashes and shown once at mint ([S-13](../security.md#3-cliapi-tokens)), so the leaked text is the only copy — revoke it (token panel in the org UI, or `DELETE /api/v1/tokens/{id}`); revocation is effective everywhere within ≤ 60 s. Then check the token's last-used timestamp and the audit log for activity between leak and revocation.
