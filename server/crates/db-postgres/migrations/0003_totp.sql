-- 0003_totp (postgres): TOTP second factor (S-05).
--
-- `credentials.secret_enc` (0002) already carries the KEK-sealed seed / recovery hashes;
-- this migration adds the replay floor and pins "one active TOTP per user".

-- Highest accepted RFC 6238 time-step for type = 'totp' rows; codes at or below it are
-- replays and must be rejected (S-05 last-accepted-counter).
ALTER TABLE credentials ADD COLUMN totp_last_step BIGINT;

-- Exactly one active TOTP enrollment per user.
CREATE UNIQUE INDEX credentials_totp_key ON credentials (user_id) WHERE type = 'totp';
