-- ============================================================================
--  SFMPAS backend schema  (PostgreSQL)
-- ============================================================================
--  PRIVACY INVARIANT
--  ----------------
--  This database MUST NOT store fingerprint images, minutiae templates, or any
--  other biometric sample. Biometric data never leaves the handset: the finger
--  is matched locally by Android BiometricPrompt, and the only thing that
--  crosses the network is a PUBLIC key and an ECDSA signature over a
--  server-issued challenge.
--
--  `users.public_key` is an EC P-256 *public* key (X.509 SubjectPublicKeyInfo,
--  base64). It is not biometric data and cannot be used to reconstruct a print.
--  `transactions.liveness_score` is a single float produced by the on-device PAD
--  model — a scalar, not an image.
--
--  There is deliberately no column anywhere for image bytes, and no BYTEA/BLOB
--  type is used in this schema.
--
--  APPLYING THIS FILE
--  ------------------
--  Render does not run init scripts against a managed database. main.py applies
--  this file itself on startup, which is why every statement is idempotent
--  (IF NOT EXISTS / OR REPLACE). You can also run it by hand:
--      psql "$DATABASE_URL" -f schema.sql
--
--  There is no CREATE DATABASE here: PostgreSQL cannot create a database from
--  inside a connection to another one, and Render provisions the database for
--  you.
-- ============================================================================

-- ---------------------------------------------------------------------------
--  users
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    user_id         VARCHAR(64)   NOT NULL,
    username        VARCHAR(128)  NOT NULL,
    phone_number    VARCHAR(32)   NOT NULL,
    occupation      VARCHAR(32)   NOT NULL DEFAULT 'GENERAL_USER',
    -- EC P-256 public key, X.509 SubjectPublicKeyInfo, base64. PUBLIC key only.
    public_key      TEXT          NOT NULL,
    registered_at   TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    CONSTRAINT pk_users PRIMARY KEY (user_id),
    CONSTRAINT uq_users_phone UNIQUE (phone_number),
    CONSTRAINT chk_users_occupation
        CHECK (occupation IN ('GENERAL_USER', 'MANUAL_LABOUR_WORKER'))
);

-- PostgreSQL has no ON UPDATE CURRENT_TIMESTAMP; a trigger does the same job.
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_users_updated_at ON users;
CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
--  transactions
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS transactions (
    transaction_id  VARCHAR(36)   NOT NULL,
    user_id         VARCHAR(64)   NOT NULL,
    amount_naira    BIGINT        NOT NULL,
    recipient       VARCHAR(128)  NOT NULL,
    tier            VARCHAR(16)   NOT NULL,
    -- Scalar PAD output in [0,1] from the on-device model. Not an image.
    liveness_score  REAL          NULL,
    verdict         VARCHAR(16)   NOT NULL,
    -- Base64 DER ECDSA signature over the server-issued challenge.
    assertion       TEXT          NULL,
    reason          VARCHAR(255)  NULL,
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    CONSTRAINT pk_transactions PRIMARY KEY (transaction_id),
    CONSTRAINT fk_tx_user FOREIGN KEY (user_id)
        REFERENCES users (user_id) ON DELETE CASCADE,
    CONSTRAINT chk_tx_tier CHECK (tier IN ('TIER_1', 'TIER_2', 'TIER_3')),
    CONSTRAINT chk_tx_verdict CHECK (verdict IN ('APPROVED', 'REJECTED')),
    CONSTRAINT chk_tx_amount_positive CHECK (amount_naira > 0),
    CONSTRAINT chk_tx_liveness_range
        CHECK (liveness_score IS NULL OR (liveness_score >= 0 AND liveness_score <= 1))
);

CREATE INDEX IF NOT EXISTS idx_tx_user_time
    ON transactions (user_id, created_at DESC);

-- ---------------------------------------------------------------------------
--  auth_challenges
-- ---------------------------------------------------------------------------
--  NOTE: a THIRD table beyond the two originally specified. It is required for
--  the two-step /authenticate/begin -> /authenticate/complete flow to be safe.
--
--  Without persisted challenges the server would have to trust a value chosen by
--  the client, which defeats the purpose of the signature: an attacker could
--  replay a captured assertion, or sign a payload the server never issued.
--  Storing the challenge lets the server enforce that each one is (a) generated
--  server-side from a CSPRNG, (b) bound to a specific user and amount, (c) used
--  at most once, and (d) short-lived.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS auth_challenges (
    challenge_id    VARCHAR(36)   NOT NULL,
    user_id         VARCHAR(64)   NOT NULL,
    -- 32 random bytes, base64. This exact value is what the device signs.
    challenge       VARCHAR(64)   NOT NULL,
    amount_naira    BIGINT        NOT NULL,
    tier            VARCHAR(16)   NOT NULL,
    consumed        BOOLEAN       NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ   NOT NULL,

    CONSTRAINT pk_auth_challenges PRIMARY KEY (challenge_id),
    CONSTRAINT fk_challenge_user FOREIGN KEY (user_id)
        REFERENCES users (user_id) ON DELETE CASCADE,
    CONSTRAINT chk_challenge_tier CHECK (tier IN ('TIER_1', 'TIER_2', 'TIER_3'))
);

CREATE INDEX IF NOT EXISTS idx_challenge_user
    ON auth_challenges (user_id, consumed, expires_at);

-- Convenience view for the user study: per-user authorisation outcomes.
CREATE OR REPLACE VIEW v_user_transaction_summary AS
SELECT
    u.user_id,
    u.username,
    COUNT(t.transaction_id)                                   AS total_transactions,
    COUNT(*) FILTER (WHERE t.verdict = 'APPROVED')            AS approved,
    COUNT(*) FILTER (WHERE t.verdict = 'REJECTED')            AS rejected,
    AVG(t.liveness_score)                                     AS mean_liveness,
    MAX(t.created_at)                                         AS last_activity
FROM users u
LEFT JOIN transactions t ON t.user_id = u.user_id
GROUP BY u.user_id, u.username;

-- Housekeeping: drop expired, unconsumed challenges.
-- DELETE FROM auth_challenges WHERE expires_at < NOW() AND consumed = FALSE;
