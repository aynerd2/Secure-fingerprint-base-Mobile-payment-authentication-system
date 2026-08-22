# SFMPAS Backend

FastAPI service backing the SFMPAS Android app: FIDO2-style transaction
authorisation with CBN KYC tiering, on PostgreSQL.

**No biometric data is ever stored or transmitted.** The finger is matched
locally on the handset by `BiometricPrompt`; only an EC P-256 *public* key and
an ECDSA signature over a server-issued challenge cross the network. There is no
image, template, or minutiae column anywhere in the schema.

---

## Endpoints

| Method | Path                     | Purpose                                        |
|--------|--------------------------|------------------------------------------------|
| POST   | `/register`              | Enrol a user and their public key              |
| POST   | `/authenticate/begin`    | Resolve the KYC tier, issue a signing challenge |
| POST   | `/authenticate/complete` | Verify the assertion, record the transaction   |
| GET    | `/transactions`          | Transaction history for a user                 |
| GET    | `/health`                | Liveness probe (used by Render)                |

Interactive docs are served at `/docs` once deployed.

### CBN KYC tiers

| Amount              | Tier   | Requirement                                        |
|---------------------|--------|----------------------------------------------------|
| below ₦50,000       | Tier 1 | Fingerprint only                                   |
| ₦50,000 – ₦200,000  | Tier 2 | Fingerprint + liveness check                       |
| above ₦200,000      | Tier 3 | Fingerprint + liveness + enhanced verification     |

Both bounds are **inclusive at Tier 2**: exactly ₦50,000 and exactly ₦200,000
are Tier 2. This mirrors `KycTier.forAmount()` in the Android client — if you
change one, change both or the device and server will disagree.

---

## Crypto contract with the Android client

| Item      | Value                                                                    |
|-----------|--------------------------------------------------------------------------|
| Key       | EC P-256 (`secp256r1`), public half as X.509 SubjectPublicKeyInfo, base64 |
| Signature | `SHA256withECDSA` (DER-encoded ASN.1 `(r, s)`), base64                    |
| Payload   | The raw bytes of the base64-decoded `challenge` from `/authenticate/begin` |

The key format is exactly what Java's `PublicKey.getEncoded()` returns, and the
signature format is exactly what `java.security.Signature` produces — so the
handset interoperates without any re-encoding. **Sign the raw challenge bytes:
nothing prepended, appended, or re-hashed.**

---

## Deploying to Render

### Prerequisites

- A GitHub (or GitLab) repository containing this folder
- A free Render account: <https://render.com>

### 1. Push the code

```bash
cd sfmpas-backend
git init
git add .
git commit -m "SFMPAS backend"
git branch -M main
git remote add origin https://github.com/<you>/sfmpas-backend.git
git push -u origin main
```

If you push the **whole `fgp` project** rather than just this folder, keep the
`rootDir: sfmpas-backend` line in `render.yaml`. If `sfmpas-backend` *is* the
repository root, delete that line.

### 2. Create the services from the Blueprint

1. Sign in to Render and open <https://dashboard.render.com/blueprints>.
2. Click **New Blueprint Instance**.
3. Connect your GitHub account and pick the repository.
4. Render reads `render.yaml` and shows two resources: the **sfmpas-backend**
   web service and the **sfmpas-db** PostgreSQL database.
5. Give the blueprint a name and click **Apply**.

Render provisions the database first, injects its connection string into the web
service as `DATABASE_URL`, then builds and starts the API. The first deploy takes
roughly 3–5 minutes.

### 3. Verify

Your URL will be `https://sfmpas-backend.onrender.com` (Render derives the
hostname from the service name; if the name was taken, Render appends a suffix —
check the dashboard for the real URL).

```bash
curl https://sfmpas-backend.onrender.com/health
# {"status":"ok","database":"up"}
```

Then run the full test suite against it:

```bash
pip install -r requirements.txt
python test_api.py --base-url https://sfmpas-backend.onrender.com
```

The schema is applied automatically on first startup — Render does not run init
scripts for managed databases, so `main.py` executes `schema.sql` itself. Every
statement is idempotent, so restarts and redeploys are safe.

---

## Free-tier limits that matter for a user study

**The web service sleeps after ~15 minutes of inactivity.** The next request
pays a cold start of roughly 50 seconds. During a study session this shows up as
the first payment appearing to hang. Mitigations:

- Hit `/health` a minute before each session to wake the instance.
- Keep it warm with an external pinger (e.g. UptimeRobot every 10 minutes).
- The Android client already sets a 90-second call timeout for exactly this
  reason — a default 10-second timeout would fail that first request.

**Free PostgreSQL instances expire after 30 days** and are then deleted. Export
anything you need for the dissertation before then:

```bash
pg_dump "<external connection string from the Render dashboard>" > sfmpas_backup.sql
```

**Free instances have no persistent disk** on the web service — that is fine
here, because all state lives in PostgreSQL.

---

## Environment variables

| Variable                  | Set by  | Default                  | Purpose                                   |
|---------------------------|---------|--------------------------|-------------------------------------------|
| `DATABASE_URL`            | Render  | —                        | PostgreSQL connection string              |
| `PORT`                    | Render  | `10000`                  | Port uvicorn binds                        |
| `JWT_SECRET`              | Render  | generated                | Signs the transaction receipt             |
| `CHALLENGE_TTL_SECONDS`   | you     | `300`                    | Challenge lifetime                        |
| `APPLY_SCHEMA_ON_STARTUP` | you     | `true`                   | Bootstrap the schema on boot              |
| `DB_STARTUP_RETRIES`      | you     | `30`                     | Connection attempts before giving up      |

`DATABASE_URL` is read directly; `postgres://` is normalised to `postgresql://`
because Render still hands out the legacy scheme in some places.

---

## Running locally (optional)

You need a local PostgreSQL 14+.

```bash
createdb sfmpas
pip install -r requirements.txt
export DATABASE_URL="postgresql://sfmpas:sfmpas_dev_password@127.0.0.1:5432/sfmpas"
uvicorn main:app --reload --port 10000
python test_api.py --base-url http://127.0.0.1:10000
```

---

## Connecting the Android app

`ApiConfig.BASE_URL` in `app/src/main/java/com/sfmpas/app/data/BackendApi.kt`
points at `https://sfmpas-backend.onrender.com/`. Change it if your Render
service ended up with a different hostname. The trailing slash is required.

No `networkSecurityConfig` is needed: Render is HTTPS-only, so the platform's
default cleartext block stays in force.

The Retrofit client is wired into both screens:

- **Registration** POSTs the public key to `/register` after the Keystore
  credential is minted. This is offline-first — a network failure leaves the
  local enrolment intact and marks the account "pending sync".
- **Authentication** calls `/authenticate/begin` before showing the fingerprint
  prompt, signs the **server-issued** challenge inside the `CryptoObject`
  ceremony, then submits it to `/authenticate/complete`. If the account was
  registered offline, the enrolment is retried lazily at this point.

The backend's verdict is authoritative **when it answers**. An HTTP error means
it actively refused (bad signature, replay, expired or mismatched challenge) and
the payment is rejected. A transport failure is treated differently: the flow
falls back to a device-local challenge and records the transaction as locally
verified, so a user study can run without connectivity. That fallback is
announced in the on-screen log rather than hidden.

---

## Files

| File               | Purpose                                          |
|--------------------|--------------------------------------------------|
| `main.py`          | FastAPI application                              |
| `schema.sql`       | PostgreSQL schema, applied automatically on boot  |
| `requirements.txt` | Python dependencies                              |
| `render.yaml`      | Render Blueprint: web service + database         |
| `Procfile`         | Process definition (`web:`)                      |
| `test_api.py`      | End-to-end test of all four endpoints            |
| `Dockerfile`       | Optional container build — **not** used by Render's Python runtime |
