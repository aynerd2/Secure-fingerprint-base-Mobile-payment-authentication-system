# Security Policy

## Status of this project

SFMPAS is **MSc dissertation research, not a production payment system.** It has had no
independent security audit. The payment flow uses a mock local ledger, the demo backend
ships permissive CORS and a default JWT secret, and the threat model below describes what
the design *intends*, not what has been externally verified. Do not deploy it, or anything
derived from it, to handle real money or real customer data without a professional review.

---

## The security model

### What SFMPAS is defending against

The system exists because fingerprint matching answers *"does this ridge pattern match the
enrolled one?"* but not *"is this a real, unaltered, present finger?"*. A lifted latent
print, a moulded spoof, or a deliberately altered finger can satisfy a matcher. SFMPAS adds
a presentation attack detection (PAD) stage and escalates the required factors with the
transaction value.

### Defence in depth

| Layer | Control | Defends against |
|---|---|---|
| Capture | On-device PAD model (0.89 % APCER) | Spoofed / altered prints |
| Policy | CBN KYC tiering by amount | Low-value fraud at scale, high-value single loss |
| Credential | Non-exportable EC P-256 key in the Android Keystore / TEE | Key theft, cloning to another device |
| Ceremony | `BiometricPrompt.CryptoObject` gating | Signing without a live user present |
| Protocol | Server-issued, single-use, expiring, amount-bound challenge | Replay, challenge substitution |
| Transport | HTTPS only; cleartext blocked by platform default | Interception, tampering |
| Audit | Every attempt logged, approved **and** rejected | Repudiation, undetected probing |

### Key properties

**The private key never leaves the secure element.** It is generated inside the Android
Keystore with `setUserAuthenticationRequired(true)` and, where supported,
`setIsStrongBoxBacked(true)`. It cannot be exported. A signature can only be produced
through a `CryptoObject` bound to a successful biometric authentication — the same
user-presence binding WebAuthn requires of an authenticator.
`setInvalidatedByBiometricEnrollment(true)` means adding a new fingerprint destroys the
key, forcing re-registration.

**The challenge is server-authored.** `/authenticate/begin` generates 32 bytes from a
CSPRNG, binds them to one `user_id` **and one amount**, stores them with a 5-minute
expiry, and marks any older live challenge for that user as consumed. `/authenticate/
complete` rejects a challenge that is already used, expired, or whose bound amount differs
from the submitted amount. A device-chosen challenge would make the signature worthless —
an attacker could replay a captured assertion or sign something the server never issued.

**Failure modes are asymmetric on purpose.** In the Android client, an HTTP error from the
backend means it *actively refused* and the payment is rejected. A transport failure means
we could not ask, and the flow falls back to local verification, clearly labelled. Treating
those identically would let an attacker force approval by cutting the network.

**The server never trusts the client's tier.** The device computes a tier for display, but
`/authenticate/begin` recomputes it and binds it to the challenge. Any disagreement is
surfaced in the client log rather than silently resolved.

---

## What is stored — and what is not

### Never stored, anywhere

- ❌ Fingerprint **images**
- ❌ Fingerprint **templates** or minutiae
- ❌ Any raw biometric sample, in any encoding
- ❌ Private keys outside the TEE (they are non-exportable by construction)
- ❌ Passwords or PINs (the app never collects one)

The database schema contains **no `BYTEA` or `BLOB` column at all** — this is enforced
structurally, not by convention. See the header of `sfmpas-backend/schema.sql`.

### Stored on the device

| Data | Where | Notes |
|---|---|---|
| Name, phone, occupation | `EncryptedSharedPreferences` | AES-256-GCM, keystore-backed |
| `user_id` | `EncryptedSharedPreferences` | Locally generated handle, no authority alone |
| EC P-256 **private** key | Android Keystore / StrongBox | Non-exportable, biometric-gated |
| Mock balance, transaction log | `EncryptedSharedPreferences` | Demo state only |
| Reference print fixtures | App assets | Public SOCOFing samples, for the PAD self-test |

> `SecurePrefs` falls back to plain `SharedPreferences` if `EncryptedSharedPreferences`
> cannot initialise, because `security-crypto` is an alpha artifact that fails on some
> devices. **This fails open** — acceptable for a research demo, wrong for production,
> where it should fail closed. The active mode is surfaced in the registration output.

### Stored on the server

| Data | Column | Why it is not biometric |
|---|---|---|
| EC P-256 **public** key | `users.public_key` | Public half only; cannot reconstruct a print |
| Liveness score | `transactions.liveness_score` | A single float in [0,1] — a scalar, not an image |
| Assertion | `transactions.assertion` | A signature over a random challenge |
| Amount, recipient, tier, verdict | `transactions.*` | Transaction metadata |
| Name, phone, occupation | `users.*` | Ordinary PII, not biometric |

Phone numbers and names **are** personal data under NDPR/GDPR even though they are not
biometric. A production deployment needs a lawful basis, a retention policy, and a subject
access process. `auth_challenges` rows are transient and should be pruned.

---

## Known limitations

1. **No raw fingerprint capture on Android.** `BiometricPrompt` returns only success or
   failure — the platform exposes no API for a fingerprint image. The PAD model therefore
   scores a **bundled reference print**, not a live capture. A real deployment needs an
   external scanner SDK. This is a platform constraint, not an implementation shortcut, and
   it means the demo's liveness result is illustrative rather than a live measurement.
2. **PAD is not perfect.** Worst-case PAI APCER is 2.24 % (Z-cut on lightly altered
   prints). Roughly 1 in 45 of that attack class would pass at threshold 0.5.
3. **Preprocessing parity is empirical, not proven.** The Kotlin CLAHE and bicubic
   implementations reproduce OpenCV closely but are not guaranteed bit-identical at image
   borders. The on-device self-test measures the actual divergence; use OpenCV for Android
   if you need a hard guarantee.
4. **Demo-grade backend configuration.** CORS is `*`, the JWT secret defaults to a
   placeholder, and there is no rate limiting or authentication on `GET /transactions` —
   anyone with a `user_id` can read that user's history.
5. **The mock ledger is not a ledger.** Balances are local, non-authoritative, and resettable
   from the UI.
6. **Offline fallback approves locally.** By design, so a user study can run without
   connectivity — but it means an attacker who can block the network downgrades the
   verification. Disable the fallback for any real deployment.

---

## Reporting a vulnerability

Please report security issues **privately**. Do not open a public issue for anything
exploitable.

**Preferred:** [GitHub Security Advisories](https://github.com/<your-username>/sfmpas/security/advisories/new)
— use the *Report a vulnerability* button, which opens a private channel.

**Alternative:** email the maintainer with `SFMPAS SECURITY` in the subject.

Please include: what the issue is, how to reproduce it, the affected component (model,
Android app, or backend), the impact you believe it has, and any suggested fix.

### What to expect

| Stage | Target |
|---|---|
| Acknowledgement | within 5 working days |
| Initial assessment | within 14 days |
| Fix or documented mitigation | depends on severity; you will be kept updated |

This is an academic project maintained by one person, so response times are best-effort
rather than contractual. Reporters who wish to be credited will be named in the advisory
and release notes. Please give a reasonable window before public disclosure.

### Out of scope

- The known limitations listed above (they are documented, not undiscovered)
- Vulnerabilities requiring a rooted device or a physically compromised handset
- Findings against a deployment that changed the defaults documented here
- The permissive demo configuration on any public Render instance
