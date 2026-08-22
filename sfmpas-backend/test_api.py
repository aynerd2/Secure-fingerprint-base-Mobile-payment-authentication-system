"""
End-to-end test for the SFMPAS backend.

Simulates the Android client: generates an EC P-256 key pair, registers the
public half, requests a challenge, signs it with SHA256withECDSA, and completes
the authorisation. The key handling here mirrors Android Keystore exactly —
X.509 SubjectPublicKeyInfo for the key, DER-encoded ECDSA for the signature —
so a pass here means the real handset will interoperate.

Run against a live server:
    python test_api.py
    python test_api.py --base-url http://192.168.1.50:8000
"""

from __future__ import annotations

import argparse
import base64
import sys
import time
import uuid

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

PASSED = 0
FAILED = 0


def check(label: str, condition: bool, detail: str = "") -> bool:
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"  [PASS] {label}")
    else:
        FAILED += 1
        print(f"  [FAIL] {label}" + (f"\n         {detail}" if detail else ""))
    return condition


def banner(title: str) -> None:
    print("\n" + "=" * 74)
    print(f"  {title}")
    print("=" * 74)


class SimulatedDevice:
    """Stands in for the handset's Keystore credential."""

    def __init__(self) -> None:
        self._private = ec.generate_private_key(ec.SECP256R1())

    @property
    def public_key_b64(self) -> str:
        der = self._private.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return base64.b64encode(der).decode()

    def sign_challenge(self, challenge_b64: str) -> str:
        """SHA256withECDSA over the raw challenge bytes -> base64 DER."""
        challenge = base64.b64decode(challenge_b64)
        signature = self._private.sign(challenge, ec.ECDSA(hashes.SHA256()))
        return base64.b64encode(signature).decode()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()
    base = args.base_url.rstrip("/")
    http = requests.Session()

    def post(path: str, payload: dict):
        return http.post(f"{base}{path}", json=payload, timeout=args.timeout)

    def get(path: str, params: dict):
        return http.get(f"{base}{path}", params=params, timeout=args.timeout)

    print(f"SFMPAS backend test  ->  {base}")

    # -- wait for the server ------------------------------------------------
    banner("0 · Server reachability")
    ready = False
    for attempt in range(20):
        try:
            r = http.get(f"{base}/health", timeout=args.timeout)
            if r.status_code == 200:
                ready = True
                break
            print(f"  ... /health returned {r.status_code}, retrying")
        except requests.RequestException as exc:
            print(f"  ... not up yet ({type(exc).__name__}), retry {attempt + 1}/20")
        time.sleep(2)
    if not check("server is reachable and database is up", ready,
                 f"could not get a healthy /health from {base}"):
        print("\nAborting: start the server first (docker compose up --build).")
        return 1

    device = SimulatedDevice()
    user_id = f"study-{uuid.uuid4().hex[:8]}"

    # -- 1. /register -------------------------------------------------------
    banner("1 · POST /register")
    r = post("/register", {
        "user_id": user_id,
        "username": "Ayobami Ogunlade",
        "phone_number": "08012345678",
        "occupation": "MANUAL_LABOUR_WORKER",
        "public_key": device.public_key_b64,
    })
    check("returns 200", r.status_code == 200, f"got {r.status_code}: {r.text[:300]}")
    if r.status_code == 200:
        body = r.json()
        check("echoes the user_id", body.get("user_id") == user_id)
        check("stores the occupation",
              body.get("occupation") == "MANUAL_LABOUR_WORKER")
        check("reports a registration timestamp", bool(body.get("registered_at")))

    r = post("/register", {
        "user_id": user_id, "username": "X", "phone_number": "08012345678",
        "occupation": "GENERAL_USER", "public_key": "not-a-real-key",
    })
    check("rejects a malformed public key with 400", r.status_code == 400,
          f"got {r.status_code}: {r.text[:200]}")

    # -- 2. /authenticate/begin --------------------------------------------
    banner("2 · POST /authenticate/begin  (CBN KYC tiering)")
    expectations = [
        (1_000, "TIER_1", False, False),
        (49_999, "TIER_1", False, False),
        (50_000, "TIER_2", True, False),      # inclusive lower bound
        (75_000, "TIER_2", True, False),
        (200_000, "TIER_2", True, False),     # inclusive upper bound
        (200_001, "TIER_3", True, True),
        (1_000_000, "TIER_3", True, True),
    ]
    for amount, expected_tier, needs_liveness, needs_enhanced in expectations:
        r = post("/authenticate/begin", {"user_id": user_id, "amount_naira": amount})
        if not check(f"NGN {amount:,} -> 200", r.status_code == 200,
                     f"got {r.status_code}: {r.text[:200]}"):
            continue
        b = r.json()
        check(f"NGN {amount:,} -> {expected_tier}", b.get("tier") == expected_tier,
              f"got {b.get('tier')}")
        check(f"NGN {amount:,} liveness flag = {needs_liveness}",
              b.get("requires_liveness") is needs_liveness)
        check(f"NGN {amount:,} enhanced flag = {needs_enhanced}",
              b.get("requires_enhanced") is needs_enhanced)
        check(f"NGN {amount:,} returns a challenge", bool(b.get("challenge")))

    r = post("/authenticate/begin", {"user_id": "nobody-here", "amount_naira": 1000})
    check("unknown user gets 404", r.status_code == 404, f"got {r.status_code}")

    # -- 3. /authenticate/complete -----------------------------------------
    banner("3 · POST /authenticate/complete")
    amount, recipient = 75_000, "Adaeze Okafor"

    r = post("/authenticate/begin", {"user_id": user_id, "amount_naira": amount})
    begin = r.json()
    challenge, challenge_id = begin["challenge"], begin["challenge_id"]

    r = post("/authenticate/complete", {
        "user_id": user_id,
        "assertion": device.sign_challenge(challenge),
        "amount_naira": amount,
        "recipient": recipient,
        "challenge_id": challenge_id,
        "liveness_score": 0.999578,
    })
    approved = check("valid assertion is APPROVED", r.status_code == 200,
                     f"got {r.status_code}: {r.text[:300]}")
    if approved:
        b = r.json()
        check("verdict is APPROVED", b.get("verdict") == "APPROVED")
        check("returns a transaction_id", bool(b.get("transaction_id")))
        check("tier recorded as TIER_2", b.get("tier") == "TIER_2")
        check("liveness score round-trips",
              abs((b.get("liveness_score") or 0) - 0.999578) < 1e-4)
        check("issues a signed receipt (JWT)",
              bool(b.get("receipt")) and b["receipt"].count(".") == 2)

    # replay of the same assertion must fail
    r = post("/authenticate/complete", {
        "user_id": user_id, "assertion": device.sign_challenge(challenge),
        "amount_naira": amount, "recipient": recipient,
        "challenge_id": challenge_id,
    })
    check("replayed challenge is rejected (409)", r.status_code == 409,
          f"got {r.status_code}: {r.text[:200]}")

    # forged signature from a different key
    impostor = SimulatedDevice()
    r = post("/authenticate/begin", {"user_id": user_id, "amount_naira": amount})
    forged_challenge = r.json()["challenge"]
    r = post("/authenticate/complete", {
        "user_id": user_id,
        "assertion": impostor.sign_challenge(forged_challenge),
        "amount_naira": amount, "recipient": recipient,
    })
    check("signature from the wrong key is rejected (401)", r.status_code == 401,
          f"got {r.status_code}: {r.text[:200]}")

    # amount tampering: sign a challenge issued for one amount, claim another
    r = post("/authenticate/begin", {"user_id": user_id, "amount_naira": 10_000})
    tamper = r.json()
    r = post("/authenticate/complete", {
        "user_id": user_id,
        "assertion": device.sign_challenge(tamper["challenge"]),
        "amount_naira": 500_000, "recipient": recipient,
        "challenge_id": tamper["challenge_id"],
    })
    check("amount mismatch is rejected (409)", r.status_code == 409,
          f"got {r.status_code}: {r.text[:200]}")

    # failing liveness at Tier 2 must block
    r = post("/authenticate/begin", {"user_id": user_id, "amount_naira": amount})
    live = r.json()
    r = post("/authenticate/complete", {
        "user_id": user_id,
        "assertion": device.sign_challenge(live["challenge"]),
        "amount_naira": amount, "recipient": recipient,
        "challenge_id": live["challenge_id"],
        "liveness_score": 0.000016,
    })
    check("presentation attack blocked at Tier 2 (403)", r.status_code == 403,
          f"got {r.status_code}: {r.text[:200]}")

    # -- 4. /transactions ---------------------------------------------------
    banner("4 · GET /transactions")
    r = get("/transactions", {"user_id": user_id})
    check("returns 200", r.status_code == 200, f"got {r.status_code}: {r.text[:200]}")
    if r.status_code == 200:
        b = r.json()
        txs = b.get("transactions", [])
        check("history is non-empty", len(txs) > 0, f"count={len(txs)}")
        check("contains the approved payment",
              any(t["verdict"] == "APPROVED" and t["amount_naira"] == amount
                  for t in txs))
        check("rejections are logged too (audit trail)",
              any(t["verdict"] == "REJECTED" for t in txs))
        check("newest first",
              all(txs[i]["created_at"] >= txs[i + 1]["created_at"]
                  for i in range(len(txs) - 1)))
        check("no biometric/image field is returned",
              not any(k in t for t in txs
                      for k in ("image", "fingerprint", "template", "minutiae")))

    r = get("/transactions", {"user_id": "nobody-here"})
    check("unknown user gets 404", r.status_code == 404, f"got {r.status_code}")

    # -- summary ------------------------------------------------------------
    banner("SUMMARY")
    total = PASSED + FAILED
    print(f"  passed {PASSED}/{total}   failed {FAILED}")
    print(f"  test user: {user_id}")
    if FAILED == 0:
        print("\n  ALL ENDPOINTS WORKING.")
        return 0
    print("\n  SOME CHECKS FAILED — see [FAIL] lines above.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
