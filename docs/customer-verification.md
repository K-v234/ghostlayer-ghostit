# Ghost IT — Binary Verification Guide
**Ghost Layer Technologies · Chennai, India**
**Version 1.0 · June 2026**
**CONFIDENTIAL — For Pilot Customers Only**

---

## Why Verify?

Every Ghost IT agent binary is cryptographically signed and recorded in a public transparency log before it reaches you. This means you can independently verify that:

1. The binary was built by Ghost Layer Technologies — not modified by anyone else
2. The build process is documented and auditable
3. No one — including us — can secretly swap your binary after the fact

This is called **Supply Chain Integrity** and it is built into Ghost IT from day one.

---

## What You Need

Install these two tools on the machine where you will run the verification:

```bash
curl -sLO https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
sudo mv cosign-linux-amd64 /usr/local/bin/cosign
sudo chmod +x /usr/local/bin/cosign

curl -sLO https://github.com/slsa-framework/slsa-verifier/releases/latest/download/slsa-verifier-linux-amd64
sudo mv slsa-verifier-linux-amd64 /usr/local/bin/slsa-verifier
sudo chmod +x /usr/local/bin/slsa-verifier
```

---

## Files You Receive

| File | Purpose |
|---|---|
| `ghostit-agent-linux-amd64` | The agent binary |
| `ghostit-agent-linux-amd64.cosign.bundle` | Cryptographic signature |
| `ghostit-agent-linux-amd64.intoto.jsonl` | SLSA L3 build provenance |

---

## Step 1 — Verify the Signature

```bash
cosign verify-blob \
  --bundle ghostit-agent-linux-amd64.cosign.bundle \
  --certificate-identity \
    "https://github.com/K-v234/ghostlayer-ghostit/.github/workflows/release.yml" \
  --certificate-oidc-issuer \
    "https://token.actions.githubusercontent.com" \
  ghostit-agent-linux-amd64
```

Expected output: `Verified OK`

If you see anything else — do not install. Contact Ghost Layer Technologies immediately.

---

## Step 2 — Verify the Build Provenance

```bash
slsa-verifier verify-artifact ghostit-agent-linux-amd64 \
  --provenance-path ghostit-agent-linux-amd64.intoto.jsonl \
  --source-uri github.com/K-v234/ghostlayer-ghostit \
  --source-tag v1.0.0
```

Expected output: `Verified build provenance: OK`

---

## Step 3 — Verify on Every Update

Every time you receive a new Ghost IT binary, repeat Steps 1 and 2 before installing. The agent also verifies its own binary hash against the Rekor transparency log on every startup.

---

## What Happens if Verification Fails?

| Scenario | Meaning | Action |
|---|---|---|
| cosign fails | Binary modified after signing | Do not install. Contact us. |
| slsa-verifier fails | Binary not built from our pipeline | Do not install. Contact us. |
| Agent startup tamper alert | Binary modified after installation | Isolate machine. Contact us. |

---

## Transparency Log

Every Ghost IT binary is permanently recorded in the Rekor public transparency log:
https://rekor.sigstore.dev

---

## Contact

Ghost Layer Technologies — Chennai, India
security@ghostlayer.in
Response SLA: 4 hours

---

*Ghost IT V1 Pilot Customer Package · Ghost Layer Technologies · June 2026*
