# Third-party notices

## BG5ESN/fmo-server-authrozier-service

- Source: https://github.com/BG5ESN/fmo-server-authrozier-service
- Local compatibility baseline: its `main` branch as inspected during this project's initial implementation
- License: GNU General Public License v3.0

The FMO V4 certificate TBS CBOR layouts, Base64URL behavior, and Ed25519 calling conventions in this repository were implemented directly against the upstream protocol documentation and certificate classes, especially:

- `docs/V4.0 Protocol - Signatures & Certificates.md`
- `src/certs/CertBase.cs`
- `src/certs/RootCaCert.cs`
- `src/certs/IntermediateCaCert.cs`
- `src/certs/UserCert.cs`
- `src/certs/Base64Url.cs`
- `src/certs/Ed25519.cs`
- `src/Trust/RootCaStore.cs`
- `src/Trust/CertVerifier.cs`

To avoid a misleading permissive license on compatibility-derived code, this repository is distributed under GPL-3.0 as well. See `LICENSE`.

## BG5ESN/fmo-certificate-tools

- Source: https://github.com/BG5ESN/fmo-certificate-tools
- Compatibility baseline: commit `cd99bd0e90b807c66f302bddfbe4f95a054f2081`
- License: GNU General Public License v3.0

The two-level CRL JSON models, fixed CBOR arrays, reason-code ranges, signature rules, and `sn/uid + certFingerprint` revocation matching were implemented against:

- `docs/V4.0 Protocol Root CRL Formate.md`
- `docs/V4.0 Protocol Intermediate CRL Formate.md`
- `fmo-ca-cert-cli/Program.cs`

Tests in this repository compare Root and Intermediate CRL TBS bytes with the reference implementation for the same semantic values.

## QRCoder

- Source: https://github.com/codebude/QRCoder
- Package: `QRCoder` 1.7.0
- License: MIT

QRCoder is used only by the `qr` auxiliary command to encode explicitly supplied text or file content as a PNG. It is not involved in FMO certificate, CRL, fingerprint, key-generation, signing, or verification logic.
