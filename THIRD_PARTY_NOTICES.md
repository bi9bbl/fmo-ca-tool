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
