# fmo-ca-tool

[简体中文](README.md) | [Usage Guide](docs/usage.en.md)

## Project Overview

`fmo-ca-tool` is an offline CA tool for the FMO V4 custom PKI. It implements the FMO certificate protocol rather than X.509 and has these responsibilities:

- Create a self-signed Root CA.
- Issue an Intermediate CA from the Root CA.
- Issue a User Certificate from the Intermediate CA.
- Verify Root, Intermediate, and User Certificates, complete chains, and validity periods.
- Issue Root CRLs that revoke a specific Intermediate CA by `sn + certFingerprint`.
- Issue Intermediate CRLs that revoke a specific User Certificate by `uid + certFingerprint`.
- Verify CRL signatures, update windows, and certificate revocation status.
- Generate endpoint-owned Ed25519 keys and QR-code PNGs from explicit text or files.
- Calculate the certificate fingerprint defined by the protocol.

The project exposes nine commands: `init-root`, `issue-intermediate`, `issue-user`, `verify`, `issue-root-crl`, `issue-intermediate-crl`, `generate-key`, `qr`, and `fingerprint`. It provides no daemon, Web UI, online CA, OCSP responder, or automatic publication service. See the [Usage Guide](docs/usage.en.md) for image verification, execution, issuance and revocation workflows, offline deployment, and private-key storage.

This implementation targets byte-level compatibility with SAS and the official FMO format tool. Root, Intermediate, and User Certificate TBS CBOR has been compared byte for byte with SAS; Root and Intermediate CRL TBS CBOR has been compared byte for byte with the official reference tool; certificate-chain signature verification and Root trust-store loading have also passed compatibility validation. The project is licensed under the [GNU General Public License v3.0](LICENSE). See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for compatibility sources and third-party components.

## Design

### Trust hierarchy

The certificate system uses a fixed three-level trust hierarchy:

```text
Root CA (trust anchor, self-signed, pathLen = 1)
├── Root CRL (revokes a specific Intermediate CA)
└── Intermediate CA (issuance constraints, pathLen = 0)
    ├── Intermediate CRL (revokes a specific User Certificate)
    └── User Certificate (client or service identity)
```

The Root CA establishes the trust anchor, issues Intermediate CAs, and signs Root CRLs offline. An Intermediate CA expresses its authority through a UID range and a set of issuing countries, and performs routine User Certificate and Intermediate CRL issuance. A User Certificate binds a callsign, UID, and Ed25519 public key and cannot issue further certificates. CRLs are public, cacheable signed objects and contain no private material.

### Data and signature boundaries

Certificates and CRLs use JSON as their persistent interchange format, with binary fields represented as unpadded Base64URL. JSON itself is not signed. Each object type is first encoded as a fixed-length CBOR array in the protocol-defined field order, and Ed25519 signs that CBOR byte string.

This design separates the human-readable interchange representation from the unique cryptographic representation. JSON indentation, property order, and whitespace do not change the signature input or certificate fingerprint. The signature field is not part of the TBS value, avoiding recursive encoding.

CBOR encoding uses the fixed FMO V4 field order and data types. Root, Intermediate, and User TBS arrays contain 15, 20, and 9 items respectively. Both CRL outer TBS arrays contain 8 items, with fixed 4-item nested revocation entries. Integers are written through the signed 64-bit integer interface. Reordering fields, changing types, or signing JSON instead would break protocol compatibility. CRL entries sort first by `sn` or `uid`, then by the raw-byte ordering of the 32-byte fingerprint.

### Key ownership and security boundaries

- Root and Intermediate keys are generated when the corresponding CA is created or issued. A private-key file stores a 32-byte Ed25519 seed and has no built-in password encryption.
- A User private key is owned by the endpoint by default, and the CA receives only the 32-byte public key. The tool generates a User private key only when explicitly requested, preventing the CA from becoming the central custodian of endpoint keys.
- `generate-key` supports endpoint-side key generation. `qr` encodes only explicitly supplied text or files and never discovers certificates or private keys automatically.
- The tool requires no network, database, MQTT service, Docker socket, or other external service at runtime, so it can operate in an isolated environment.
- Output is written atomically and existing certificates or private keys are not overwritten by default. Intermediate issuance verifies the Root self-signature, key match, and expiration. User issuance verifies the Intermediate key, expiration, and UID range, verifies the full issuer chain when a Root is supplied, and verifies the new certificate signature before writing it.
- Docker is the project delivery boundary. Public builds produce `linux/amd64` and `linux/arm64` images, an SBOM, provenance, and GitHub build attestations. Supply-chain evidence establishes build origin but does not replace source-code and cryptographic review.

### Implementation layers

| Layer | Primary location | Responsibility |
| --- | --- | --- |
| Command orchestration | `src/FmoCaTool/Commands` | Parameter constraints, issuance workflows, and post-issuance verification |
| Certificate model | `src/FmoCaTool/Certs` | FMO fields, CBOR TBS encoding, certificate validation, and fingerprints |
| CRL model | `src/FmoCaTool/Crls` | Two-level CRLs, CBOR TBS encoding, canonical sorting, and the JSON boundary |
| Cryptography | `src/FmoCaTool/Crypto` | Ed25519 keys, signing, verification, and the Base64URL boundary |
| Safe output | `src/FmoCaTool/IO` | Atomic writes, permissions, and overwrite protection |
| Compatibility validation | `tests` | Protocol vectors, JSON round trips, signature chains, and CLI behavior |

## Model

### Notation

Let:

- `CBOR_n([x_1, ..., x_n])` denote a CBOR array of length `n`, encoded strictly in the given order.
- `(sk_X, pk_X)` denote the Ed25519 private and public keys of entity `X`; the persisted private material is a 32-byte seed from which the key pair is derived.
- `S(sk, m)` and `V(pk, m, sig)` denote Ed25519 signing and verification.
- `H(m) = SHA-256(m)`.
- `iat_X` and `exp_X` denote the certificate's Unix timestamps in seconds.

Text strings, byte strings, Boolean values, and integers use their corresponding CBOR types. All protocol integers are written through a signed 64-bit integer interface. The tuple ordering below is part of the protocol.

### Root CA

The Root CA TBS byte string is:

```text
T_R = CBOR_15([
  "FMO", 4, "rootCA", sn_R,
  issuerName_R, issuerEmail_R, subjectName_R, pk_R,
  true, 1, crl_R, license_R, keyId_R, iat_R, exp_R
])
```

Here, `issuerName_R = subjectName_R`. The Root signs with its own private key and verifies with its own public key:

```text
sig_R = S(sk_R, T_R)
V(pk_R, T_R, sig_R) = true
```

### Intermediate CA

The Intermediate CA TBS byte string is:

```text
T_I = CBOR_20([
  "FMO", 4, "intermediateCA", sn_I,
  sn_R, subjectName_R, pk_R,
  subjectName_I, subjectEmail_I, pk_I,
  true, 0, keyId_I, crl_I, license_I,
  uidMin_I, uidMax_I, countries_I, iat_I, exp_I
])
```

`countries_I` is an array of normalized, deduplicated, lexically ordered, two-letter uppercase country codes. The Root signs the Intermediate:

```text
sig_I = S(sk_R, T_I)
V(pk_R, T_I, sig_I) = true
```

### User Certificate

The User Certificate TBS byte string is:

```text
T_U = CBOR_9([
  "FMO", 4, "userCert", sn_I,
  callsign_U, uid_U, pk_U, iat_U, exp_U
])
```

The Intermediate signs the User Certificate:

```text
sig_U = S(sk_I, T_U)
V(pk_I, T_U, sig_U) = true
```

### Two-level CRLs

The Root CRL TBS byte string and signature are:

```text
T_RL = CBOR_8([
  "FMO", 4, "rootCRL", sn_R, crlNumber_R,
  thisUpdate_R, nextUpdate_R,
  [[sn_I, H(T_I), revokedAt, reason], ...]
])

sig_RL = S(sk_R, T_RL)
V(pk_R, T_RL, sig_RL) = true
```

The Intermediate CRL model is:

```text
T_IL = CBOR_8([
  "FMO", 4, "intermediateCRL", sn_I, crlNumber_I,
  thisUpdate_I, nextUpdate_I,
  [[uid_U, H(T_U), revokedAt, reason], ...]
])

sig_IL = S(sk_I, T_IL)
V(pk_I, T_IL, sig_IL) = true
```

`H(T_I)` and `H(T_U)` are 32-byte CBOR byte strings and are represented as Base64URL only in JSON. A Root CRL revokes an Intermediate only when both `sn_I` and `H(T_I)` match and `revokedAt <= t`. The Intermediate CRL analogously requires both `uid_U` and `H(T_U)`. A serial-number-only or UID-only match does not revoke a later reissued certificate.

### Constraints and chain validation

The issuance model satisfies at least the following structural constraints:

```text
sn_R > 0
sn_I > 0
sn_I != sn_R

0 <= uidMin_I <= uid_U <= uidMax_I

iat_R < exp_R
iat_I < exp_I <= exp_R
iat_U < exp_U <= exp_I

len(pk_R) = len(pk_I) = len(pk_U) = 32 bytes
len(sig_R) = len(sig_I) = len(sig_U) = 64 bytes
```

The Intermediate's `issuerSn`, `issuerName`, and `issuerPublicKey` fields must bind to the Root's serial number, subject name, and public key. The User Certificate's `issuerSn` must bind to the Intermediate's serial number. Given trusted Root `R`, Intermediate `I`, User Certificate `U`, and validation time `t`, the complete trust relation can be written as:

```text
ChainValid(R, I, U, t) =
    TrustedAnchor(R)
  AND V(pk_R, T_R, sig_R)
  AND BindIssuer(R, I)
  AND V(pk_R, T_I, sig_I)
  AND (uidMin_I <= uid_U <= uidMax_I)
  AND (sn_I = issuerSn_U)
  AND V(pk_I, T_U, sig_U)
  AND NotRevoked_RL(I, t)
  AND NotRevoked_IL(U, t)
  AND (t < exp_R)
  AND (t < exp_I)
  AND (t < exp_U)
```

`TrustedAnchor(R)` cannot be inferred from a self-signature alone. It means the caller has configured the Root through a trusted channel. A self-signature proves that the certificate has not been modified, but it does not automatically make an unknown Root trustworthy.

`NotRevoked_RL` and `NotRevoked_IL` are evaluated only from caller-supplied CRLs whose signatures verify. Without a current CRL, the signature chain can be established, but revocation status cannot be claimed as current.

### Fingerprint

The FMO fingerprint of any certificate `X` is defined as:

```text
Fingerprint(X) = H(T_X) = SHA-256(X.ToTbsCbor())
```

The input is not the JSON file bytes, JSON formatting, the standalone public key, or the signature bytes. Base64URL and hexadecimal are only representations of the same 32-byte hash and do not change the fingerprint.
