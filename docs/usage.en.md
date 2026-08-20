# fmo-ca-tool Usage Guide

[简体中文](usage.md) | [Project README](../README.en.md)

This guide covers image acquisition and verification, local builds, certificate issuance, offline deployment, and private-key storage for `fmo-ca-tool`. See the [project README](../README.en.md) for the project overview, protocol design, and model.

## Images and public builds

Public image:

```text
ghcr.io/bi9bbl/fmo-ca-tool
```

Image tags include both multi-platform variants that select the host architecture automatically and single-platform variants with an explicit CPU architecture suffix:

```text
ghcr.io/bi9bbl/fmo-ca-tool:latest
ghcr.io/bi9bbl/fmo-ca-tool:latest-amd64
ghcr.io/bi9bbl/fmo-ca-tool:latest-arm64
```

The `latest`, `main`, `sha-<40-character-Git-commit>`, original `v*` Git tag, and semantic-version tags each receive corresponding `-amd64` and `-arm64` tags. Without a suffix, Docker selects the host-compatible image from the multi-platform index. GitHub attestations are created separately for the top-level multi-platform digest, the amd64 manifest digest, and the arm64 manifest digest, allowing independent verification of architecture-specific tags.

The image is built by the repository's public workflow:

- Source: https://github.com/bi9bbl/fmo-ca-tool
- Build workflow: https://github.com/bi9bbl/fmo-ca-tool/actions/workflows/docker.yml
- Workflow source: [`.github/workflows/docker.yml`](../.github/workflows/docker.yml)
- Dockerfile: [`Dockerfile`](../Dockerfile)

The workflow builds `linux/amd64` and `linux/arm64` on a public GitHub-hosted runner, pushes the images to GHCR, and generates:

- Maximum-level BuildKit provenance.
- An SBOM.
- SLSA build-provenance attestations signed through GitHub OIDC and Sigstore.
- OCI `source` and `revision` labels tied to the exact Git commit.

Base images are pinned by immutable digest, dependency resolution uses the repository lock file, and third-party Actions in the publication workflow are pinned to full commit SHAs. Changes to base images, dependencies, the Dockerfile, workflows, or application source must therefore appear in a public Git commit.

> **Important:** A public repository does not mean the code has been security-audited. Cryptographic evidence can establish the repository, commit, and workflow that produced an image, but it cannot replace human review. Before producing a Root CA, audit the exact commit and verify that the pulled image attestation refers to that commit.

## Pull and strictly verify a public image

Do not rely only on `latest`, `main`, or version tags because tags can move. For production use, resolve and record an immutable digest first, then always run the image as `name@sha256:...`.

The following example verifies that:

1. The image attestation belongs to `bi9bbl/fmo-ca-tool`.
2. The signer is this repository's `docker.yml` workflow.
3. The build did not use a self-hosted runner.
4. The source ref is the selected version tag.
5. The source commit exactly matches the reviewed and recorded 40-character Git commit SHA.

```bash
TAG=v1.0.0
REPOSITORY=ghcr.io/bi9bbl/fmo-ca-tool
AUDITED_COMMIT='<40_CHARACTER_AUDITED_COMMIT_SHA>'

docker pull "${REPOSITORY}:${TAG}"
PINNED_IMAGE="$(docker image inspect "${REPOSITORY}:${TAG}" \
  --format '{{index .RepoDigests 0}}')"

printf 'Pinned image: %s\n' "${PINNED_IMAGE}"

gh attestation verify "oci://${PINNED_IMAGE}" \
  --repo bi9bbl/fmo-ca-tool \
  --signer-workflow bi9bbl/fmo-ca-tool/.github/workflows/docker.yml \
  --source-ref "refs/tags/${TAG}" \
  --source-digest "${AUDITED_COMMIT}" \
  --deny-self-hosted-runners

docker pull "${PINNED_IMAGE}"
docker image inspect "${PINNED_IMAGE}" \
  --format '{{json .Config.Labels}}'
```

Windows PowerShell:

```powershell
$Tag = "v1.0.0"
$Repository = "ghcr.io/bi9bbl/fmo-ca-tool"
$AuditedCommit = "<40_CHARACTER_AUDITED_COMMIT_SHA>"

docker pull "${Repository}:${Tag}"
$PinnedImage = docker image inspect "${Repository}:${Tag}" `
  --format '{{index .RepoDigests 0}}'

Write-Host "Pinned image: $PinnedImage"

gh attestation verify "oci://${PinnedImage}" `
  --repo bi9bbl/fmo-ca-tool `
  --signer-workflow bi9bbl/fmo-ca-tool/.github/workflows/docker.yml `
  --source-ref "refs/tags/${Tag}" `
  --source-digest $AuditedCommit `
  --deny-self-hosted-runners

docker pull $PinnedImage
docker image inspect $PinnedImage --format '{{json .Config.Labels}}'
```

To verify a single-platform tag, pull `${TAG}-amd64` or `${TAG}-arm64`, but keep `--source-ref` set to the original Git tag that produced the image: `refs/tags/${TAG}`. The workflow creates a separate attestation for each architecture manifest.

After verification succeeds, open the corresponding public Actions run and confirm that:

- The run commit matches the audited commit.
- The `Build and publish audited multi-platform image` step succeeded.
- The `Publish signed GitHub build attestation` step succeeded.
- The digest recorded in the run summary exactly matches `PINNED_IMAGE`.

Do not use the image to generate a Root CA if any value differs, an attestation is missing, or verification fails.

## Build locally from audited source

If the public package is unavailable or policy requires a local build:

```bash
git clone https://github.com/bi9bbl/fmo-ca-tool.git
cd fmo-ca-tool
git checkout <AUDITED_COMMIT_SHA>
git status --short

docker build \
  --label "org.opencontainers.image.revision=<AUDITED_COMMIT_SHA>" \
  -t fmo-ca-tool:audited .

docker run --rm --network none \
  --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true \
  fmo-ca-tool:audited --help
```

`git status --short` must produce no output. Before building, review the Dockerfile, lock file, certificate CBOR encoding, Ed25519 calls, safe-write logic, and build workflow in that commit.

Multi-platform build:

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --provenance=mode=max \
  --sbom=true \
  --output type=oci,dest=fmo-ca-tool.oci .
```

## Quick start

Local build:

```bash
docker build -t fmo-ca-tool:local .
docker run --rm --network none fmo-ca-tool:local --help
```

The public image automatically selects the current host architecture:

```bash
docker pull ghcr.io/bi9bbl/fmo-ca-tool:latest
docker image inspect ghcr.io/bi9bbl/fmo-ca-tool:latest \
  --format '{{.Os}}/{{.Architecture}}'
```

You can also select and verify the CPU architecture explicitly:

```bash
docker pull --platform linux/amd64 ghcr.io/bi9bbl/fmo-ca-tool:latest-amd64
docker pull --platform linux/arm64 ghcr.io/bi9bbl/fmo-ca-tool:latest-arm64

docker image inspect ghcr.io/bi9bbl/fmo-ca-tool:latest-amd64 \
  --format '{{.Os}}/{{.Architecture}}'
docker image inspect ghcr.io/bi9bbl/fmo-ca-tool:latest-arm64 \
  --format '{{.Os}}/{{.Architecture}}'
```

Use a verified public image in immutable form:

```bash
IMAGE='ghcr.io/bi9bbl/fmo-ca-tool@sha256:<VERIFIED_DIGEST>'
docker run --rm --network none "${IMAGE}" --help
```

Certificates and private keys must be written to the host through a bind mount. Never place private keys in a container layer, Dockerfile, Compose environment, Docker secret, build argument, or image.

## Complete Docker issuance workflow

The following examples assume that `IMAGE` contains a verified digest:

```bash
IMAGE='ghcr.io/bi9bbl/fmo-ca-tool@sha256:<VERIFIED_DIGEST>'
mkdir -p ./pki
chmod 700 ./pki
```

On Linux, run as the current UID and GID so private-key files are not owned by root or another UID:

```bash
DOCKER_CA=(
  docker run --rm
  --network none
  --user "$(id -u):$(id -g)"
  --read-only
  --cap-drop ALL
  --security-opt no-new-privileges:true
  --mount "type=bind,src=$(pwd)/pki,dst=/work/pki"
  "${IMAGE}"
)
```

### 1. Create a Root CA

```bash
"${DOCKER_CA[@]}" init-root \
  --name "BI9BBL FMO Root CA" \
  --email "ca@example.com" \
  --sn 900000001 \
  --key-id "bi9bbl-root-2026" \
  --crl "" --license "" \
  --valid-days 3650 \
  --out /work/pki/root
```

Output:

```text
pki/root/root.key.json
pki/root/root.cert.json
```

### 2. Issue an Intermediate CA

```bash
"${DOCKER_CA[@]}" issue-intermediate \
  --root-cert /work/pki/root/root.cert.json \
  --root-key /work/pki/root/root.key.json \
  --name "BI9BBL FMO Issuing CA" \
  --email "ca@example.com" \
  --sn 900001001 \
  --key-id "bi9bbl-intermediate-2026" \
  --uid-start 1 --uid-end 99999999 \
  --countries CN \
  --crl "" --license "" \
  --valid-days 1825 \
  --out /work/pki/intermediate
```

Output:

```text
pki/intermediate/intermediate.key.json
pki/intermediate/intermediate.cert.json
```

After successful issuance and backup of the Root material, return the Root private-key medium to offline storage. Routine User Certificate issuance requires only the Intermediate private key.

### 3. Issue a User Certificate

A normal endpoint should generate its own key and send only its 32-byte Ed25519 public key to the CA:

```bash
"${DOCKER_CA[@]}" issue-user \
  --intermediate-cert /work/pki/intermediate/intermediate.cert.json \
  --intermediate-key /work/pki/intermediate/intermediate.key.json \
  --root-cert /work/pki/root/root.cert.json \
  --callsign BI9BBL \
  --uid 12345 \
  --public-key '<BASE64URL_PUBLIC_KEY>' \
  --valid-days 365 \
  --out /work/pki/users/BI9BBL-12345.cert.json
```

Use `--generate-key` explicitly only for server identities, lab use, or test environments:

```bash
"${DOCKER_CA[@]}" issue-user \
  --intermediate-cert /work/pki/intermediate/intermediate.cert.json \
  --intermediate-key /work/pki/intermediate/intermediate.key.json \
  --root-cert /work/pki/root/root.cert.json \
  --callsign BI9BBL \
  --uid 12345 \
  --generate-key \
  --valid-days 365 \
  --out /work/pki/server
```

### 4. Calculate a fingerprint

```bash
"${DOCKER_CA[@]}" fingerprint \
  /work/pki/server/BI9BBL-12345.cert.json

FP="$("${DOCKER_CA[@]}" fingerprint --quiet \
  /work/pki/server/BI9BBL-12345.cert.json)"
printf 'SAS_CERT_FINGERPRINT=%s\n' "${FP}"
```

The fingerprint is strictly defined as:

```text
SHA-256(certificate.ToTbsCbor())
```

It is not a hash of the JSON file, public key, signature, or certificate-file bytes.

## Run with Compose

By default, Compose mounts only `./pki`, makes the container root filesystem read-only, and drops all Linux capabilities.

```bash
mkdir -p ./pki
chmod 700 ./pki
export FMO_CA_UID="$(id -u)"
export FMO_CA_GID="$(id -g)"

docker compose build cli
docker compose run --rm cli --help
docker compose run --rm cli fingerprint \
  /work/pki/server/BI9BBL-12345.cert.json
```

To use a public image, replace the `image` value in [`docker-compose.yml`](../docker-compose.yml) with the verified `name@sha256:...` reference and remove or disable the `build` section. This prevents a local rebuild from being confused with the verified digest.

## Generate a Root CA on a truly offline system

`--network none` alone is not physical isolation. For a high-value Root CA, use a dedicated offline host with no wireless hardware or with all network devices disabled.

### Online preparation system

On the networked preparation system, which must never hold the Root private key:

1. Audit the target Git commit.
2. Verify the image digest, workflow identity, and attestation as described above.
3. Pull an image that matches the offline host architecture.
4. Export the image and create a checksum for the transfer file.

```bash
PINNED_IMAGE='ghcr.io/bi9bbl/fmo-ca-tool@sha256:<VERIFIED_DIGEST>'

docker pull "${PINNED_IMAGE}"
docker tag "${PINNED_IMAGE}" fmo-ca-tool:verified-offline
docker save fmo-ca-tool:verified-offline \
  --output fmo-ca-tool-verified-offline.tar

sha256sum fmo-ca-tool-verified-offline.tar \
  > fmo-ca-tool-verified-offline.tar.sha256
```

Move the following items into the offline zone on clean media used only for transfer:

- `fmo-ca-tool-verified-offline.tar`
- The `.sha256` checksum file
- A paper or read-only record of the audited Git commit SHA and public Actions run URL
- The successful online attestation-verification output

### Offline CA host

1. Physically disconnect the host and disable wireless interfaces.
2. Verify the transfer file.
3. Import the image.
4. Generate the Root in a container with `--network none`, a read-only root filesystem, and only the encrypted CA medium mounted.

```bash
sha256sum --check fmo-ca-tool-verified-offline.tar.sha256
docker load --input fmo-ca-tool-verified-offline.tar

mkdir -p /media/encrypted-ca/fmo-pki
chmod 700 /media/encrypted-ca/fmo-pki

docker run --rm \
  --network none \
  --user "$(id -u):$(id -g)" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --mount type=bind,src=/media/encrypted-ca/fmo-pki,dst=/work/pki \
  fmo-ca-tool:verified-offline \
  init-root \
  --name "BI9BBL FMO Root CA" \
  --email "ca@example.com" \
  --sn 900000001 \
  --key-id "bi9bbl-root-2026" \
  --crl "" --license "" \
  --valid-days 3650 \
  --out /work/pki/root
```

After generation, issue the required Intermediate CAs and verify the certificates before unmounting and storing the Root private-key medium. Never copy the offline Root private key back to the networked preparation system.

### Additional guidance for a Live OS

A Live OS can reduce the chance of persistent CA data being left on local disks, but it does not replace trusted boot, physical isolation, or encryption of private keys at rest. For a high-value Root CA, include the following checks in the formal ceremony:

- **Verify the boot medium:** Obtain the Live OS image only from a trusted official source. On a clean networked preparation system, verify the publisher-provided hash and signature, and record the image version and digest. Test the boot medium, CPU architecture, container runtime, and offline image archive before the ceremony.
- **Ensure the session is non-persistent:** Boot without a persistence overlay, disable automatic mounting of internal disks, and do not use disk-backed swap or hibernation. Confirm that container storage, temporary directories, logs, shell history, and crash dumps cannot be written to the boot USB drive or an internal disk.
- **Disable networking physically:** Unplug Ethernet and disable wireless hardware in firmware or with a hardware control. After boot, confirm again that every network interface is unavailable. Do not treat `--network none` or a desktop status icon as proof of physical isolation.
- **Prepare the runtime in advance:** The Live OS must already contain a working Docker or equivalent container runtime and the verified offline image tar. After Root private-key generation begins, never connect the system temporarily to install software, download dependencies, or repair the environment.
- **Write only to encrypted CA media:** Do not output keys to the Live OS, boot USB drive, or internal disk. Mount only dedicated encrypted removable media, and expose only the directory required by the current command through the container bind mount. The ephemeral nature of a Live OS does not encrypt output files.
- **Close the session completely:** After issuance and verification, flush write caches, unmount and lock the encrypted medium, confirm that outputs are readable and the backup policy has been followed, and then power the host off completely. Rebooting or removing power is not secure erasure of RAM, firmware, or attached devices.

A Live OS cannot defend against compromised firmware, a malicious boot image, hardware implants, memory attacks, or procedural violations by people in the room. A high-value CA still requires controlled hardware, a verifiable boot policy, dual control, an operation record, and a repeatable, rehearsed ceremony.

## Private-key storage

### Private-key files are not password-encrypted

The `privateKey` value in each `*.key.json` file is a **plaintext 32-byte Ed25519 seed** represented as unpadded Base64URL. The JSON file itself has no password, KDF, or encryption.

A read-only container filesystem, non-root user, and `0600` permissions do not provide encryption at rest. Production private keys must reside on a host-encrypted volume or encrypted removable medium, such as an organization-managed LUKS, BitLocker, or equivalent full-disk or volume-encryption system.

### Root private key

- Apply the highest security level and use it only in a physically isolated, offline CA environment.
- Keep at least two encrypted, offline, geographically separated backups, with recovery credentials stored separately.
- Use dual control, access logs, regular recovery exercises, and media-health checks.
- Never place it in Git, cloud storage, email, chat, tickets, CI artifacts, Docker images, Docker volume snapshots, or a long-running server.
- Never place it in SAS, EMQX, FAS, or `fmo-server-suite`.
- Do not use `--force` in production directories because it permits replacement of an existing private key.
- On SSDs, copy-on-write filesystems, and snapshot systems, ordinary deletion is not secure erasure. Prefer a dedicated encrypted volume and retire it by destroying the encryption key and following the organization's media-destruction procedure.

The Root certificate is not secret. Keep multiple independent public copies and deploy it to the SAS trust store and devices that trust this PKI.

### Intermediate private key

- Use it for routine User Certificate issuance and keep it separate from the Root private key.
- It may reside on a controlled issuance host, but still requires encrypted storage, least privilege, offline backups, and access auditing.
- If it is compromised, stop issuance, revoke or replace the Intermediate, and assess every subordinate certificate.

### User private key

- A normal endpoint should generate its key locally; the CA accepts `--public-key` or `--public-key-file` by default.
- Do not generate and retain every endpoint private key centrally for convenience.
- `--generate-key` is primarily for server identities, testing, and development; its generated key file also contains a plaintext seed.

### Host permissions

Linux:

```bash
chmod 700 ./pki ./pki/root ./pki/intermediate
chmod 600 ./pki/root/*.key.json ./pki/intermediate/*.key.json
```

Run the container with the current host user's UID and GID. On Windows, use a dedicated account, restrict NTFS ACLs, and place the directory on a BitLocker-protected or equivalently protected volume.

Never mount the Docker socket into the CA container. Access to the Docker daemon is generally equivalent to high privilege on the host and may allow private keys in bind mounts to be read.

## Image runtime security boundary

Always prefer:

- `--network none`
- `--read-only`
- `--cap-drop ALL`
- `--security-opt no-new-privileges:true`
- A non-root UID and GID
- Only the CA directory needed for the current command
- An immutable image digest verified through its attestation

The image requires no network, database, MQTT service, Docker socket, or other service. It does not start SAS, modify other repositories, or edit `fmo-server-suite`.

The image exposes only four commands: `init-root`, `issue-intermediate`, `issue-user`, and `fingerprint`. It contains no CRL issuance, daemon, Web UI, or online CA service.

## Related documents

- [Project overview, design, and model](../README.en.md)
- [简体中文使用指南](usage.md)
- [Third-party components and compatibility sources](../THIRD_PARTY_NOTICES.md)
- [GNU General Public License v3.0](../LICENSE)
