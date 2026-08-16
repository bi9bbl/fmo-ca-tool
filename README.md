# fmo-ca-tool Docker image

`fmo-ca-tool` 是 FMO V4 自定义 PKI 的离线 CA 命令行容器，用于：

- 创建自签名 FMO Root CA。
- 使用 Root CA 签发 Intermediate CA。
- 使用 Intermediate CA 签发 User Certificate。
- 计算 `SHA-256(ToTbsCbor())` 定义的 FMO 证书指纹。

这不是 X.509 CA。镜像入口直接是 `fmo-ca-tool`，容器名后填写 `init-root`、`issue-intermediate`、`issue-user` 或 `fingerprint`。

## 镜像和公开构建

公开镜像地址：

```text
ghcr.io/bi9bbl/fmo-ca-tool
```

镜像由仓库中的公开工作流构建：

- 源代码：https://github.com/bi9bbl/fmo-ca-tool
- 构建工作流：https://github.com/bi9bbl/fmo-ca-tool/actions/workflows/docker.yml
- 工作流源码：[`.github/workflows/docker.yml`](.github/workflows/docker.yml)
- Dockerfile：[`Dockerfile`](Dockerfile)

工作流在公开 GitHub-hosted runner 上构建 `linux/amd64` 和 `linux/arm64`，推送 GHCR，并同时生成：

- 最大级别的 BuildKit provenance。
- SBOM。
- 使用 GitHub OIDC 与 Sigstore 签名的 SLSA build provenance attestation。
- 与具体 Git commit 对应的 OCI `source` 和 `revision` labels。

Docker 构建所用的基础镜像以不可变 digest 固定，依赖解析使用仓库内的 lock file；发布工作流引用的第三方 Actions 也固定到完整 commit SHA。修改基础镜像、依赖、Dockerfile、工作流或应用源码都必须表现为公开的 Git commit。

> **重要：**“仓库公开”不等于“代码已经安全审计”。密码学证明只能确认镜像来自哪个仓库、commit 和工作流，不能代替人工代码审计。生产 Root CA 应先审计准备使用的确切 commit，再验证所拉镜像的 attestation 确实指向该 commit。

### 首次发布时的 GHCR 可见性

GHCR Container package 的可见性可以独立于仓库。仓库维护者第一次推送镜像后，必须在 GitHub package settings 中将 `fmo-ca-tool` 设置为 **Public**，并保持它与本仓库关联。只有 Public package 才能匿名拉取。

如果匿名 `docker pull` 返回权限错误，不要改用来源不明的镜像；应检查 GHCR package 是否已经公开，或直接从审计过的 Git commit 本地构建。

## 拉取并严格验证公开镜像

不要只依赖 `latest`、`main` 或版本标签。这些标签可以移动。生产环境应先解析并记录不可变 digest，之后始终通过 `name@sha256:...` 使用镜像。

以下示例验证：

1. 镜像 attestation 属于 `bi9bbl/fmo-ca-tool`。
2. 签名者是本仓库的 `docker.yml` 工作流。
3. 构建没有使用 self-hosted runner。
4. 构建源 ref 是指定版本 tag。
5. 构建源 commit 与人工审计并记录的 40 位 Git commit SHA 完全一致。

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

Windows PowerShell：

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

验证成功后，还应打开对应的公开 Action run，核对：

- run 使用的 commit 与已审计 commit 相同。
- `Build and publish audited multi-platform image` 步骤成功。
- `Publish signed GitHub build attestation` 步骤成功。
- run summary 中记录的 digest 与 `PINNED_IMAGE` 完全一致。

任何一项不一致、attestation 缺失或验证失败时，都不要用该镜像生成 Root CA。

## 从审计过的源码本地构建

如果公开 package 尚不可用，或安全策略要求自行构建：

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

`git status --short` 必须为空。构建前应审计该 commit 中的 Dockerfile、lock file、证书 CBOR 编码、Ed25519 调用、安全写入逻辑和构建工作流。

多架构构建：

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --provenance=mode=max \
  --sbom=true \
  --output type=oci,dest=fmo-ca-tool.oci .
```

## 快速运行

本地构建：

```bash
docker build -t fmo-ca-tool:local .
docker run --rm --network none fmo-ca-tool:local --help
```

已验证的公开镜像应写成不可变形式：

```bash
IMAGE='ghcr.io/bi9bbl/fmo-ca-tool@sha256:<VERIFIED_DIGEST>'
docker run --rm --network none "${IMAGE}" --help
```

所有证书和私钥必须通过 bind mount 写入宿主机。不要把私钥写入容器层、Dockerfile、Compose environment、Docker secret、构建参数或镜像。

## 完整 Docker 签发流程

以下示例假设已经把经过验证的 digest 放入 `IMAGE`：

```bash
IMAGE='ghcr.io/bi9bbl/fmo-ca-tool@sha256:<VERIFIED_DIGEST>'
mkdir -p ./pki
chmod 700 ./pki
```

Linux 上使用当前 UID/GID，避免产生属于 root 或其他 UID 的私钥文件：

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

### 1. 创建 Root CA

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

生成：

```text
pki/root/root.key.json
pki/root/root.cert.json
```

### 2. 签发 Intermediate CA

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

生成：

```text
pki/intermediate/intermediate.key.json
pki/intermediate/intermediate.cert.json
```

签发成功并备份 Root 材料后，应把 Root 私钥介质重新离线封存。日常 User Certificate 签发只使用 Intermediate 私钥。

### 3. 签发 User Certificate

普通终端应自己生成密钥，只把 32 字节 Ed25519 公钥交给 CA：

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

只有服务器身份、实验室或测试环境才建议显式使用 `--generate-key`：

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

### 4. 计算 fingerprint

```bash
"${DOCKER_CA[@]}" fingerprint \
  /work/pki/server/BI9BBL-12345.cert.json

FP="$("${DOCKER_CA[@]}" fingerprint --quiet \
  /work/pki/server/BI9BBL-12345.cert.json)"
printf 'SAS_CERT_FINGERPRINT=%s\n' "${FP}"
```

Fingerprint 严格定义为：

```text
SHA-256(certificate.ToTbsCbor())
```

它不是 JSON 文件、公钥、签名或证书文件字节的哈希。

## Compose 运行

Compose 默认只挂载 `./pki`，容器根文件系统只读，并移除全部 Linux capabilities。

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

如果要使用公开镜像，把 [`compose.yml`](compose.yml) 中的 `image` 改成已经验证的 `name@sha256:...`，并删除或禁用 `build` 段，避免本地重建与已验证 digest 混淆。

## 真正离线生成 Root CA

仅使用 `--network none` 不等于物理隔离。高价值 Root CA 推荐使用专用、无无线网卡或已禁用网络设备的离线主机。

### 在线准备机

在联网但不持有 Root 私钥的准备机上：

1. 审计目标 Git commit。
2. 按前文验证镜像 digest、workflow identity 和 attestation。
3. 拉取与离线主机架构一致的镜像。
4. 导出镜像并生成传输文件校验值。

```bash
PINNED_IMAGE='ghcr.io/bi9bbl/fmo-ca-tool@sha256:<VERIFIED_DIGEST>'

docker pull "${PINNED_IMAGE}"
docker tag "${PINNED_IMAGE}" fmo-ca-tool:verified-offline
docker save fmo-ca-tool:verified-offline \
  --output fmo-ca-tool-verified-offline.tar

sha256sum fmo-ca-tool-verified-offline.tar \
  > fmo-ca-tool-verified-offline.tar.sha256
```

把以下材料通过干净、只用于传输的介质带入离线区：

- `fmo-ca-tool-verified-offline.tar`
- `.sha256` 校验文件
- 审计过的 Git commit SHA 和公开 Action run URL 的纸质或只读记录
- 在线验证成功的 attestation 输出

### 离线 CA 主机

1. 物理断网并禁用无线接口。
2. 校验传输文件。
3. 导入镜像。
4. 使用 `--network none`、只读根文件系统和只挂载加密 CA 介质的容器生成 Root。

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

生成后先签发所需 Intermediate CA、验证证书，再卸载并封存 Root 私钥介质。不要把离线 Root 私钥复制回联网准备机。

## 私钥如何保管

### 私钥文件没有口令加密

`*.key.json` 中的 `privateKey` 是无 padding base64url 表示的 **32 字节 Ed25519 seed 明文**。JSON 文件本身没有密码、KDF 或加密保护。

Docker 的只读根文件系统、非 root 用户和 `0600` 权限不能替代静态加密。生产私钥必须放在宿主机的加密卷或加密可移动介质中，例如受组织策略管理的 LUKS、BitLocker 或等效全盘/卷加密设施。

### Root private key

- 最高安全等级，只在物理隔离的离线 CA 环境使用。
- 至少制作两份加密、离线、地理隔离的备份；分别保管恢复凭据。
- 建议双人控制、访问登记、定期恢复演练和介质健康检查。
- 不得进入 Git、云盘、邮件、聊天工具、工单、CI artifact、Docker image、Docker volume snapshot 或长期运行服务器。
- 不得放入 SAS、EMQX、FAS 或 `fmo-server-suite`。
- 生产目录不要使用 `--force`；它允许覆盖现有私钥。
- SSD、写时复制文件系统和快照环境中，普通删除不等于安全擦除。优先在独立加密卷中操作，退役时销毁加密密钥并按组织介质销毁流程处理。

Root certificate 不是秘密。应单独保存多份公开副本，并部署到 SAS trust store 和信任该 PKI 的设备。

### Intermediate private key

- 用于日常 User Certificate 签发，应与 Root 私钥分离。
- 可以部署在受控签发主机，但仍应使用加密磁盘、最小权限、离线备份和访问审计。
- Intermediate 泄露时应停止签发、吊销/替换该 Intermediate，并评估所有下级证书。

### User private key

- 普通终端应在终端自身生成，CA 默认只接收 `--public-key` 或 `--public-key-file`。
- 不要为了方便集中生成并保存所有终端私钥。
- `--generate-key` 主要用于服务器身份、测试和开发环境；生成的 key 文件同样是明文 seed。

### 宿主机权限

Linux：

```bash
chmod 700 ./pki ./pki/root ./pki/intermediate
chmod 600 ./pki/root/*.key.json ./pki/intermediate/*.key.json
```

容器运行时应使用当前宿主用户的 UID/GID。Windows 环境应使用专用账户、限制 NTFS ACL，并把目录放在启用 BitLocker 或等效保护的卷中。

不要把 Docker socket 挂入 CA 容器。能够访问 Docker daemon 的用户通常等价于拥有宿主机高权限，可能读取 bind mount 中的私钥。

## 镜像运行安全边界

推荐始终使用：

- `--network none`
- `--read-only`
- `--cap-drop ALL`
- `--security-opt no-new-privileges:true`
- 非 root UID/GID
- 只挂载本次命令实际需要的 CA 目录
- 经过 attestation 验证的不可变 image digest

镜像不需要网络、数据库、MQTT、Docker socket 或其他服务。它不会启动 SAS、修改其他仓库或编辑 `fmo-server-suite`。

当前镜像只公开四个命令：`init-root`、`issue-intermediate`、`issue-user` 和 `fingerprint`。不包含 CRL 签发、daemon、Web UI 或在线 CA 服务。

## License

本项目采用 GNU General Public License v3.0。镜像内包含 `/licenses/fmo-ca-tool/LICENSE`，完整来源和兼容性说明见 [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)。
