# fmo-ca-tool

## 项目说明

`fmo-ca-tool` 是面向 FMO V4 自定义 PKI 的离线 CA 工具。它实现的是 FMO 证书协议，而不是 X.509，职责限定为：

- 创建自签名 Root CA。
- 由 Root CA 签发 Intermediate CA。
- 由 Intermediate CA 签发 User Certificate。
- 计算协议定义的证书指纹。

项目只公开 `init-root`、`issue-intermediate`、`issue-user` 和 `fingerprint` 四个命令，不提供守护进程、Web UI、在线 CA 服务或 CRL 签发服务。运行、镜像验证、签发流程、离线部署与私钥保管方法统一见[操作指南](docs/operations.md)。

本实现以与 SAS 的字节级兼容为目标：Root、Intermediate 和 User Certificate 的待签名 CBOR 已与 SAS 实现逐字节比对，证书链签名验证与 Root trust store 加载也通过兼容性验证。项目采用 [GNU General Public License v3.0](LICENSE)，兼容性来源与第三方组件见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## 设计说明

### 信任层级

证书体系采用固定的三级信任结构：

```text
Root CA（信任锚，自签名，pathLen = 1）
└── Intermediate CA（签发约束，pathLen = 0）
    └── User Certificate（终端或服务身份）
```

Root CA 只负责建立信任锚并签发 Intermediate CA；Intermediate CA 通过 UID 区间和签发国家集合表达授权范围，并承担日常 User Certificate 签发。User Certificate 绑定呼号、UID 与 Ed25519 公钥，不具备继续签发证书的能力。

### 数据与签名边界

证书使用 JSON 作为持久化和交换格式，二进制字段使用无填充 Base64URL 表示。JSON 本身不参与签名；每类证书都先按协议规定的字段顺序编码为定长 CBOR 数组，再对该 CBOR 字节串执行 Ed25519 签名。

这种设计将“可读的交换表示”与“唯一的密码学表示”分离：JSON 的缩进、属性顺序或空白变化不会改变签名输入与证书指纹。签名字段也不属于待签名内容，因此不存在递归编码。

CBOR 编码固定使用 FMO V4 的字段顺序和数据类型。Root、Intermediate、User 的待签名数组长度分别为 15、20、9；整数按 64 位整数写入，任何字段重排、类型替换或改用 JSON 签名都会破坏协议兼容性。

### 密钥职责与安全边界

- Root 和 Intermediate 密钥在对应 CA 创建或签发阶段生成；私钥文件保存 32 字节 Ed25519 seed，文件本身不包含口令加密。
- User 私钥默认由终端持有，CA 只接收 32 字节公钥。工具仅在显式请求时生成 User 私钥，以避免 CA 成为终端私钥的集中托管者。
- 工具运行时不需要网络、数据库、MQTT、Docker socket 或其他外部服务，适合置于隔离环境中执行。
- 输出采用原子写入，默认拒绝覆盖已有证书或私钥；签发前会检查证书与私钥匹配、上级签名、有效期和授权范围。
- Docker 是项目的交付边界。公开构建生成 `linux/amd64` 与 `linux/arm64` 镜像、SBOM、provenance 和 GitHub build attestation，但供应链证明只说明构建来源，不能替代源码与密码学实现审计。

### 实现分层

| 层 | 主要位置 | 职责 |
| --- | --- | --- |
| 命令编排 | `src/FmoCaTool/Commands` | 参数约束、签发流程、签发后自校验 |
| 证书模型 | `src/FmoCaTool/Certs` | FMO 字段、CBOR TBS 编码、证书验证与指纹 |
| 密码学 | `src/FmoCaTool/Crypto` | Ed25519 密钥、签名、验签与 Base64URL 边界 |
| 安全输出 | `src/FmoCaTool/IO` | 原子写入、权限设置与覆盖保护 |
| 兼容性验证 | `tests` | 协议向量、JSON 往返、签名链与 CLI 行为测试 |

## 数学模型说明

### 记号

设：

- `CBOR_n([x_1, ..., x_n])` 表示严格按给定顺序编码、长度为 `n` 的 CBOR 数组。
- `(sk_X, pk_X)` 表示实体 `X` 的 Ed25519 私钥与公钥；持久化私钥材料是用于派生密钥对的 32 字节 seed。
- `S(sk, m)` 与 `V(pk, m, sig)` 分别表示 Ed25519 签名和验签。
- `H(m) = SHA-256(m)`。
- `iat_X`、`exp_X` 是证书 `X` 的 Unix 时间戳，单位为秒。

文本、字节串、布尔值和整数分别编码为对应的 CBOR 类型；所有协议整数均通过有符号 64 位整数接口写入。下列元组的顺序也是协议的一部分。

### Root CA

Root CA 的待签名字节串为：

```text
T_R = CBOR_15([
  "FMO", 4, "rootCA", sn_R,
  issuerName_R, issuerEmail_R, subjectName_R, pk_R,
  true, 1, crl_R, license_R, keyId_R, iat_R, exp_R
])
```

其中 `issuerName_R = subjectName_R`。Root 使用自身私钥签名并使用自身公钥验证：

```text
sig_R = S(sk_R, T_R)
V(pk_R, T_R, sig_R) = true
```

### Intermediate CA

Intermediate CA 的待签名字节串为：

```text
T_I = CBOR_20([
  "FMO", 4, "intermediateCA", sn_I,
  sn_R, subjectName_R, pk_R,
  subjectName_I, subjectEmail_I, pk_I,
  true, 0, keyId_I, crl_I, license_I,
  uidMin_I, uidMax_I, countries_I, iat_I, exp_I
])
```

`countries_I` 是经过规范化、去重并按序排列的两字母大写国家代码数组。Intermediate 由 Root 签名：

```text
sig_I = S(sk_R, T_I)
V(pk_R, T_I, sig_I) = true
```

### User Certificate

User Certificate 的待签名字节串为：

```text
T_U = CBOR_9([
  "FMO", 4, "userCert", sn_I,
  callsign_U, uid_U, pk_U, iat_U, exp_U
])
```

User Certificate 由 Intermediate 签名：

```text
sig_U = S(sk_I, T_U)
V(pk_I, T_U, sig_U) = true
```

### 约束与证书链判定

签发模型至少满足以下结构约束：

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

Intermediate 中的 `issuerSn`、`issuerName`、`issuerPublicKey` 必须分别绑定 Root 的序列号、主体名称和公钥。User 中的 `issuerSn` 必须绑定 Intermediate 的序列号。给定受信任 Root `R`、Intermediate `I`、User `U` 和校验时刻 `t`，完整信任关系可写为：

```text
ChainValid(R, I, U, t) =
    TrustedAnchor(R)
  AND V(pk_R, T_R, sig_R)
  AND BindIssuer(R, I)
  AND V(pk_R, T_I, sig_I)
  AND (uidMin_I <= uid_U <= uidMax_I)
  AND (sn_I = issuerSn_U)
  AND V(pk_I, T_U, sig_U)
  AND (t < exp_R)
  AND (t < exp_I)
  AND (t < exp_U)
```

`TrustedAnchor(R)` 不能仅由自签名推出；它表示调用方已经通过可信渠道配置了该 Root。自签名证明证书未被修改，但不会自动赋予任何未知 Root 信任。

### 指纹

任意证书 `X` 的 FMO 指纹定义为：

```text
Fingerprint(X) = H(T_X) = SHA-256(X.ToTbsCbor())
```

指纹输入不包括 JSON 文件字节、JSON 格式、公钥单独值或签名字节。Base64URL 与十六进制只是同一个 32 字节哈希值的输出表示，不改变指纹本身。
