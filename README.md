# gojwt

`gojwt` 是一个轻量、直接、面向生产使用的 JWT 工具库，支持以下三类签名方式：

- `HMAC-SHA` 家族：默认 `HS256`，可选 `HS384`、`HS512`
- `Ed25519` (EdDSA)
- `RSA` 家族：默认 `RS256`，可选 `RS384`、`RS512`（PKCS1-v1_5）及 `PS256`、`PS384`、`PS512`（PSS）

库中提供了统一的 Token 生成、解析、有界刷新、缓存解析、并发校验、密钥轮换、黑名单与用户级吊销等能力，
适合在 API 服务、后台服务、网关鉴权和内部 RPC 场景中使用。

## 为什么封装 gojwt

Go 生态中已经有了 `github.com/golang-jwt/jwt/v5` 这样优秀的底层 JWT 库，
但直接在业务代码中使用它，你会发现有很多「配套工作」需要反复处理：

**签发阶段：**
每次签发 token 都要手动拼接 Claims 结构体、生成随机 TokenID、设置 `exp` / `iat` / `nbf` 时间字段、额外写一遍 `jti` 与自定义 ID 的对齐逻辑——十几行重复的样板代码。

**解析阶段：**
解析 token 后要单独做黑名单检查、把 `golang-jwt` 的底层错误映射成业务层能理解的错误码、处理时钟漂移容忍时间。这些每次都得自己写。

**刷新阶段：**
刷新 token 时要重新生成 TokenID、重置 iat/nbf/exp、保证旧 token 被吊销后新 token 仍然可独立吊销，还要给整条刷新链设一个上界，否则一个泄露的 token 可以被无限续下去。

**算法切换与密钥轮换：**
如果你从 HMAC 切换到 Ed25519 或 RSA，ParseToken 中获取验签密钥的逻辑完全不同，GenerateToken 的签名方式也要改；密钥轮换期新旧密钥并存，验证方还得自己按 `kid` 选键。

**gojwt 替你做了这些：**

- ✅ 签发时自动生成 TokenID、写入时间字段与会话起点 `auth_time`、对齐 `jti`
- ✅ 解析时自动检查黑名单与吊销回调、归一化错误、容忍时钟漂移、要求 `exp` 并校验 `iat`
- ✅ 刷新时自动轮换 TokenID，会话以 `auth_time + refreshDuration` 为上界，旧 token 与新 token 独立可吊销
- ✅ 提供统一接口 `Tokener` / `Verifier` / `Issuer`，HMAC / Ed25519 / RSA 切换只需改构造行
- ✅ 只持公钥的验签实例与按 `kid` 选键的 `KeyRing`，验签方与密钥轮换在包内闭环
- ✅ 内置并发安全缓存 + 有界 worker pool 并发验签
- ✅ 提供完整的 sentinel error 体系，业务层用 `errors.Is` 一行判断，错误链保留底层原因

**简单说：gojwt 让你只关心「谁、什么角色、能不能过」，不关心「怎么签名、怎么对齐、怎么吊销」。**

## 特性

- 支持 `HMAC-SHA` 家族、`Ed25519` 与 `RSA`（RS/PS 系列）
- 内置业务 Claims 结构，支持 `Ext` 扩展字段承载 tenant_id、device_id 等业务信息
- 支持标准字段与业务字段混合签发
- 支持临近过期时刷新 Token，刷新链以会话起点加最长会话时长为上界
- 支持缓存解析 `CachedParseToken`
- 支持带 context 的解析、刷新、缓存解析和批量并发验签
- 提供只持公钥的验签实例，以及从内存密钥、PEM 字节构造实例的入口
- 提供 `KeyRing`，按 `kid` 汇集多个验签方，密钥轮换期新旧密钥并存
- 提供并发安全内存黑名单，以及接收完整 claims 的吊销回调
- 提供 `ParseBearerToken`，从 `Authorization` 头提取 token
- 提供统一接口 `Tokener` / `Verifier` / `Issuer`
- 错误统一为 sentinel error，便于 `errors.Is`

## 环境要求

- Go `1.26`

## 安装

```bash
go get github.com/gtkit/gojwt
```

## 适用场景

- 在 Go 服务里快速接入 JWT 签发与验签
- 在 `HMAC`、`Ed25519` 和 `RSA` 之间自由切换
- 只持公钥的服务或网关验签授权中心签出的 token
- 密钥轮换期新旧密钥并存，按 `kid` 自动选键
- 对 token 做角色、业务域、过期时间、签发者、受众等校验
- 用户改密、管理员踢下线等需要按用户维度吊销的场景
- 一个简单直接、没有重型框架依赖的 JWT 封装

## 包结构

```text
gojwt/
├── bearer.go         # Authorization 头解析
├── blacklist.go      # 并发安全黑名单
├── error.go          # 主包错误定义
├── helpers.go        # 缓存、错误归一化、刷新逻辑
├── jwt.go            # 密钥工具函数
├── jwted25519.go     # Ed25519 实现
├── jwthmac.go        # HMAC 实现
├── jwtrsa.go         # RSA 实现（RS/PS 系列）
├── keyring.go        # 按 kid 选键的 KeyRing
├── options.go        # 构造 Option
├── tokener.go        # 统一接口
└── claims/
    ├── claims.go     # Claims 结构与 Claims Option
    └── error.go      # Claims 相关错误
```

## 核心概念

### Claims 结构

库内默认使用 `claims.Claims`：

```go
type Claims struct {
    jwt.RegisteredClaims

    UserID   int64            `json:"uid"`
    Prv      string           `json:"prv,omitempty"`
    Roles    []string         `json:"roles,omitzero"`
    TokenID  string           `json:"token_id"`
    AuthTime *jwt.NumericDate `json:"auth_time,omitempty"`
    Ext      map[string]any   `json:"ext,omitempty"`
}
```

字段说明：

- `UserID`：业务用户 ID
- `Prv`：业务域标识，例如 `admin`、`app`、`open-api`
- `Roles`：角色集合
- `TokenID`：唯一 Token ID；默认自动生成，并与 JWT 标准字段 `jti` 保持一致
- `AuthTime`：会话起点，即首次签发（登录）的时刻，对应 OIDC 的 `auth_time`；刷新时原样继承
- `Ext`：业务扩展字段，例如 `tenant_id`、`device_id`；用 `ExtString` / `ExtInt64` 读取
- `RegisteredClaims`：JWT 标准字段，如 `exp`、`iat`、`nbf`、`iss`、`sub`

### 默认时长

三种算法实现的默认值相同：

- `tokenDuration = 2 小时`：单个 token 的有效期
- `refreshDuration = 7 天`：会话最长时长，从 `auth_time` 起算
- `refreshWindow = 5 分钟`：距过期不足此时长才允许刷新；token 有效期短于 5 分钟时窗口等于整段有效期
- `parseLeeway = 5 秒`
- `cacheMaxEntries = 4096`

可以通过构造时的 Option 修改。构造函数会校验 `refreshDuration >= tokenDuration` 与
`0 < refreshWindow <= tokenDuration`，不满足时返回 `ErrInvalidConfig` 并在错误信息中指出该改哪个 Option。

### Refresh 规则

`RefreshToken` 的行为是"进入刷新窗口后才允许刷新，且整条刷新链有上界"。

当前规则：

- 会话终点为 `auth_time + refreshDuration`；到达终点后刷新返回 `ErrRefreshExpired`，用户需要重新登录
- token 距离过期时间仍大于 `refreshWindow`（默认 5 分钟），返回 `ErrRefreshTooEarly`
- 刷新成功后生成新的 `TokenID/jti`，重置 `iat`、`nbf`，`auth_time` 原样继承
- 新 token 保留旧 token 的有效时长（`exp - iat`），但 `exp` 不会越过会话终点
- 升级前签发的 token 没有 `auth_time`，刷新时以其 `iat` 作为会话起点

这非常适合 Access Token 的"临期续签"模型：客户端每次临期续签，续到会话终点为止。

## 快速开始

### HMAC 用法

```go
package main

import (
    "errors"
    "fmt"
    "os"
    "time"

    jwtv5 "github.com/golang-jwt/jwt/v5"
    "github.com/gtkit/gojwt"
    "github.com/gtkit/gojwt/claims"
)

func main() {
    // ========== 密钥准备 ==========
    // 密钥长度必须满足算法要求：HS256 至少 32 字节，HS384 至少 48 字节，HS512 至少 64 字节。
    // 用 GenerateHMACKeyString 一次性生成后写入环境变量或配置中心，
    // 不要用手写简单口令——它们熵不够，容易被暴力枚举。
    //
    //   s, _ := gojwt.GenerateHMACKeyString(jwtv5.SigningMethodHS512) // 86 字符，直接 []byte(s) 即可
    secret := []byte(os.Getenv("JWT_SECRET"))

    // ========== 创建实例 ==========
    // NewJwtHmac 接受密钥和可选的配置 Option。
    // 所有可选配置都通过 WithXXX 函数注入，不传则使用默认值。
    j, err := gojwt.NewJwtHmac(
        secret,
        // 默认使用 HS256，这里显式切换为 HS512。
        gojwt.WithHMACSigningMethod(jwtv5.SigningMethodHS512),
        // Access Token 有效期：2 小时。
        gojwt.WithTokenDuration(2*time.Hour),
        // 会话最长 7 天：从首次签发起，刷新最多把会话延续到 7 天后。
        gojwt.WithRefreshDuration(7*24*time.Hour),
    )
    if err != nil {
        panic(err)
    }

    // ========== 签发 Token ==========
    // GenerateToken 必须传用户 ID，还可通过 claims.Option 附加业务字段。
    // 系统会自动生成唯一 TokenID、设置 exp/iat/nbf/auth_time、对齐 jti。
    token, err := j.GenerateToken(
        10001,                                // 用户 ID
        claims.WithPrv("admin"),              // 业务域：控制后台
        claims.WithRoles("admin", "finance"), // 角色：管理员 + 财务
        claims.WithIssuer("gtkit-auth"),      // 签发者
        claims.WithSubject("access-token"),   // 主题
        claims.WithExt("tenant_id", 42),      // 业务扩展字段
    )
    if err != nil {
        panic(err)
    }

    // ========== 解析 Token ==========
    // ParseToken 会自动完成：签名验证、时间字段校验（默认容忍 5s 时钟漂移，要求 exp 存在并校验 iat）、
    // 黑名单与吊销回调检查（如果配置了的话）。
    tokenClaims, err := j.ParseToken(token)
    if err != nil {
        panic(err)
    }

    // 读取 Claims 中的业务字段。
    fmt.Println("uid:", tokenClaims.UserID)      // 10001
    fmt.Println("tokenID:", tokenClaims.TokenID) // 自动生成的 16 字节随机 ID
    fmt.Println("prv:", tokenClaims.Prv)         // admin
    fmt.Println("roles:", tokenClaims.Roles)     // [admin finance]
    tenantID, _ := tokenClaims.ExtInt64("tenant_id")
    fmt.Println("tenant:", tenantID) // 42

    // ========== 校验角色和业务域 ==========
    // Claims 提供了内置的辅助方法，一行完成校验。
    // VerifyRole 要求同时具备所有指定角色，缺少任意一个返回 ErrTokenRole。
    if err := tokenClaims.VerifyRole("admin"); err != nil {
        panic(err)
    }
    // VerifyPrv 校验业务域是否匹配。
    if err := tokenClaims.VerifyPrv("admin"); err != nil {
        panic(err)
    }

    // ========== 刷新 Token ==========
    // RefreshToken 只在「token 距过期不足刷新窗口」时允许执行，且不会把会话续到 auth_time + 7 天之后。
    newToken, err := j.RefreshToken(token)
    if err != nil {
        switch {
        case errors.Is(err, gojwt.ErrRefreshTooEarly):
            // token 仍然有效，还没到刷新窗口。
            fmt.Println("当前还没到刷新窗口")
            return
        case errors.Is(err, gojwt.ErrRefreshExpired):
            // 会话已到最长时长，让用户重新登录。
            fmt.Println("会话已到期，请重新登录")
            return
        }
        panic(err)
    }

    // 刷新成功后，建议让客户端切换到新 token。
    // 旧 token 与新 token 有独立的 TokenID，可以分别吊销。
    fmt.Println("new token:", newToken)
}
```

### Ed25519 用法

```go
package main

import (
    "errors"
    "fmt"
    "io/fs"
    "path/filepath"

    "github.com/gtkit/gojwt"
    "github.com/gtkit/gojwt/claims"
)

func main() {
    // ========== 生成密钥对 ==========
    // Ed25519 是非对称签名，私钥签名、公钥验签。
    // 适合多服务场景：只有授权服务有私钥，其他服务只持有公钥。
    priPath := filepath.Join("cert", "jwt_ed25519.pem")     // 私钥路径
    pubPath := filepath.Join("cert", "jwt_ed25519.pub.pem") // 公钥路径

    // 首次部署时生成 Ed25519 密钥对文件，私钥文件权限 0600，公钥文件权限 0644。
    // 文件已存在时返回 fs.ErrExist 且不会覆盖，后续启动据此跳过。
    if err := gojwt.GenerateEd25519Keys(priPath, pubPath); err != nil && !errors.Is(err, fs.ErrExist) {
        panic(err)
    }

    // ========== 加载密钥对 ==========
    // 从 PEM 文件加载私钥和公钥。私钥负责签名，公钥负责验签；两者不匹配时构造失败。
    j, err := gojwt.NewJwtEd25519(priPath, pubPath)
    if err != nil {
        panic(err)
    }

    // ========== 签发 Token ==========
    // 使用私钥签名。接口与 HMAC 完全一致。
    token, err := j.GenerateToken(
        20001,
        claims.WithPrv("open-api"),  // 业务域：开放 API
        claims.WithRoles("service"), // 角色：服务调用
    )
    if err != nil {
        panic(err)
    }

    // ========== 验签方：只持公钥 ==========
    // 其他服务只需要公钥文件就能验签，拿不到私钥也就无法伪造 token。
    verifier, err := gojwt.NewJwtEd25519VerifierFromFile(pubPath)
    if err != nil {
        panic(err)
    }
    tokenClaims, err := verifier.ParseToken(token)
    if err != nil {
        panic(err)
    }

    fmt.Println("uid:", tokenClaims.UserID)
}
```

密钥来自 KMS、Vault 或环境变量时，先解析 PEM 字节再从内存密钥构造：

```go
privateKey, err := gojwt.ParseEd25519PrivateKeyPEM([]byte(os.Getenv("JWT_ED25519_PRIVATE_PEM")))
if err != nil {
    panic(err)
}
publicKey, err := gojwt.ParseEd25519PublicKeyPEM([]byte(os.Getenv("JWT_ED25519_PUBLIC_PEM")))
if err != nil {
    panic(err)
}
j, err := gojwt.NewJwtEd25519FromKeys(privateKey, publicKey)
```

### RSA 用法

```go
package main

import (
    "errors"
    "fmt"
    "io/fs"
    "path/filepath"

    jwtv5 "github.com/golang-jwt/jwt/v5"
    "github.com/gtkit/gojwt"
    "github.com/gtkit/gojwt/claims"
)

func main() {
    // ========== 生成 RSA 密钥对 ==========
    // RSA 是非对称签名，适合与使用 RS256 的第三方系统互通。
    // RS/PS 全系列算法都可用 2048 bit 密钥；需要更高安全强度时用 3072 或 4096。
    priPath := filepath.Join("cert", "jwt_rsa.pem")
    pubPath := filepath.Join("cert", "jwt_rsa.pub.pem")

    // 首次部署时生成 RSA 密钥对，文件已存在时不会覆盖。
    if err := gojwt.GenerateRSAKeys(priPath, pubPath, 2048); err != nil && !errors.Is(err, fs.ErrExist) {
        panic(err)
    }

    // ========== 从 PEM 加载密钥 ==========
    // NewJwtRSA 支持 PKCS1（"RSA PRIVATE KEY"）和 PKCS8（"PRIVATE KEY"）两种私钥格式。
    // 默认签名算法为 RS256。
    j, err := gojwt.NewJwtRSA(priPath, pubPath)
    if err != nil {
        panic(err)
    }

    // ========== 签发 Token ==========
    // 使用 RSA 私钥签名。接口与 HMAC、Ed25519 完全一致。
    token, err := j.GenerateToken(
        30001,
        claims.WithPrv("gateway"),        // 业务域：API 网关
        claims.WithRoles("service"),      // 角色：服务调用
        claims.WithIssuer("auth-center"), // 签发者：统一认证中心
    )
    if err != nil {
        panic(err)
    }

    // ========== 验签方：只持公钥 ==========
    // 持有对方公钥的 PEM 文件即可验签，同样适用于验签第三方系统用 RS/PS 系列签出的 token。
    verifier, err := gojwt.NewJwtRSAVerifierFromFile(pubPath)
    if err != nil {
        panic(err)
    }
    tokenClaims, err := verifier.ParseToken(token)
    if err != nil {
        panic(err)
    }

    fmt.Println("uid:", tokenClaims.UserID)
    fmt.Println("issuer:", tokenClaims.Issuer)

    // ========== 使用 PSS 系列（更安全） ==========
    // 如果希望使用 RSA-PSS（比 PKCS1-v1_5 更安全），可以在创建时指定：
    // jPSS, _ := gojwt.NewJwtRSA(priPath, pubPath, gojwt.WithRSASigningMethod(jwtv5.SigningMethodPS256))
    _ = jwtv5.SigningMethodPS256 // 示例引用
}
```

也可以直接从内存密钥创建（适用于 KMS、Vault 等场景）：

```go
j, err := gojwt.NewJwtRSAFromKeys(privateKey, &privateKey.PublicKey)
verifier, err := gojwt.NewJwtRSAVerifier(&privateKey.PublicKey)
```

## 构造函数

### `NewJwtHmac`

```go
func NewJwtHmac(secretKey []byte, options ...gojwt.Option) (*gojwt.JwtHmac, error)
```

说明：

- 默认使用 `HS256`
- 可通过 `WithHMACSigningMethod` 切换到 `HS384` / `HS512`
- `HS256` 至少 `32` 字节，`HS384` 至少 `48` 字节，`HS512` 至少 `64` 字节；用 `GenerateHMACKeyString` 生成的密钥总能满足
- 密钥只保留在本进程内

示例：

```go
// 创建 HMAC JWT 实例。
j, err := gojwt.NewJwtHmac([]byte("12345678901234567890123456789012"))
if err != nil {
    panic(err)
}
_ = j
```

### `WithHMACSigningMethod`

用于为 `JwtHmac` 指定 HMAC 签名算法。

```go
j, err := gojwt.NewJwtHmac(
    []byte("123456789012345678901234567890123456789012345678"),
    gojwt.WithHMACSigningMethod(jwtv5.SigningMethodHS384),
)
if err != nil {
    panic(err)
}
_ = j
```

支持：

- `jwtv5.SigningMethodHS256`
- `jwtv5.SigningMethodHS384`
- `jwtv5.SigningMethodHS512`

注意：

- 不传时默认 `HS256`
- 当前实例只接受与自身配置一致的 HMAC 算法 token
- `Ed25519` / `RSA` 实例传入此 Option 时构造返回 `ErrInvalidConfig`

### `WithRSASigningMethod`

用于为 `JwtRSA` 指定签名算法。

```go
j, err := gojwt.NewJwtRSA(
    priPath, pubPath,
    gojwt.WithRSASigningMethod(jwtv5.SigningMethodPS256),
)
```

支持：

| 系列 | 算法 | 说明 |
|------|------|------|
| PKCS1-v1_5 | `RS256` / `RS384` / `RS512` | 兼容性最好，与第三方系统互通的常见选择 |
| PSS | `PS256` / `PS384` / `PS512` | 更安全，推荐新项目使用 |

注意：

- 不传时默认 `RS256`
- `HMAC` / `Ed25519` 实例传入此 Option 时构造返回 `ErrInvalidConfig`

### `NewJwtEd25519` 系列

```go
func NewJwtEd25519(priPath, pubPath string, options ...gojwt.Option) (*gojwt.JwtEd25519, error)
func NewJwtEd25519FromKeys(privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey, options ...gojwt.Option) (*gojwt.JwtEd25519, error)
func NewJwtEd25519Verifier(publicKey ed25519.PublicKey, options ...gojwt.Option) (*gojwt.JwtEd25519, error)
func NewJwtEd25519VerifierFromFile(pubPath string, options ...gojwt.Option) (*gojwt.JwtEd25519, error)
```

说明：

- `NewJwtEd25519` 从 PEM 文件加载私钥、公钥，`NewJwtEd25519FromKeys` 使用内存中的密钥对
- 两者都会校验公钥与私钥匹配，不匹配返回 `ErrInvalidKey`
- `Verifier` 系列只持公钥，解析类方法行为与持私钥实例一致，`GenerateToken` / `RefreshToken` 返回 `ErrNoSigningKey`
- PEM 字节用 `ParseEd25519PrivateKeyPEM` / `ParseEd25519PublicKeyPEM` 解析，支持 PKCS8 / PKIX 与 64 / 32 字节原始格式

### `NewJwtRSA` 系列

```go
func NewJwtRSA(priPath, pubPath string, options ...gojwt.Option) (*gojwt.JwtRSA, error)
func NewJwtRSAFromKeys(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, options ...gojwt.Option) (*gojwt.JwtRSA, error)
func NewJwtRSAVerifier(publicKey *rsa.PublicKey, options ...gojwt.Option) (*gojwt.JwtRSA, error)
func NewJwtRSAVerifierFromFile(pubPath string, options ...gojwt.Option) (*gojwt.JwtRSA, error)
```

说明：

- `NewJwtRSA` 从 PEM 文件加载 RSA 密钥对，支持 PKCS1（`RSA PRIVATE KEY`）和 PKCS8（`PRIVATE KEY`）私钥格式
- `NewJwtRSAFromKeys` 使用内存中的密钥对，输入会被复制并预计算
- 两者都会校验公钥与私钥匹配，不匹配返回 `ErrInvalidKey`
- `Verifier` 系列只持公钥，解析类方法行为与持私钥实例一致，`GenerateToken` / `RefreshToken` 返回 `ErrNoSigningKey`
- 默认使用 `RS256`，可通过 `WithRSASigningMethod` 切换到 `RS384` / `RS512` / `PS256` / `PS384` / `PS512`
- 密钥长度要求：全系列至少 `2048` bit（RFC 7518）
- PEM 字节用 `ParseRSAPrivateKeyPEM` / `ParseRSAPublicKeyPEM` 解析

### 密钥加载错误

四个 `ParseXxxPEM` 函数与文件构造函数的错误语义一致：

- PEM 解码失败、密钥长度错误、结构解析失败：`errors.Is(err, gojwt.ErrInvalidKey)`
- 密钥算法类型不符（例如把 Ed25519 的 PKCS8 交给 `ParseRSAPrivateKeyPEM`）：`errors.Is(err, gojwt.ErrInvalidKeyType)`
- 文件读取失败：保留 `fs` 错误链，`errors.Is(err, fs.ErrNotExist)` 可判断文件不存在

## 构造 Option

### `WithTokenDuration`

用于设置 Access Token 有效期。

```go
// 将 access token 时长设置为 30 分钟。
j, err := gojwt.NewJwtHmac(
    []byte("12345678901234567890123456789012"),
    gojwt.WithTokenDuration(30*time.Minute),
)
if err != nil {
    panic(err)
}
_ = j
```

### `WithRefreshDuration`

用于设置会话最长时长，从首次签发时刻 `auth_time` 起算。

```go
// 会话最长 3 天：刷新最多把会话延续到首次签发后 3 天。
j, err := gojwt.NewJwtHmac(
    []byte("12345678901234567890123456789012"),
    gojwt.WithRefreshDuration(72*time.Hour),
)
if err != nil {
    panic(err)
}
_ = j
```

说明：

- 默认 `7 天`
- 取值必须不短于 `WithTokenDuration`，否则构造返回 `ErrInvalidConfig`
- 到达终点后 `RefreshToken` 返回 `ErrRefreshExpired`

### `WithRefreshWindow`

用于设置刷新窗口：token 距过期不足此时长时才允许刷新。

```go
// 距过期 10 分钟内可刷新。
j, err := gojwt.NewJwtHmac(
    []byte("12345678901234567890123456789012"),
    gojwt.WithTokenDuration(time.Hour),
    gojwt.WithRefreshWindow(10*time.Minute),
)
if err != nil {
    panic(err)
}
_ = j
```

说明：

- 默认 `5 分钟`；token 有效期短于 5 分钟时默认窗口等于整段有效期
- 取值必须大于零且不超过 `WithTokenDuration`，否则构造返回 `ErrInvalidConfig`
- 设为与有效期相等即整段有效期内随时可刷新

### `WithParseLeeway`

用于设置 JWT 解析时对时间字段的容忍时间。

```go
// 将解析时钟漂移容忍时间设为 10 秒。
j, err := gojwt.NewJwtHmac(
    []byte("12345678901234567890123456789012"),
    gojwt.WithParseLeeway(10*time.Second),
)
if err != nil {
    panic(err)
}
_ = j
```

说明：

- 默认值为 `5 秒`
- 会同时作用于 `exp`、`nbf`、`iat`；解析默认要求 `exp` 存在并校验 `iat` 不晚于当前时刻加 leeway
- 如果你希望严格按时间字段校验，可显式传 `gojwt.WithParseLeeway(0)`

### `WithParserOptions`

用于设置实例级的 `jwtv5.ParserOption`，每次解析都会应用。

```go
j, err := gojwt.NewJwtHmac(
    []byte("12345678901234567890123456789012"),
    gojwt.WithParserOptions(
        jwtv5.WithIssuer("auth-center"),
        jwtv5.WithAudience("web"),
    ),
)
if err != nil {
    panic(err)
}
_ = j
```

说明：

- 应用顺序为包内默认选项 → 实例级选项 → 单次调用传入的选项
- 实例级选项固定不变，`CachedParseToken` 的缓存对它仍然生效；单次调用传入的选项仍会绕过缓存
- 适合把 issuer / audience 校验固定在实例上，避免每个调用点各写一遍

### `WithKeyID`

用于在签发时把密钥标识写入 JWT header 的 `kid` 字段。

```go
// 签出的 token header 为 {"alg":"HS256","kid":"app-2026","typ":"JWT"}
j, err := gojwt.NewJwtHmac(
    []byte("12345678901234567890123456789012"),
    gojwt.WithKeyID("app-2026"),
)
if err != nil {
    panic(err)
}
_ = j
```

说明：

- 默认不写入 `kid`，header 与不使用本选项时完全一致
- 传空字符串等价于不设置
- `HMAC`、`Ed25519`、`RSA` 三种实现都支持，`RefreshToken` 产出的新 token 同样带上 `kid`
- `kid` 只是密钥标识，会以明文出现在 token 里，不要放密钥本身或任何敏感信息

验证侧用 `KeyRing` 按 `kid` 汇集多个实例，见下一节。

### `KeyRing`

按 `kid` 汇集多个验签方：解析时用 `ParseKeyID` 取出 token 的 `kid`，再委托给对应实例验签。

```go
func NewKeyRing() *KeyRing
func (r *KeyRing) Register(kid string, v Verifier) error
func (r *KeyRing) Unregister(kid string)
```

**密钥轮换**。新旧密钥并存期间，验证方靠 `kid` 知道该用哪一把，不必停机切换：

```go
// 轮换期：新签发的 token 用新密钥，老 token 仍带着老 kid 在有效期内正常使用
oldJwt, _ := gojwt.NewJwtHmac(oldSecret, gojwt.WithKeyID("app-2025"))
newJwt, _ := gojwt.NewJwtHmac(newSecret, gojwt.WithKeyID("app-2026"))

ring := gojwt.NewKeyRing()
_ = ring.Register("app-2025", oldJwt)
_ = ring.Register("app-2026", newJwt)

// 验证方：一次调用完成选键与验签
cc, err := ring.ParseToken(tokenString)

// 老 token 全部过期后注销旧 kid，之后携带旧 kid 的 token 返回 ErrUnknownKeyID
ring.Unregister("app-2025")
```

**网关侧多算法分流**。同一个网关同时接收不同算法签发的 token，靠 `kid` 分流到对应实例：

```go
hmacJwt, _ := gojwt.NewJwtHmac(secret, gojwt.WithKeyID("app-2026"))
rsaVerifier, _ := gojwt.NewJwtRSAVerifierFromFile(pubPath) // 网关只持公钥

ring := gojwt.NewKeyRing()
_ = ring.Register("app-2026", hmacJwt)
_ = ring.Register("rs-2026", rsaVerifier)
_ = ring.Register("", legacyJwt) // 空 kid：升级前签发、未携带 kid 的 token

cc, err := ring.ParseToken(tokenString)
```

说明：

- `KeyRing` 实现 `Verifier`，`ParseToken` / `CachedParseToken` / `ParallelVerify` 及对应 context 变体都按 kid 逐个选键
- 空 kid 注册的实例用于未携带 `kid` 的 token
- `kid` 未注册返回 `ErrUnknownKeyID`；token 格式错误返回 `ErrTokenMalformed`
- 并发安全，`Register` / `Unregister` 可在运行期调用

### `ParseKeyID`

不验签地读出 token header 中的 `kid`，用于在验签前定位该用哪一把密钥。`KeyRing` 内部就是用它选键。

```go
kid, err := gojwt.ParseKeyID(tokenString)
```

说明：

- token 未携带 `kid` 时返回空字符串和 `nil` error
- 只对 header 段做 base64 与 JSON 解码，签名被篡改或 token 已过期时同样能读出 `kid`
- 格式错误（缺少分隔符、header 段不是合法 base64 或合法 JSON 对象）返回的错误
  满足 `errors.Is(err, gojwt.ErrTokenMalformed)`
- 返回的 `kid` 来自未经验证的数据，攻击者可控。它只能用来挑选密钥，
  随后必须用选中的密钥走一次 `ParseToken` 完成验签，不能直接用于鉴权或授权判断

### `WithBlacklistFunc` / `WithBlacklistCheckFunc` / `WithBlacklistCheckContextFunc`

用于注入按 `token_id` 查询的黑名单检查函数。三者只能配置一个，同时配置多个时构造返回 `ErrInvalidConfig`。

```go
// 内存黑名单
j, err := gojwt.NewJwtHmac(secret, gojwt.WithBlacklistFunc(blacklist.In))

// Redis：支持 context 超时，存储不可用时返回 error 让鉴权 fail closed
j, err := gojwt.NewJwtHmac(
    secret,
    gojwt.WithBlacklistCheckContextFunc(func(ctx context.Context, tokenID string) (bool, error) {
        n, err := rdb.Exists(ctx, "jwt:blacklist:"+tokenID).Result()
        return n > 0, err
    }),
)
```

说明：

- 命中黑名单时解析返回 `ErrTokenBlacklisted`
- 检查函数返回 error 时解析返回包装后的该 error
- `ParseTokenContext` / `CachedParseTokenContext` / `ParallelVerifyContext` 会把 ctx 透传给 context 版检查函数

### `WithRevocationCheck`

用于注入接收完整 claims 的吊销回调，覆盖"按用户吊销"这类黑名单做不到的场景。

```go
j, err := gojwt.NewJwtHmac(
    secret,
    // 改密后让该用户在改密时刻之前签发的全部 token 作废
    gojwt.WithRevocationCheck(func(ctx context.Context, c *claims.Claims) (bool, error) {
        cutoff, err := store.PasswordChangedAt(ctx, c.UserID)
        if err != nil {
            return false, err // 存储不可用时 fail closed
        }
        return c.IssuedAt != nil && c.IssuedAt.Time.Before(cutoff), nil
    }),
)
```

说明：

- 在签名与 claims 校验通过、黑名单检查之后执行；`CachedParseToken` 缓存命中时同样执行
- 返回 `true` 时解析返回 `ErrTokenBlacklisted`；返回 error 时解析返回包装后的该 error
- 可与黑名单 Option 同时配置：黑名单负责单个 token 的登出，回调负责用户级吊销

## HMAC 算法选择

`HS256`、`HS384`、`HS512` 都是对称签名，差别主要在哈希强度、签名长度和密钥长度要求：

| 算法 | 哈希函数 | 签名长度 | 最小密钥长度 | 适用建议 |
|---|---|---:|---:|---|
| `HS256` | SHA-256 | 32 字节 | 32 字节 | 默认选择。兼容性最好，性能和安全性平衡最好 |
| `HS384` | SHA-384 | 48 字节 | 48 字节 | 需要比 `HS256` 更长摘要，但又不想上到 `HS512` 时可选 |
| `HS512` | SHA-512 | 64 字节 | 64 字节 | 对摘要长度要求更高，且能接受更长密钥与更大 token 时可选 |

实践建议：

- 常规业务默认用 `HS256` 即可
- 只有当你明确要求更长摘要或与外部系统算法对齐时，再选 `HS384` / `HS512`
- 密钥用 `GenerateHMACKeyString(method)` 生成，它按算法给出足够长的密钥

> `Options` 是历史兼容别名，已 deprecated，新代码请使用 `Option`。

## Claims Option

签发时可以通过 `claims.Option` 动态组合 Claims：

- `claims.WithRole(role string)`
- `claims.WithRoles(roles ...string)`
- `claims.WithPrv(prv string)`
- `claims.WithIssuer(issuer string)`
- `claims.WithSubject(subject string)`
- `claims.WithAudience(audience ...string)`
- `claims.WithExpiresIn(d time.Duration)` — 设置相对过期时长
- `claims.WithExpiresAtTime(t time.Time)` — 设置绝对过期时间
- `claims.WithJwtID(jwtID string)`
- `claims.WithExt(key string, value any)` — 写入业务扩展字段

说明：

- `claims.WithJwtID` 会同时设置标准字段 `jti` 和业务字段 `token_id`
- `claims.WithExt` 的值必须能被 `encoding/json` 编码，否则签发时返回错误；刷新会保留全部扩展字段
- `claims.WithExpiresAt` 仍可用，但已 deprecated，请迁移到 `WithExpiresIn`

示例：

```go
// 通过 claims.Option 组合业务字段和标准字段。
token, err := j.GenerateToken(
    9527,
    claims.WithPrv("admin"),
    claims.WithRoles("admin", "auditor"),
    claims.WithIssuer("gtkit-auth"),
    claims.WithSubject("access-token"),
    claims.WithAudience("web", "mobile"),
    claims.WithExt("tenant_id", 42),
    claims.WithExt("device_id", "ios-7f3a"),
)
if err != nil {
    panic(err)
}
_ = token
```

## 主要 API

### `GenerateToken`

```go
func (j *JwtHmac) GenerateToken(uid int64, options ...claims.Option) (string, error)
func (j *JwtEd25519) GenerateToken(uid int64, options ...claims.Option) (string, error)
func (j *JwtRSA) GenerateToken(uid int64, options ...claims.Option) (string, error)
```

行为说明：

- 根据 `uid` 与附加 `claims.Option` 生成 JWT
- 自动写入 `exp`、`iat`、`nbf`、`auth_time`
- 自动生成唯一 `TokenID`
- 只持公钥的验签实例返回 `ErrNoSigningKey`

### `ParseToken`

```go
func (j *JwtHmac) ParseToken(tokenString string, opt ...jwt.ParserOption) (*claims.Claims, error)
func (j *JwtHmac) ParseTokenContext(ctx context.Context, tokenString string, opt ...jwt.ParserOption) (*claims.Claims, error)
func (j *JwtEd25519) ParseToken(tokenString string, opt ...jwt.ParserOption) (*claims.Claims, error)
func (j *JwtEd25519) ParseTokenContext(ctx context.Context, tokenString string, opt ...jwt.ParserOption) (*claims.Claims, error)
func (j *JwtRSA) ParseToken(tokenString string, opt ...jwt.ParserOption) (*claims.Claims, error)
func (j *JwtRSA) ParseTokenContext(ctx context.Context, tokenString string, opt ...jwt.ParserOption) (*claims.Claims, error)
```

行为说明：

- 完成验签，只接受与实例算法一致的 token
- 校验标准时间字段：要求 `exp` 存在，校验 `exp`、`nbf`、`iat`
- 默认带 `5 秒` leeway，用于吸收轻微时钟漂移
- 可通过构造时的 `WithParseLeeway` / `WithParserOptions` 修改，或在单次调用中通过 `jwt.ParserOption` 覆盖
- 执行黑名单检查与吊销回调（如果配置了的话）
- 返回 `*claims.Claims`；错误满足对应的 sentinel，`err.Error()` 中带底层库的原因文本

示例：

```go
// 解析 token 并读取 claims。
tokenClaims, err := j.ParseToken(token)
if err != nil {
    panic(err)
}

fmt.Println("uid:", tokenClaims.UserID)
```

### `CachedParseToken`

```go
func (j *JwtHmac) CachedParseToken(tokenString string, opt ...jwt.ParserOption) (*claims.Claims, error)
func (j *JwtHmac) CachedParseTokenContext(ctx context.Context, tokenString string, opt ...jwt.ParserOption) (*claims.Claims, error)
func (j *JwtEd25519) CachedParseToken(tokenString string, opt ...jwt.ParserOption) (*claims.Claims, error)
func (j *JwtEd25519) CachedParseTokenContext(ctx context.Context, tokenString string, opt ...jwt.ParserOption) (*claims.Claims, error)
func (j *JwtRSA) CachedParseToken(tokenString string, opt ...jwt.ParserOption) (*claims.Claims, error)
func (j *JwtRSA) CachedParseTokenContext(ctx context.Context, tokenString string, opt ...jwt.ParserOption) (*claims.Claims, error)
```

行为说明：

- 首次解析时正常验签并缓存 Claims
- 再次解析相同 token 时优先命中缓存，命中后仍执行黑名单检查与吊销回调
- 返回的是 Claims 副本（含 `Ext` 的嵌套结构），避免调用方意外改坏缓存对象
- 仅在未传入单次调用 `ParserOption` 时使用缓存；构造期的 `WithParserOptions` 不影响缓存

注意事项：

- 缓存是"实例级"的，不跨不同 JWT 实例共享
- 缓存采用 LRU 淘汰，容量上限严格受 `WithCacheMaxEntries` 控制
- 过期条目会做惰性清扫
- 默认最多缓存 `4096` 个 token，可通过 `WithCacheMaxEntries` 调整
- `WithCacheMaxEntries(0)` 会关闭缓存路径，直接退化为普通解析

示例：

```go
// 对频繁重复校验的 token 使用缓存解析。
tokenClaims, err := j.CachedParseToken(token)
if err != nil {
    panic(err)
}

fmt.Println("token id:", tokenClaims.TokenID)
```

### `RefreshToken`

```go
func (j *JwtHmac) RefreshToken(tokenString string, opt ...jwt.ParserOption) (string, error)
func (j *JwtHmac) RefreshTokenContext(ctx context.Context, tokenString string, opt ...jwt.ParserOption) (string, error)
func (j *JwtEd25519) RefreshToken(tokenString string, opt ...jwt.ParserOption) (string, error)
func (j *JwtEd25519) RefreshTokenContext(ctx context.Context, tokenString string, opt ...jwt.ParserOption) (string, error)
func (j *JwtRSA) RefreshToken(tokenString string, opt ...jwt.ParserOption) (string, error)
func (j *JwtRSA) RefreshTokenContext(ctx context.Context, tokenString string, opt ...jwt.ParserOption) (string, error)
```

行为说明：

- 使用旧 token 中的 Claims 重新签发新 token，保留原业务字段与 `auth_time`
- 生成新的 `TokenID/jti`，重置 `iat`、`nbf`
- 新 token 保留旧 token 的有效时长，`exp` 不越过 `auth_time + refreshDuration`
- 距过期仍超过刷新窗口返回 `ErrRefreshTooEarly`；会话已到终点返回 `ErrRefreshExpired`
- 旧 token 与新 token 可独立吊销
- 只持公钥的验签实例返回 `ErrNoSigningKey`

示例：

```go
// 对即将过期的 token 进行刷新。
newToken, err := j.RefreshToken(oldToken)
if err != nil {
    switch {
    case errors.Is(err, gojwt.ErrRefreshTooEarly):
        // token 还没进入刷新窗口。
        return
    case errors.Is(err, gojwt.ErrRefreshExpired):
        // 会话已到最长时长，让用户重新登录。
        return
    }
    panic(err)
}
_ = newToken
```

### `ParallelVerify`

```go
func (j *JwtHmac) ParallelVerify(tokens []string, opt ...jwt.ParserOption) ([]*claims.Claims, []error)
func (j *JwtEd25519) ParallelVerify(tokens []string, opt ...jwt.ParserOption) ([]*claims.Claims, []error)
func (j *JwtRSA) ParallelVerify(tokens []string, opt ...jwt.ParserOption) ([]*claims.Claims, []error)

func (j *JwtHmac) ParallelVerifyContext(ctx context.Context, tokens []string, opt ...jwt.ParserOption) ([]*claims.Claims, []error)
func (j *JwtEd25519) ParallelVerifyContext(ctx context.Context, tokens []string, opt ...jwt.ParserOption) ([]*claims.Claims, []error)
func (j *JwtRSA) ParallelVerifyContext(ctx context.Context, tokens []string, opt ...jwt.ParserOption) ([]*claims.Claims, []error)
```

行为说明：

- 并发验证多个 token
- 内部使用有界 worker pool，而不是为每个 token 单独起 goroutine
- 默认最大并发数为 `min(len(tokens), runtime.GOMAXPROCS(0))`
- `results[i]` 与 `errs[i]` 对应同一个输入 token，两个切片总与输入等长
- `ParallelVerifyContext` 会在 `ctx` 取消后停止分发未开始的任务，并将 ctx 透传给 context-aware 黑名单检查函数与吊销回调

注意事项：

- 如果你要处理超大批量 token，仍建议在业务侧分批调用
- 返回顺序始终与输入顺序一致

示例：

```go
// 批量并发验签。
result, errs := j.ParallelVerify([]string{token1, token2, token3})
for i := range result {
    if errs[i] != nil {
        fmt.Println("verify failed:", i, errs[i])
        continue
    }
    fmt.Println("uid:", result[i].UserID)
}
```

### `ParseBearerToken`

```go
func ParseBearerToken(authorization string) (string, error)
```

行为说明：

- 从 `Authorization` 头的值中取出 Bearer token，scheme 大小写不敏感
- 头为空返回 `ErrAuthorizationMissing`，对应 401 并回 `WWW-Authenticate: Bearer`
- scheme 不是 `Bearer`、token 为空或含空白返回 `ErrAuthorizationInvalid`，对应 400

## Claims 辅助方法

### `VerifyRole`

```go
// 要求 token 同时具备 admin 和 finance 两个角色。
if err := tokenClaims.VerifyRole("admin", "finance"); err != nil {
    // 不满足时返回 ErrTokenRole。
}
```

### `VerifyPrv`

```go
// 验证业务域是否为 admin。
if err := tokenClaims.VerifyPrv("admin"); err != nil {
    // 不匹配时返回 ErrTokenPrv。
}
```

### `ExtString` / `ExtInt64`

```go
// 读取扩展字段。JSON 往返会把整数变成 float64，ExtInt64 会把它转回 int64。
tenantID, ok := tokenClaims.ExtInt64("tenant_id")
deviceID, ok := tokenClaims.ExtString("device_id")
```

键不存在、类型不符、数值带小数或超出 `int64` 范围时第二个返回值为 `false`。

### `TTL`

```go
// 获取 token 剩余有效时间。
ttl := tokenClaims.TTL()
fmt.Println("ttl:", ttl)
```

## 统一接口

三个接口按职责拆分，业务层按需要的能力选择：

- `Tokener`：签发、解析、刷新、缓存解析、并发验签，三种签名实现都满足
- `Verifier`：只有解析类方法（含 context 变体），三种签名实现与 `KeyRing` 都满足，验签方与网关面向它编程
- `Issuer`：签发与刷新（含 context 变体），三种签名实现都满足

```go
package main

import (
    "github.com/gtkit/gojwt"
    "github.com/gtkit/gojwt/claims"
)

func IssueToken(t gojwt.Issuer, uid int64) (string, error) {
    // 调用方不用关心底层是 HMAC、Ed25519 还是 RSA。
    return t.GenerateToken(uid, claims.WithPrv("admin"))
}

func Authenticate(v gojwt.Verifier, token string) (*claims.Claims, error) {
    // 传入单个实例或 KeyRing 都可以。
    return v.CachedParseToken(token)
}
```

面向 `Tokener` 编程时，需要 context 取消能力可按需断言扩展接口：

```go
if ct, ok := t.(gojwt.ContextTokener); ok {
    return ct.ParseTokenContext(ctx, token)
}
```

## 黑名单

`Blacklist` 是一个并发安全的内存黑名单。

接口：

```go
type Blacklister interface {
    In(tokenID string) bool
    Add(tokenID string)
    Remove(tokenID string)
}
```

增强接口 `BlacklistManager`（`*Blacklist` 同时实现了两个接口）：

```go
type BlacklistManager interface {
    Blacklister
    AddWithExpiration(tokenID string, expiresAt time.Time)
    AddToken(tokenClaims *claims.Claims) error
    SweepExpired() int
    Close()
}
```

工厂函数：

- `NewBlacklist() *Blacklist`
- `NewBlacklistWithCleanup(interval time.Duration) (*Blacklist, error)`

示例：

```go
// ========== 创建黑名单 ==========
// NewBlacklistWithCleanup 创建一个带后台清扫协程的并发安全黑名单。
// 清扫间隔为 1 分钟，自动清理过期条目。
blacklist, err := gojwt.NewBlacklistWithCleanup(time.Minute)
if err != nil {
    panic(err)
}
// 服务退出时关闭后台协程，避免 goroutine 泄漏。
defer blacklist.Close()

// ========== 推荐用法：按 token 自身 exp 自动失效 ==========
// AddToken 会自动读取 Claims 中的 TokenID 和 ExpiresAt，
// token 过期后黑名单条目自动失效，不需要手动删除。
err = blacklist.AddToken(&claims.Claims{
    TokenID: "token-id-1",
    RegisteredClaims: jwtv5.RegisteredClaims{
        ExpiresAt: jwtv5.NewNumericDate(time.Now().Add(2 * time.Hour)),
    },
})
if err != nil {
    panic(err)
}

// ========== 兼容旧用法：永久拉黑 ==========
// Add("token-id-2") 将 token 永久加入黑名单，直到手动 Remove。
// 使用时注意：永久条目需要手动管理，否则会驻留在内存中。
blacklist.Add("token-id-2")

// ========== 请求入口检查 ==========
// 每次请求进入时（一般在 auth 中间件里），检查 token 是否已被拉黑。
if blacklist.In("token-id-1") {
    fmt.Println("token 已失效")
}

// ========== 手动恢复 ==========
// 某些场景下（如误操作），可以将 token 从黑名单中移除。
blacklist.Remove("token-id-1")
```

注意：

- 当前是纯内存实现，适用于单实例部署
- `AddToken` / `AddWithExpiration` 写入的条目会在到达过期时间后惰性失效
- 如果使用 `NewBlacklistWithCleanup`，后台会按固定间隔主动清理过期条目
- `Close()` 应在服务退出时调用，用于停止后台清理协程
- `Add(tokenID)` 是兼容旧代码的永久拉黑接口

多副本部署时把 `token_id` 存入 Redis，通过 `WithBlacklistCheckContextFunc` 接入即可。

## 中间件接入示例

下面给一个简化版 HTTP 中间件示例，演示如何解析 Bearer Token、验签并把 Claims 放进请求上下文。
黑名单与吊销回调在构造实例时通过 Option 注入，中间件里不需要再单独检查。

```go
package main

import (
    "context"
    "errors"
    "net/http"

    "github.com/gtkit/gojwt"
    "github.com/gtkit/gojwt/claims"
)

// claimsKey 是 context 中存储 Claims 的键，使用空结构体避免 key 冲突。
type claimsKey struct{}

// AuthMiddleware 返回一个 HTTP 中间件，负责从请求中解析 Bearer Token、验签，
// 并把解析后的 Claims 注入请求上下文。
//
// v 可以是 *JwtHmac / *JwtEd25519 / *JwtRSA 的任意一种，也可以是 KeyRing，
// 它们都实现了 Verifier 接口。
//
// 在 handler 中通过 ClaimsFromContext 获取 Claims。
func AuthMiddleware(v gojwt.Verifier) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // ========== 第一步：取 Token ==========
            token, err := gojwt.ParseBearerToken(r.Header.Get("Authorization"))
            if err != nil {
                if errors.Is(err, gojwt.ErrAuthorizationMissing) {
                    w.Header().Set("WWW-Authenticate", `Bearer realm="api"`)
                    http.Error(w, "missing authorization header", http.StatusUnauthorized)
                    return
                }
                http.Error(w, "invalid authorization header", http.StatusBadRequest)
                return
            }

            // ========== 第二步：解析并验签 ==========
            // 使用 CachedParseTokenContext：同一 token 重复到达时命中缓存，避免重复 RSA/Ed25519 验签开销；
            // 缓存命中后仍会执行黑名单检查与吊销回调。
            tokenClaims, err := v.CachedParseTokenContext(r.Context(), token)
            if err != nil {
                // 根据错误类型返回不同的 HTTP 状态和消息。
                switch {
                case errors.Is(err, gojwt.ErrTokenExpired):
                    http.Error(w, "token expired", http.StatusUnauthorized)
                case errors.Is(err, gojwt.ErrTokenBlacklisted):
                    http.Error(w, "token revoked", http.StatusUnauthorized)
                default:
                    http.Error(w, "invalid token", http.StatusUnauthorized)
                }
                return
            }

            // ========== 第三步：放行 ==========
            // 将 Claims 放入 context，后续 handler 可以直接读取用户 ID / 角色 / 业务域。
            ctx := context.WithValue(r.Context(), claimsKey{}, tokenClaims)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
```

读取上下文中的 Claims：

```go
// 从 context 中读取 claims。
func ClaimsFromContext(ctx context.Context) (*claims.Claims, bool) {
    tokenClaims, ok := ctx.Value(claimsKey{}).(*claims.Claims)
    return tokenClaims, ok
}
```

Gin 项目的接线方式相同：

```go
func GinAuth(v gojwt.Verifier) gin.HandlerFunc {
    return func(c *gin.Context) {
        token, err := gojwt.ParseBearerToken(c.GetHeader("Authorization"))
        if err != nil {
            status := http.StatusBadRequest
            if errors.Is(err, gojwt.ErrAuthorizationMissing) {
                status = http.StatusUnauthorized
            }
            c.AbortWithStatusJSON(status, gin.H{"error": err.Error()})
            return
        }
        tokenClaims, err := v.CachedParseTokenContext(c.Request.Context(), token)
        if err != nil {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
            return
        }
        c.Set("claims", tokenClaims)
        c.Next()
    }
}
```

## 登录 / 刷新 / 登出 示例

### 登录接口示例

```go
// 登录成功后签发 access token。
func Login(j gojwt.Issuer, uid int64) (string, error) {
    return j.GenerateToken(
        uid,
        // 标记为后台管理端 token。
        claims.WithPrv("admin"),
        // 写入角色。
        claims.WithRoles("admin"),
    )
}
```

### 刷新接口示例

```go
// 刷新接口显式区分"未到刷新窗口""会话到期"和"token 失效"。
func Refresh(j gojwt.Issuer, oldToken string) (string, error) {
    newToken, err := j.RefreshToken(oldToken)
    if err != nil {
        switch {
        case errors.Is(err, gojwt.ErrRefreshTooEarly):
            // 返回 400 或业务码，提示客户端稍后再刷新。
        case errors.Is(err, gojwt.ErrRefreshExpired):
            // 会话已到最长时长，返回 401 让客户端重新登录。
        }
        return "", err
    }
    return newToken, nil
}
```

### 登出接口示例

```go
// 登出时优先按 token 自身 exp 加入黑名单。
func Logout(blacklist *gojwt.Blacklist, tokenClaims *claims.Claims) error {
    if blacklist == nil || tokenClaims == nil {
        return nil
    }
    return blacklist.AddToken(tokenClaims)
}
```

### 改密踢下线示例

```go
// 改密时记录时刻；WithRevocationCheck 回调据此把该用户改密前签发的全部 token 判为已吊销。
func ChangePassword(ctx context.Context, store Store, uid int64, newPassword string) error {
    if err := store.UpdatePassword(ctx, uid, newPassword); err != nil {
        return err
    }
    return store.SetPasswordChangedAt(ctx, uid, time.Now())
}
```

## 密钥工具

### 生成 HMAC 密钥

```go
// 按算法生成随机 HMAC 密钥字符串，直接 []byte(secret) 作为 NewJwtHmac 的密钥即可。
secret, err := gojwt.GenerateHMACKeyString(jwtv5.SigningMethodHS512)
if err != nil {
    panic(err)
}
fmt.Println(secret) // 86 字符
```

生成长度：HS256 为 32 字节随机数（43 字符），HS384 为 48 字节（64 字符），HS512 为 64 字节（86 字符）。

### 生成 Ed25519 密钥对

```go
// 生成 PEM 格式的 Ed25519 密钥对文件；目标文件已存在时返回 fs.ErrExist，不会覆盖。
err := gojwt.GenerateEd25519Keys("./cert/jwt.pem", "./cert/jwt.pub.pem")
if err != nil && !errors.Is(err, fs.ErrExist) {
    panic(err)
}
```

### 生成 RSA 密钥对

```go
// 生成 2048 bit RSA 密钥对，RS/PS 全系列算法都可用；目标文件已存在时返回 fs.ErrExist，不会覆盖。
err := gojwt.GenerateRSAKeys("./cert/rsa.pem", "./cert/rsa.pub.pem", 2048)
if err != nil && !errors.Is(err, fs.ErrExist) {
    panic(err)
}

// 需要更高安全强度时生成 3072 或 4096 bit。
err = gojwt.GenerateRSAKeys("./cert/rsa4096.pem", "./cert/rsa4096.pub.pem", 4096)
```

### 解析 PEM 字节

```go
func ParseRSAPrivateKeyPEM(data []byte) (*rsa.PrivateKey, error)
func ParseRSAPublicKeyPEM(data []byte) (*rsa.PublicKey, error)
func ParseEd25519PrivateKeyPEM(data []byte) (ed25519.PrivateKey, error)
func ParseEd25519PublicKeyPEM(data []byte) (ed25519.PublicKey, error)
```

密钥来自 KMS、Vault、环境变量或配置中心时，用它们解析后交给 `NewJwtRSAFromKeys` / `NewJwtRSAVerifier` /
`NewJwtEd25519FromKeys` / `NewJwtEd25519Verifier`。

## 错误处理

常见错误包括：

- `ErrInvalidConfig`：构造参数非法，错误信息指出该改哪个 Option
- `ErrJWTNotInit`：在 nil 实例上调用方法
- `ErrInvalidKey` / `ErrInvalidKeyType`：密钥加载失败、公私钥不匹配、密钥算法类型不符
- `ErrNoSigningKey`：只持公钥的实例调用签发或刷新
- `ErrUnknownKeyID`：`KeyRing` 中没有注册 token 携带的 `kid`
- `ErrTokenMalformed`
- `ErrTokenUnverifiable`
- `ErrTokenSignatureInvalid`
- `ErrTokenRequiredClaimMissing`：缺少 `exp` 等必需字段
- `ErrTokenInvalidAudience`
- `ErrTokenExpired`
- `ErrTokenUsedBeforeIssued`：`iat` 晚于当前时刻加 leeway
- `ErrTokenInvalidIssuer`
- `ErrTokenInvalidSubject`
- `ErrTokenNotValidYet`
- `ErrTokenInvalidClaims`
- `ErrTokenInvalid`
- `ErrTokenBlacklisted`：黑名单命中或吊销回调判定已吊销
- `ErrRefreshTooEarly`
- `ErrRefreshExpired`：会话已到 `auth_time + refreshDuration`
- `ErrAuthorizationMissing` / `ErrAuthorizationInvalid`
- `ErrTokenRole`
- `ErrTokenPrv`

推荐使用 `errors.Is` 判断；解析类错误的 `err.Error()` 同时带有底层库的原因文本，便于排障：

```go
if err != nil {
    switch {
    case errors.Is(err, gojwt.ErrTokenExpired):
        fmt.Println("token 已过期")
    case errors.Is(err, gojwt.ErrTokenSignatureInvalid):
        fmt.Println("token 签名非法")
    case errors.Is(err, gojwt.ErrRefreshTooEarly):
        fmt.Println("未到刷新窗口")
    case errors.Is(err, gojwt.ErrRefreshExpired):
        fmt.Println("会话已到期")
    default:
        fmt.Println("处理失败:", err)
    }
}
```

## 算法如何选择

### 选择 HMAC（HS256 / HS384 / HS512）

适合：

- 单体服务
- 内部系统
- 签发和验签都在同一服务边界内

优点：

- 部署简单
- 不依赖公私钥文件
- 使用成本低

### 选择 Ed25519

适合：

- 多服务验签
- 只有少数服务具备签发权限
- 希望安全边界更清晰
- 对性能要求高

优点：

- 公私钥职责分离，验签方只需 `NewJwtEd25519VerifierFromFile`
- 签名验签速度最快的非对称算法
- 密钥短（32 字节）

### 选择 RSA（RS256 / PS256 等）

适合：

- 需要与使用 RS256 的第三方系统互通，持有对方公钥即可验签
- 需要 NIST 合规的场景

优点：

- 生态兼容性最好
- PSS 系列比 PKCS1-v1_5 更安全
- 公私钥职责分离，验签方只需 `NewJwtRSAVerifierFromFile`

注意：

- 密钥较长（2048 bit 起），签名验签比 Ed25519 慢
- 新项目如无兼容性要求，优先考虑 Ed25519

### 快速选型

| 场景 | 推荐 |
|------|------|
| 单体服务、简单鉴权 | HMAC（HS256） |
| 微服务、签发/验证分离、高性能 | Ed25519 |
| 与使用 RS256 的第三方系统互通 | RSA（RS256） |
| 新项目、更安全的 RSA | RSA（PS256） |

## 最佳实践

### 1. 黑名单建议存 `token_id`

不要把整段 token 当作黑名单 key，优先存 `TokenID`。

原因：

- 长度更短
- 逻辑更清晰
- 不暴露完整 token 内容

### 2. HMAC 密钥用 `GenerateHMACKeyString` 生成

库里按算法强制要求最小密钥长度，`GenerateHMACKeyString(method)` 生成的密钥总能满足，且熵足够。不要手写简单口令。

### 3. `CachedParseToken` 用在重复校验场景

适合：

- 网关层重复校验相同 token
- 同一请求链路中多次读取同一 token

### 4. 用 `RefreshToken` 做 Access Token 临期续签

客户端在 token 临期时调用刷新接口，续到 `auth_time + refreshDuration` 为止；到达终点收到 `ErrRefreshExpired` 时引导重新登录。
需要"随时可刷"时把 `WithRefreshWindow` 设为与 `WithTokenDuration` 相等。

### 5. 多实例黑名单落 Redis

内存黑名单适用于单实例。多副本部署时把 `token_id` 存入 Redis，通过 `WithBlacklistCheckContextFunc` 接入。

### 6. 密钥轮换用 `KeyRing`

签发方给每把密钥配 `WithKeyID`，验证方用 `KeyRing` 注册新旧两把；等旧 token 全部过期后 `Unregister` 旧 kid。

### 7. 验签方只拿公钥

授权中心持私钥签发，其他服务用 `NewJwtRSAVerifierFromFile` / `NewJwtEd25519VerifierFromFile` 验签，私钥不出授权中心。

## 常见问题

### 为什么 `RefreshToken` 会返回 `ErrRefreshTooEarly`

因为当前设计只允许"接近过期时刷新"，避免客户端在 token 刚发下来时就不断刷新。刷新窗口可用 `WithRefreshWindow` 调整。

### 为什么 `RefreshToken` 会返回 `ErrRefreshExpired`

会话已经到达 `auth_time + refreshDuration`。刷新链从首次签发起有上界，到期后需要重新登录。

### `CachedParseToken` 如何控制内存增长

当前实现默认限制最多缓存 `4096` 条，并通过 LRU 淘汰和 token 过期时间惰性清扫控制内存增长。可通过 `WithCacheMaxEntries(n)` 调整容量，传 `0` 可关闭缓存路径。

### 为什么内存黑名单还保留 `Add(tokenID string)`

这是为了兼容已有调用方。新代码优先使用 `AddToken` 或 `AddWithExpiration`，这样条目会随 token 生命周期自动失效。

### 为什么还需要 `NewBlacklistWithCleanup`

惰性失效只能在调用 `In(tokenID)` 时删除过期条目。长生命周期进程如果写入很多一次性 token、但后续不再查询这些 token，过期条目仍会留在内存里。`NewBlacklistWithCleanup` 提供了一个可选的主动清理机制。

## 测试

```bash
# 运行全部测试
go test ./...

# 含数据竞争检测
go test -race ./...

# 查看测试覆盖率
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out

# 运行 fuzz 冒烟测试
go test -run=^$ -fuzz=FuzzJwtHmacParseToken -fuzztime=5s .
go test -run=^$ -fuzz=FuzzPEMKeyParsers -fuzztime=5s .

# 运行 Example 测试
go test -run Example ./... -v
```

测试覆盖单元测试、Example 测试、Benchmark、fuzz 与数据竞争检测。

## 兼容说明

- `gojwt.Option` 是当前推荐命名
- `gojwt.Options` 仍可用，但已 deprecated
- `claims.Option` 是当前推荐命名
- `claims.Options` 仍可用，但已 deprecated
- `GenerateSecureKey()` / `GenerateSecureKeyString()` 仍可用，但已 deprecated，请迁移到 `GenerateHMACKeyString(method)`
- `claims.WithExpiresAt()` 仍可用，但已 deprecated，请迁移到 `claims.WithExpiresIn()` 或 `claims.WithExpiresAtTime()`

## License

MIT，见仓库根目录的 `LICENSE` 文件。
