# gojwt

`gojwt` 是一个轻量、直接、面向生产使用的 JWT 工具库，支持以下三类签名方式：

- `HMAC-SHA` 家族：默认 `HS256`，可选 `HS384`、`HS512`
- `Ed25519` (EdDSA)
- `RSA` 家族：默认 `RS256`，可选 `RS384`、`RS512`（PKCS1-v1_5）及 `PS256`、`PS384`、`PS512`（PSS）

库中提供了统一的 Token 生成、解析、刷新、缓存解析、并发校验、黑名单等能力，适合在 API 服务、后台服务、网关鉴权和内部 RPC 场景中使用。

## 为什么封装 gojwt

Go 生态中已经有了 `github.com/golang-jwt/jwt/v5` 这样优秀的底层 JWT 库，
但直接在业务代码中使用它，你会发现有很多「配套工作」需要反复处理：

**签发阶段：**
每次签发 token 都要手动拼接 Claims 结构体、生成随机 TokenID、设置 `exp` / `iat` / `nbf` 时间字段、额外写一遍 `jti` 与自定义 ID 的对齐逻辑——十几行重复的样板代码。

**解析阶段：**
解析 token 后要单独做黑名单检查、把 `golang-jwt` 的底层错误映射成业务层能理解的错误码、处理时钟漂移容忍时间。这些每次都得自己写。

**刷新阶段：**
刷新 token 时要重新生成 TokenID、重置 iat/nbf/exp、保证旧 token 被吊销后新 token 仍然可独立吊销——少做一步都是安全隐患。

**算法切换：**
如果你从 HMAC 切换到 Ed25519 或 RSA，ParseToken 中获取验签密钥的逻辑完全不同，GenerateToken 的签名方式也要改。没有统一抽象的话，改一次算法要动大量业务代码。

**gojwt 替你做了这些：**

- ✅ 签发时自动生成 TokenID、写入时间字段、对齐 `jti`
- ✅ 解析时自动检查黑名单、归一化错误、容忍时钟漂移
- ✅ 刷新时自动轮换 TokenID，保证旧 token 与新 token 独立可吊销
- ✅ 提供统一接口 `Tokener`，HMAC / Ed25519 / RSA 切换只需改构造行
- ✅ 内置并发安全缓存 + 有界 worker pool 并发验签
- ✅ 提供完整的 sentinel error 体系，业务层用 `errors.Is` 一行判断

**简单说：gojwt 让你只关心「谁、什么角色、能不能过」，不关心「怎么签名、怎么对齐、怎么吊销」。

## 特性

- 支持 `HMAC-SHA` 家族、`Ed25519` 与 `RSA`（RS/PS 系列）
- 内置业务 Claims 结构
- 支持标准字段与业务字段混合签发
- 支持临近过期时刷新 Token
- 支持缓存解析 `CachedParseToken`
- 支持带 context 的解析、刷新、缓存解析和批量并发验签
- 提供并发安全内存黑名单
- 支持写入与读取 `kid`，便于密钥轮换与网关侧按 kid 选密钥
- 提供统一接口 `Tokener`
- 错误统一为 sentinel error，便于 `errors.Is`

## 环境要求

- Go `1.26`

## 安装

```bash
go get github.com/gtkit/gojwt
```

## 适用场景

### 什么时候适合用这个库

- 你需要在 Go 服务里快速接入 JWT
- 你希望在 `HMAC`、`Ed25519` 和 `RSA` 之间自由切换
- 你需要对 token 做角色、业务域、过期时间等校验
- 你需要一个简单直接、没有重型框架依赖的 JWT 封装

### 什么时候不适合

- 你需要分布式黑名单同步
- 你需要超大规模、强约束的本地缓存淘汰策略
- 你需要 OAuth2 / OIDC 全套协议能力

这类需求通常应交给 Redis、外部鉴权中心或更完整的身份系统来处理。

## 包结构

```text
gojwt/
├── blacklist.go      # 并发安全黑名单
├── error.go          # 主包错误定义
├── helpers.go        # 缓存、错误归一化、刷新逻辑
├── jwt.go            # 密钥工具函数
├── jwted25519.go     # Ed25519 实现
├── jwthmac.go        # HMAC 实现
├── jwtrsa.go         # RSA 实现（RS/PS 系列）
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

    UserID  int64    `json:"uid"`
    Prv     string   `json:"prv,omitempty"`
    Roles   []string `json:"roles,omitzero"`
    TokenID string   `json:"token_id"`
}
```

字段说明：

- `UserID`：业务用户 ID
- `Prv`：业务域标识，例如 `admin`、`app`、`open-api`
- `Roles`：角色集合
- `TokenID`：唯一 Token ID；默认自动生成，并与 JWT 标准字段 `jti` 保持一致
- `RegisteredClaims`：JWT 标准字段，如 `exp`、`iat`、`nbf`、`iss`、`sub`

### 默认时长

两种算法实现的默认值相同：

- `tokenDuration = 2 小时`
- `refreshDuration = 7 天`
- `parseLeeway = 5 秒`
- `cacheMaxEntries = 4096`

可以通过构造时的 Option 修改。

### Refresh 规则

`RefreshToken` 的行为不是“随时可刷新”，而是“进入刷新窗口后才允许刷新”。

当前规则：

- token 距离签发时间超过 `refreshDuration`，返回 `ErrTokenExpired`
- token 距离过期时间仍大于等于 `5 分钟`，返回 `ErrRefreshTooEarly`
- 只有在离过期不足 `5 分钟` 时，才允许刷新
- 刷新成功后会生成新的 `TokenID/jti`，并重置 `iat`、`nbf`，旧新 token 可独立吊销

这非常适合 Access Token 的”临期续签”模型。

## 快速开始

### HMAC 用法

```go
package main

import (
    "errors"
    "fmt"
    "time"

    jwtv5 "github.com/golang-jwt/jwt/v5"
    "github.com/gtkit/gojwt"
    "github.com/gtkit/gojwt/claims"
)

func main() {
    // ========== 密钥准备 ==========
    // HS512 要求密钥至少 64 字节。建议使用 GenerateSecureKeyString() 生成随机密钥，
    // 不要用手写简单口令——它们熵不够，容易被暴力枚举。
    secret := []byte("1234567890123456789012345678901234567890123456789012345678901234")

    // ========== 创建实例 ==========
    // NewJwtHmac 接受密钥和可选的配置 Option。
    // 所有可选配置都通过 WithXXX 函数注入，不传则使用默认值。
    j, err := gojwt.NewJwtHmac(
        secret,
        // 默认使用 HS256，这里显式切换为 HS512。
        gojwt.WithHMACSigningMethod(jwtv5.SigningMethodHS512),
        // Access Token 有效期：2 小时。
        gojwt.WithTokenDuration(2*time.Hour),
        // Refresh 总窗口：7 天。超过这个时间，即使 token 未过期也不再允许刷新。
        gojwt.WithRefreshDuration(7*24*time.Hour),
    )
    if err != nil {
        panic(err)
    }

    // ========== 签发 Token ==========
    // GenerateToken 必须传用户 ID，还可通过 claims.Option 附加业务字段。
    // 系统会自动生成唯一 TokenID、设置 exp/iat/nbf、对齐 jti。
    token, err := j.GenerateToken(
        10001,                          // 用户 ID
        claims.WithPrv("admin"),        // 业务域：控制后台
        claims.WithRoles("admin", "finance"), // 角色：管理员 + 财务
        claims.WithIssuer("gtkit-auth"), // 签发者
        claims.WithSubject("access-token"),   // 主题
    )
    if err != nil {
        panic(err)
    }

    // ========== 解析 Token ==========
    // ParseToken 会自动完成：签名验证、时间字段校验（默认容忍 5s 时钟漂移）、
    // 黑名单检查（如果配置了的话）。
    tokenClaims, err := j.ParseToken(token)
    if err != nil {
        panic(err)
    }

    // 读取 Claims 中的业务字段。
    fmt.Println("uid:", tokenClaims.UserID)       // 10001
    fmt.Println("tokenID:", tokenClaims.TokenID)   // 自动生成的 16 字节随机 ID
    fmt.Println("prv:", tokenClaims.Prv)           // admin
    fmt.Println("roles:", tokenClaims.Roles)       // [admin finance]

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
    // RefreshToken 只在「token 距过期不足 5 分钟」时允许执行。
    // 这是为了防止客户端无限刷新同一个 token。
    newToken, err := j.RefreshToken(token)
    if err != nil {
        if errors.Is(err, gojwt.ErrRefreshTooEarly) {
            // 业务上可以告诉调用方：token 仍然有效，还没到刷新窗口。
            fmt.Println("当前还没到刷新窗口")
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
    "fmt"
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

    // 首次部署时生成 Ed25519 密钥对文件。
    // 私钥文件权限 0600，公钥文件权限 0644。
    if err := gojwt.GenerateEd25519Keys(priPath, pubPath); err != nil {
        panic(err)
    }

    // ========== 加载密钥对 ==========
    // 从 PEM 文件加载私钥和公钥。私钥负责签名，公钥负责验签。
    j, err := gojwt.NewJwtEd25519(priPath, pubPath)
    if err != nil {
        panic(err)
    }

    // ========== 签发 Token ==========
    // 使用私钥签名。接口与 HMAC 完全一致。
    token, err := j.GenerateToken(
        20001,
        claims.WithPrv("open-api"),    // 业务域：开放 API
        claims.WithRoles("service"),   // 角色：服务调用
    )
    if err != nil {
        panic(err)
    }

    // ========== 验签并解析 ==========
    // 只有持有对应公钥的实例才能验签。即使 HMAC 密钥泄露，
    // 攻击者也无法伪造 Ed25519 token——因为他不持有私钥。
    tokenClaims, err := j.ParseToken(token)
    if err != nil {
        panic(err)
    }

    fmt.Println("uid:", tokenClaims.UserID)
}
```

### RSA 用法

```go
package main

import (
    "fmt"
    "path/filepath"

    jwtv5 "github.com/golang-jwt/jwt/v5"
    "github.com/gtkit/gojwt"
    "github.com/gtkit/gojwt/claims"
)

func main() {
    // ========== 生成 RSA 密钥对 ==========
    // RSA 是非对称签名，适合与第三方系统集成（OAuth2 / OIDC 事实标准）。
    // 2048 bit 适用于 RS256 和 PS256；RS384/PS384 至少 3072 bit；RS512/PS512 至少 4096 bit。
    priPath := filepath.Join("cert", "jwt_rsa.pem")
    pubPath := filepath.Join("cert", "jwt_rsa.pub.pem")

    // 首次部署时生成 RSA 密钥对。
    if err := gojwt.GenerateRSAKeys(priPath, pubPath, 2048); err != nil {
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

    // ========== 解析并验签 ==========
    // 使用公钥验签。如果对接第三方 OIDC 系统（如 Auth0、Cognito），
    // 你通常只需要加载它们的公钥来验签即可，不需要私钥。
    tokenClaims, err := j.ParseToken(token)
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
```

## 构造函数

### `NewJwtHmac`

```go
func NewJwtHmac(secretKey []byte, options ...gojwt.Option) (*gojwt.JwtHmac, error)
```

说明：

- 默认使用 `HS256`
- 可通过 `WithHMACSigningMethod` 切换到 `HS384` / `HS512`
- `HS256` 至少 `32` 字节，`HS384` 至少 `48` 字节，`HS512` 至少 `64` 字节
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
- `Ed25519` / `RSA` 实例不接受这个 Option

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
| PKCS1-v1_5 | `RS256` / `RS384` / `RS512` | 兼容性最好，OAuth2/OIDC 默认 |
| PSS | `PS256` / `PS384` / `PS512` | 更安全，推荐新项目使用 |

注意：

- 不传时默认 `RS256`
- `HMAC` / `Ed25519` 实例不接受这个 Option

### `NewJwtEd25519`

```go
func NewJwtEd25519(priPath, pubPath string, options ...gojwt.Option) (*gojwt.JwtEd25519, error)
```

说明：

- 从 PEM 文件加载私钥、公钥
- 私钥负责签名
- 公钥负责验签
- 更适合多服务共享公钥的场景

### `NewJwtRSA`

```go
func NewJwtRSA(priPath, pubPath string, options ...gojwt.Option) (*gojwt.JwtRSA, error)
```

说明：

- 从 PEM 文件加载 RSA 密钥对
- 支持 PKCS1（`RSA PRIVATE KEY`）和 PKCS8（`PRIVATE KEY`）格式
- 默认使用 `RS256`
- 可通过 `WithRSASigningMethod` 切换到 `RS384` / `RS512` / `PS256` / `PS384` / `PS512`
- 密钥长度要求：`RS256/PS256` 至少 `2048` bit，`RS384/PS384` 至少 `3072` bit，`RS512/PS512` 至少 `4096` bit

示例：

```go
j, err := gojwt.NewJwtRSA(priPath, pubPath, gojwt.WithRSASigningMethod(jwtv5.SigningMethodPS256))
```

### `NewJwtRSAFromKeys`

```go
func NewJwtRSAFromKeys(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, options ...gojwt.Option) (*gojwt.JwtRSA, error)
```

说明：

- 直接使用内存中的 RSA 密钥对创建实例
- 适用于密钥来自 KMS、Vault、环境变量等外部系统
- 其余行为与 `NewJwtRSA` 一致

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

用于设置刷新总窗口。

```go
// 将 refresh 总窗口设置为 3 天。
j, err := gojwt.NewJwtHmac(
    []byte("12345678901234567890123456789012"),
    gojwt.WithRefreshDuration(72*time.Hour),
)
if err != nil {
    panic(err)
}
_ = j
```

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
- 会同时作用于 `exp`、`nbf`、`iat`
- 如果你希望严格按时间字段校验，可显式传 `gojwt.WithParseLeeway(0)`

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

验证侧用 `ParseKeyID` 读出 `kid` 来定位密钥，见下一节。

两个典型用途：

**密钥轮换**。新旧密钥并存期间，验证方靠 `kid` 知道该用哪一把，不必停机切换：

```go
// 轮换期：新签发的 token 用新密钥，老 token 仍带着老 kid 在有效期内正常使用
oldJwt, _ := gojwt.NewJwtHmac(oldSecret, gojwt.WithKeyID("app-2025"))
newJwt, _ := gojwt.NewJwtHmac(newSecret, gojwt.WithKeyID("app-2026"))

verifiers := map[string]*gojwt.JwtHmac{
    "app-2025": oldJwt,
    "app-2026": newJwt,
}

// 验证方：先按 kid 选密钥，再用选中的实例验签
kid, err := gojwt.ParseKeyID(tokenString)
if err != nil {
    return err
}
j, ok := verifiers[kid]
if !ok {
    return gojwt.ErrInvalidKey
}
cc, err := j.ParseToken(tokenString)
```

**网关侧预校验**。网关按 `kid` 在多个密钥中定位，同一个网关可以同时接收不同算法签发的 token：

```go
hmacJwt, _ := gojwt.NewJwtHmac(secret, gojwt.WithKeyID("app-2026"))
rsaJwt, _  := gojwt.NewJwtRSA(priPath, pubPath, gojwt.WithKeyID("rs-2026"))

// 两种算法签发的 token 走同一个入口，靠 kid 分流到对应实例
verifiers := map[string]gojwt.Tokener{
    "app-2026": hmacJwt,
    "rs-2026":  rsaJwt,
}

kid, err := gojwt.ParseKeyID(tokenString)
if err != nil {
    return err
}
j, ok := verifiers[kid]
if !ok {
    return gojwt.ErrInvalidKey
}
cc, err := j.ParseToken(tokenString)
```

### `ParseKeyID`

不验签地读出 token header 中的 `kid`，用于在验签前定位该用哪一把密钥。

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

### `WithBlacklistCheckFunc`

用于注入可返回错误的黑名单检查函数，适合 Redis、数据库等外部依赖场景。

```go
ctx := context.Background()

j, err := gojwt.NewJwtHmac(
    []byte("12345678901234567890123456789012"),
    gojwt.WithBlacklistCheckFunc(func(tokenID string) (bool, error) {
        n, err := rdb.Exists(ctx, "jwt:blacklist:"+tokenID).Result()
        return n > 0, err
    }),
)
if err != nil {
    panic(err)
}
_ = j
```

### `WithBlacklistCheckContextFunc`

用于注入支持 `context.Context` 的黑名单检查函数，适合 Redis、数据库等需要超时控制的外部依赖场景。

```go
ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
defer cancel()
token := "your.jwt.token.here"

j, err := gojwt.NewJwtHmac(
    []byte("12345678901234567890123456789012"),
    gojwt.WithBlacklistCheckContextFunc(func(ctx context.Context, tokenID string) (bool, error) {
        n, err := rdb.Exists(ctx, "jwt:blacklist:"+tokenID).Result()
        return n > 0, err
    }),
)
if err != nil {
    panic(err)
}

_, err = j.ParseTokenContext(ctx, token)
_ = err
```

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
- 不要只改算法不升级密钥长度；算法越强，密钥也应该同步变长

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

说明：

- `claims.WithJwtID` 会同时设置标准字段 `jti` 和业务字段 `token_id`
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
- 自动写入 `exp`、`iat`、`nbf`
- 自动生成唯一 `TokenID`

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

- 完成验签
- 校验标准时间字段
- 默认带 `5 秒` leeway，用于吸收轻微时钟漂移
- 可通过构造时的 `WithParseLeeway` 修改，或在单次调用中通过 `jwt.ParserOption` 覆盖
- 返回 `*claims.Claims`

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
- 再次解析相同 token 时优先命中缓存
- 返回的是 Claims 副本，避免调用方意外改坏缓存对象
- 仅在未传入 `ParserOption` 时使用缓存；传入 `issuer`/`audience`/`subject` 等校验选项时会退化为普通解析

注意事项：

- 缓存是“实例级”的，不跨不同 JWT 实例共享
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

- 使用旧 token 中的 Claims 重新签发新 token
- 保留原业务字段
- 生成新的 `TokenID/jti`，重置 `iat`、`nbf`、`exp`
- 旧 token 与新 token 可独立吊销

示例：

```go
// 对即将过期的 token 进行刷新。
newToken, err := j.RefreshToken(oldToken)
if err != nil {
    if errors.Is(err, gojwt.ErrRefreshTooEarly) {
        // 这里表示 token 还没进入刷新窗口。
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
- `results[i]` 与 `errs[i]` 对应同一个输入 token
- `ParallelVerifyContext` 会在 `ctx` 取消后停止分发未开始的任务，并将 ctx 透传给 context-aware 黑名单检查函数

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

### `TTL`

```go
// 获取 token 剩余有效时间。
ttl := tokenClaims.TTL()
fmt.Println("ttl:", ttl)
```

## 统一接口 `Tokener`

如果你的业务层不想依赖具体算法实现，可以面向 `Tokener` 编程。

```go
package main

import (
    "github.com/gtkit/gojwt"
    "github.com/gtkit/gojwt/claims"
)

func IssueToken(t gojwt.Tokener, uid int64) (string, error) {
    // 调用方不用关心底层是 HMAC、Ed25519 还是 RSA。
    return t.GenerateToken(uid, claims.WithPrv("admin"))
}
```

需要 context 取消能力时，可按需断言扩展接口：

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

- 当前是纯内存实现
- `AddToken` / `AddWithExpiration` 写入的条目会在到达过期时间后惰性失效
- 如果使用 `NewBlacklistWithCleanup`，后台会按固定间隔主动清理过期条目
- `Close()` 应在服务退出时调用，用于停止后台清理协程
- `Add(tokenID)` 是兼容旧代码的永久拉黑接口
- 进程重启后数据会丢失
- 多实例之间不会自动同步

如果你要在多实例部署下使用黑名单，建议将 `token_id` 存入 Redis。

## 中间件接入示例

下面给一个简化版 HTTP 中间件示例，演示如何解析 Bearer Token、校验黑名单，并把 Claims 放进请求上下文。

```go
package main

import (
    "context"
    "errors"
    "net/http"
    "strings"

    "github.com/gtkit/gojwt"
    "github.com/gtkit/gojwt/claims"
)

// claimsKey 是 context 中存储 Claims 的键，使用空结构体避免 key 冲突。
type claimsKey struct{}

// AuthMiddleware 返回一个 HTTP 中间件，负责从请求中解析 Bearer Token、
// 校验黑名单，并把解析后的 Claims 注入请求上下文。
//
// 参数说明：
//   - j：JWT 实例。理论上可以是 *JwtHmac / *JwtEd25519 / *JwtRSA 的任意一种，
//     因为它们都实现了 Tokener 接口（本例为简洁用具体类型演示）。
//   - blacklist：黑名单检查器。传 nil 则跳过黑名单检查。
//
// 在 handler 中通过 ClaimsFromContext 获取 Claims。
func AuthMiddleware(j *gojwt.JwtHmac, blacklist gojwt.Blacklister) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // ========== 第一步：取 Token ==========
            // 标准 HTTP Authorization 头格式："Bearer <token>"
            authHeader := r.Header.Get("Authorization")
            if authHeader == "" {
                http.Error(w, "missing authorization header", http.StatusUnauthorized)
                return
            }

            // 只接受 Bearer 方案，不做 Basic / Digest 等。
            const prefix = "Bearer "
            if !strings.HasPrefix(authHeader, prefix) {
                http.Error(w, "invalid authorization scheme", http.StatusUnauthorized)
                return
            }

            token := strings.TrimPrefix(authHeader, prefix)

            // ========== 第二步：解析并验签 ==========
            // 使用 CachedParseToken：同一请求链路中如果多次读取 Claims，
            // 第二次开始命中缓存，避免重复 RSA/Ed25519 验签开销。
            tokenClaims, err := j.CachedParseToken(token)
            if err != nil {
                // 根据错误类型返回不同的 HTTP 状态和消息。
                switch {
                case errors.Is(err, gojwt.ErrTokenExpired):
                    http.Error(w, "token expired", http.StatusUnauthorized)
                default:
                    http.Error(w, "invalid token", http.StatusUnauthorized)
                }
                return
            }

            // ========== 第三步：黑名单检查 ==========
            // 即使 token 签名有效且未过期，如果 TokenID 已被加入黑名单
            //（用户登出、管理员强制吊销等），仍应拒绝。
            if blacklist != nil && blacklist.In(tokenClaims.TokenID) {
                http.Error(w, "token revoked", http.StatusUnauthorized)
                return
            }

            // ========== 第四步：放行 ==========
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

## 登录 / 刷新 / 登出 示例

### 登录接口示例

```go
// 登录成功后签发 access token。
func Login(j *gojwt.JwtHmac, uid int64) (string, error) {
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
// 刷新接口建议显式区分“未到刷新窗口”和“token 真失效”。
func Refresh(j *gojwt.JwtHmac, oldToken string) (string, error) {
    newToken, err := j.RefreshToken(oldToken)
    if err != nil {
        if errors.Is(err, gojwt.ErrRefreshTooEarly) {
            // 这里可以返回 400 或业务码，提示客户端稍后再刷新。
            return "", err
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

## 密钥工具

### 生成 HMAC 密钥

```go
// 生成随机 HMAC 密钥字符串。
secret, err := gojwt.GenerateSecureKeyString()
if err != nil {
    panic(err)
}
fmt.Println(secret)
```

### 兼容旧方法

```go
// Deprecated: 新代码请使用 GenerateSecureKeyString。
secret, err := gojwt.GenerateSecureKey()
if err != nil {
    panic(err)
}
fmt.Println(secret)
```

### 生成 Ed25519 密钥对

```go
// 生成 PEM 格式的 Ed25519 密钥对文件。
err := gojwt.GenerateEd25519Keys("./cert/jwt.pem", "./cert/jwt.pub.pem")
if err != nil {
    panic(err)
}
```

### 生成 RSA 密钥对

```go
// 生成 2048 bit RSA 密钥对（适用于 RS256/PS256）。
err := gojwt.GenerateRSAKeys("./cert/rsa.pem", "./cert/rsa.pub.pem", 2048)
if err != nil {
    panic(err)
}

// 生成 4096 bit RSA 密钥对（适用于 RS512/PS512）。
err = gojwt.GenerateRSAKeys("./cert/rsa4096.pem", "./cert/rsa4096.pub.pem", 4096)
if err != nil {
    panic(err)
}
```

## 错误处理

常见错误包括：

- `ErrJWTNotInit`
- `ErrTokenMalformed`
- `ErrTokenUnverifiable`
- `ErrTokenSignatureInvalid`
- `ErrTokenRequiredClaimMissing`
- `ErrTokenInvalidAudience`
- `ErrTokenExpired`
- `ErrTokenUsedBeforeIssued`
- `ErrTokenInvalidIssuer`
- `ErrTokenInvalidSubject`
- `ErrTokenNotValidYet`
- `ErrTokenInvalidClaims`
- `ErrTokenInvalid`
- `ErrRefreshTooEarly`
- `ErrTokenRole`
- `ErrTokenPrv`

推荐使用 `errors.Is` 判断：

```go
if err != nil {
    switch {
    case errors.Is(err, gojwt.ErrTokenExpired):
        fmt.Println("token 已过期")
    case errors.Is(err, gojwt.ErrTokenSignatureInvalid):
        fmt.Println("token 签名非法")
    case errors.Is(err, gojwt.ErrRefreshTooEarly):
        fmt.Println("未到刷新窗口")
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

- 公私钥职责分离
- 签名验签速度最快的非对称算法
- 密钥短（32 字节）

### 选择 RSA（RS256 / PS256 等）

适合：

- 需要对接第三方 OAuth2 / OIDC 系统（RS256 是事实标准）
- 与 AWS Cognito、Auth0、Firebase 等云服务集成
- 需要 NIST 合规的场景

优点：

- 生态兼容性最好，几乎所有 IdP 都支持
- PSS 系列比 PKCS1-v1_5 更安全
- 公私钥职责分离

注意：

- 密钥较长（2048-4096 bit），签名验签比 Ed25519 慢
- 新项目如无兼容性要求，优先考虑 Ed25519

### 快速选型

| 场景 | 推荐 |
|------|------|
| 单体服务、简单鉴权 | HMAC（HS256） |
| 微服务、签发/验证分离、高性能 | Ed25519 |
| 对接第三方 OAuth2/OIDC | RSA（RS256） |
| 新项目、更安全的 RSA | RSA（PS256） |

## 最佳实践

### 1. 黑名单建议存 `token_id`

不要把整段 token 当作黑名单 key，优先存 `TokenID`。

原因：

- 长度更短
- 逻辑更清晰
- 不暴露完整 token 内容

### 2. HMAC 密钥使用随机高熵字符串

虽然库里已经强制要求最少 `32` 字节，但仍建议使用 `GenerateSecureKeyString()` 生成，不要手写简单口令。

### 3. `CachedParseToken` 适合重复校验场景

适合：

- 网关层重复校验相同 token
- 同一请求链路中多次读取同一 token

不太适合：

- 基本每次请求都是不同 token

### 4. `RefreshToken` 适合 Access Token 临期续签

如果你的业务需要“任意时刻刷新”，当前实现不适合直接套用，建议单独设计 Refresh Token 体系。

### 5. 多实例黑名单请落 Redis

内存黑名单只适合单实例。如果你的服务是多副本部署，应把黑名单存外部存储。

## 常见问题

### 为什么 `RefreshToken` 会返回 `ErrRefreshTooEarly`

因为当前设计只允许“接近过期时刷新”，避免客户端在 token 刚发下来时就不断刷新。

### `CachedParseToken` 如何控制内存增长

当前实现默认限制最多缓存 `4096` 条，并通过 LRU 淘汰和 token 过期时间惰性清扫控制内存增长。可通过 `WithCacheMaxEntries(n)` 调整容量，传 `0` 可关闭缓存路径。

### 为什么黑名单不直接内置 Redis

因为库本身希望保持无外部基础设施依赖。Redis 黑名单通常跟业务部署方式强相关，更适合由上层应用自己实现。

### 为什么内存黑名单还保留 `Add(tokenID string)`

这是为了兼容已有调用方。新代码优先使用 `AddToken` 或 `AddWithExpiration`，这样条目会随 token 生命周期自动失效。

### 为什么还需要 `NewBlacklistWithCleanup`

惰性失效只能在调用 `In(tokenID)` 时删除过期条目。长生命周期进程如果写入很多一次性 token、但后续不再查询这些 token，过期条目仍会留在内存里。`NewBlacklistWithCleanup` 提供了一个可选的主动清理机制。

## 测试

```bash
# 运行全部测试
go test ./...

# 含数据竞争检测（CI 中必须开启）
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

当前测试覆盖情况：

- 主包覆盖率：**约 85%**（核心操作 100%）
- claims 子包覆盖率：**100%**
- Example 测试：**5 个**
- 数据竞争检测：**通过**（`go test -race`）
- 全部测试数：**104 个**，全部通过

## 兼容说明

- `gojwt.Option` 是当前推荐命名
- `gojwt.Options` 仍可用，但已 deprecated
- `claims.Option` 是当前推荐命名
- `claims.Options` 仍可用，但已 deprecated
- `GenerateSecureKey()` 仍可用，但已 deprecated，请迁移到 `GenerateSecureKeyString()`
- `claims.WithExpiresAt()` 仍可用，但已 deprecated，请迁移到 `claims.WithExpiresIn()` 或 `claims.WithExpiresAtTime()`

## License

如果需要开源发布，请按项目实际情况补充许可证文件。
