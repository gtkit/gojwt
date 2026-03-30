# gojwt

`gojwt` 是一个轻量、直接、面向生产使用的 JWT 工具库，支持以下两种签名方式：

- `HMAC-SHA256`
- `Ed25519`

库中提供了统一的 Token 生成、解析、刷新、缓存解析、并发校验、黑名单等能力，适合在 API 服务、后台服务、网关鉴权和内部 RPC 场景中使用。

## 特性

- 支持 `HMAC` 与 `Ed25519` 两种算法
- 内置业务 Claims 结构
- 支持标准字段与业务字段混合签发
- 支持临近过期时刷新 Token
- 支持缓存解析 `CachedParseToken`
- 支持批量并发验签 `ParallelVerify`
- 提供并发安全内存黑名单
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
- 你希望在 `HMAC` 和 `Ed25519` 之间自由切换
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
- `TokenID`：唯一 Token ID，创建时自动生成
- `RegisteredClaims`：JWT 标准字段，如 `exp`、`iat`、`nbf`、`iss`、`sub`

### 默认时长

两种算法实现的默认值相同：

- `tokenDuration = 2 小时`
- `refreshDuration = 7 天`

可以通过构造时的 Option 修改。

### Refresh 规则

`RefreshToken` 的行为不是“随时可刷新”，而是“进入刷新窗口后才允许刷新”。

当前规则：

- token 距离签发时间超过 `refreshDuration`，返回 `ErrTokenExpired`
- token 距离过期时间仍大于等于 `5 分钟`，返回 `ErrRefreshTooEarly`
- 只有在离过期不足 `5 分钟` 时，才允许刷新

这非常适合 Access Token 的“临期续签”模型。

## 快速开始

### HMAC 用法

```go
package main

import (
    "errors"
    "fmt"
    "time"

    "github.com/gtkit/gojwt"
    "github.com/gtkit/gojwt/claims"
)

func main() {
    // HMAC 密钥至少 32 字节。
    secret := []byte("12345678901234567890123456789012")

    // 创建 HMAC JWT 实例。
    j, err := gojwt.NewJwtHmac(
        secret,
        // 设置 access token 有效期。
        gojwt.WithTokenDuration(2*time.Hour),
        // 设置 token 允许刷新的总窗口。
        gojwt.WithRefreshDuration(7*24*time.Hour),
    )
    if err != nil {
        panic(err)
    }

    // 签发 token，并写入业务字段。
    token, err := j.GenerateToken(
        10001,
        // 设置业务域。
        claims.WithPrv("admin"),
        // 设置角色。
        claims.WithRoles("admin", "finance"),
        // 设置签发者。
        claims.WithIssuer("gtkit-auth"),
        // 设置主题。
        claims.WithSubject("access-token"),
    )
    if err != nil {
        panic(err)
    }

    // 解析并验签 token。
    tokenClaims, err := j.ParseToken(token)
    if err != nil {
        panic(err)
    }

    fmt.Println("uid:", tokenClaims.UserID)
    fmt.Println("tokenID:", tokenClaims.TokenID)
    fmt.Println("prv:", tokenClaims.Prv)
    fmt.Println("roles:", tokenClaims.Roles)

    // 校验角色。
    if err := tokenClaims.VerifyRole("admin"); err != nil {
        panic(err)
    }

    // 校验业务域。
    if err := tokenClaims.VerifyPrv("admin"); err != nil {
        panic(err)
    }

    // 刷新 token。
    newToken, err := j.RefreshToken(token)
    if err != nil {
        if errors.Is(err, gojwt.ErrRefreshTooEarly) {
            // 这里表示 token 仍然有效，只是还没进入刷新窗口。
            fmt.Println("当前还没到刷新窗口")
            return
        }
        panic(err)
    }

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
    // 定义密钥文件路径。
    priPath := filepath.Join("cert", "jwt_ed25519.pem")
    pubPath := filepath.Join("cert", "jwt_ed25519.pub.pem")

    // 首次部署时生成 Ed25519 密钥对。
    if err := gojwt.GenerateEd25519Keys(priPath, pubPath); err != nil {
        panic(err)
    }

    // 从 PEM 文件加载私钥、公钥。
    j, err := gojwt.NewJwtEd25519(priPath, pubPath)
    if err != nil {
        panic(err)
    }

    // 签发 token。
    token, err := j.GenerateToken(
        20001,
        claims.WithPrv("open-api"),
        claims.WithRoles("service"),
    )
    if err != nil {
        panic(err)
    }

    // 使用公钥完成验签与解析。
    tokenClaims, err := j.ParseToken(token)
    if err != nil {
        panic(err)
    }

    fmt.Println("uid:", tokenClaims.UserID)
}
```

## 构造函数

### `NewJwtHmac`

```go
func NewJwtHmac(secretKey []byte, options ...gojwt.Option) (*gojwt.JwtHmac, error)
```

说明：

- `secretKey` 至少 `32` 字节
- 使用 `HS256`
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

### `NewJwtEd25519`

```go
func NewJwtEd25519(priPath, pubPath string, options ...gojwt.Option) (*gojwt.JwtEd25519, error)
```

说明：

- 从 PEM 文件加载私钥、公钥
- 私钥负责签名
- 公钥负责验签
- 更适合多服务共享公钥的场景

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

> `Options` 是历史兼容别名，已 deprecated，新代码请使用 `Option`。

## Claims Option

签发时可以通过 `claims.Option` 动态组合 Claims：

- `claims.WithRole(role string)`
- `claims.WithRoles(roles ...string)`
- `claims.WithPrv(prv string)`
- `claims.WithIssuer(issuer string)`
- `claims.WithSubject(subject string)`
- `claims.WithAudience(audience ...string)`
- `claims.WithExpiresAt(expiresAt time.Duration)`
- `claims.WithJwtID(jwtID string)`

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
```

行为说明：

- 根据 `uid` 与附加 `claims.Option` 生成 JWT
- 自动写入 `exp`、`iat`、`nbf`
- 自动生成唯一 `TokenID`

### `ParseToken`

```go
func (j *JwtHmac) ParseToken(tokenString string, opt ...jwt.ParserOption) (*claims.Claims, error)
func (j *JwtEd25519) ParseToken(tokenString string, opt ...jwt.ParserOption) (*claims.Claims, error)
```

行为说明：

- 完成验签
- 校验标准时间字段
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
func (j *JwtEd25519) CachedParseToken(tokenString string, opt ...jwt.ParserOption) (*claims.Claims, error)
```

行为说明：

- 首次解析时正常验签并缓存 Claims
- 再次解析相同 token 时优先命中缓存
- 返回的是 Claims 副本，避免调用方意外改坏缓存对象

注意事项：

- 缓存是“实例级”的，不跨不同 JWT 实例共享
- 过期条目会做惰性清扫
- 当前没有容量上限，极端大规模唯一 token 场景应自行评估

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
func (j *JwtEd25519) RefreshToken(tokenString string, opt ...jwt.ParserOption) (string, error)
```

行为说明：

- 使用旧 token 中的 Claims 重新签发新 token
- 保留原业务字段
- 重新计算新的过期时间

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
```

行为说明：

- 并发验证多个 token
- `results[i]` 与 `errs[i]` 对应同一个输入 token

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
    // 调用方不用关心底层是 HMAC 还是 Ed25519。
    return t.GenerateToken(uid, claims.WithPrv("admin"))
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

示例：

```go
// 创建黑名单。
blacklist := gojwt.NewBlacklist()

// 用户登出时，将 tokenID 拉黑。
blacklist.Add("token-id-1")

// 请求进入时，先检查 token 是否已失效。
if blacklist.In("token-id-1") {
    fmt.Println("token 已失效")
}

// 需要恢复时可移除。
blacklist.Remove("token-id-1")
```

注意：

- 当前是纯内存实现
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

type claimsKey struct{}

func AuthMiddleware(j *gojwt.JwtHmac, blacklist gojwt.Blacklister) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // 读取 Authorization 头。
            authHeader := r.Header.Get("Authorization")
            if authHeader == "" {
                http.Error(w, "missing authorization header", http.StatusUnauthorized)
                return
            }

            // 只接受 Bearer Token。
            const prefix = "Bearer "
            if !strings.HasPrefix(authHeader, prefix) {
                http.Error(w, "invalid authorization scheme", http.StatusUnauthorized)
                return
            }

            token := strings.TrimPrefix(authHeader, prefix)

            // 使用缓存解析，减少重复验签开销。
            tokenClaims, err := j.CachedParseToken(token)
            if err != nil {
                switch {
                case errors.Is(err, gojwt.ErrTokenExpired):
                    http.Error(w, "token expired", http.StatusUnauthorized)
                default:
                    http.Error(w, "invalid token", http.StatusUnauthorized)
                }
                return
            }

            // 检查 token_id 是否已进入黑名单。
            if blacklist != nil && blacklist.In(tokenClaims.TokenID) {
                http.Error(w, "token revoked", http.StatusUnauthorized)
                return
            }

            // 将 claims 放入上下文，供后续 handler 使用。
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
// 登出时通常不是删除 token，而是将 tokenID 拉黑。
func Logout(blacklist gojwt.Blacklister, tokenClaims *claims.Claims) {
    if blacklist == nil || tokenClaims == nil {
        return
    }
    blacklist.Add(tokenClaims.TokenID)
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

## 错误处理

常见错误包括：

- `ErrJWTNotInit`
- `ErrTokenMalformed`
- `ErrTokenUnverifiable`
- `ErrTokenSignatureInvalid`
- `ErrTokenExpired`
- `ErrTokenNotValidYet`
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

## HMAC 与 Ed25519 如何选择

### 选择 HMAC

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

优点：

- 公私钥职责分离
- 可以把公钥分发到多个只读验证服务

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
- 需要严格容量淘汰策略的场景

### 4. `RefreshToken` 适合 Access Token 临期续签

如果你的业务需要“任意时刻刷新”，当前实现不适合直接套用，建议单独设计 Refresh Token 体系。

### 5. 多实例黑名单请落 Redis

内存黑名单只适合单实例。如果你的服务是多副本部署，应把黑名单存外部存储。

## 常见问题

### 为什么 `RefreshToken` 会返回 `ErrRefreshTooEarly`

因为当前设计只允许“接近过期时刷新”，避免客户端在 token 刚发下来时就不断刷新。

### 为什么 `CachedParseToken` 不做严格容量限制

当前实现定位是轻量封装，只做实例级缓存和惰性清扫。如果你需要 TTL + LRU + 容量上限，可以在外层自己做缓存包装。

### 为什么黑名单不直接内置 Redis

因为库本身希望保持无外部基础设施依赖。Redis 黑名单通常跟业务部署方式强相关，更适合由上层应用自己实现。

## 测试

运行测试：

```bash
go test ./...
```

## 兼容说明

- `gojwt.Option` 是当前推荐命名
- `gojwt.Options` 仍可用，但已 deprecated
- `claims.Option` 是当前推荐命名
- `claims.Options` 仍可用，但已 deprecated
- `GenerateSecureKey()` 仍可用，但已 deprecated，请迁移到 `GenerateSecureKeyString()`

## License

如果需要开源发布，请按项目实际情况补充许可证文件。
