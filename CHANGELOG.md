# Changelog

所有重要变更均记录在此文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
版本遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

> ⚠ 破坏性变更（均为 fail-closed，旧的危险行为改为显式报错并在错误信息中给出出路）：
>
> - 构造期校验 `refreshDuration >= tokenDuration` 与 `0 < refreshWindow <= tokenDuration`，
>   不满足返回 `ErrInvalidConfig`。此前 `refreshDuration` 在默认配置下从不生效，刷新链没有上界。
> - `ParseToken` 系列默认要求 `exp` 存在并校验 `iat`：缺 `exp` 的外来 token 返回 `ErrTokenRequiredClaimMissing`，
>   `iat` 晚于当前时刻加 leeway 返回 `ErrTokenUsedBeforeIssued`。本包签发的 token 天然满足。
> - `WithBlacklistFunc` / `WithBlacklistCheckFunc` / `WithBlacklistCheckContextFunc` 同时配置多个时返回 `ErrInvalidConfig`，
>   此前静默只用其中一个。
> - `GenerateEd25519Keys` / `GenerateRSAKeys` 不再覆盖已存在的密钥文件，返回满足 `errors.Is(err, fs.ErrExist)` 的错误。
> - 删除从未被返回的 `ErrHashUnavailable`；引用它的代码需要删掉对应分支。

### Added

- 会话有界刷新：`claims.Claims.AuthTime`（`auth_time`）记录首次签发时刻并在刷新时继承；
  `RefreshToken` 以 `auth_time + refreshDuration` 为会话终点，到达终点返回新 sentinel `ErrRefreshExpired`，
  新 token 的 `exp` 不越过终点，并保留旧 token 的有效时长。无 `auth_time` 的旧 token 以 `iat` 作起点。
- `WithRefreshWindow`：刷新窗口可配置，默认 5 分钟；token 有效期短于 5 分钟时默认窗口等于整段有效期。
- `Verifier` / `Issuer` 接口；`Tokener`、`ContextTokener` 方法集不变。
- 只持公钥的验签实例：`NewJwtRSAVerifier`、`NewJwtRSAVerifierFromFile`、`NewJwtEd25519Verifier`、`NewJwtEd25519VerifierFromFile`，
  签发与刷新返回新 sentinel `ErrNoSigningKey`。
- `NewJwtEd25519FromKeys` 与导出的 PEM 解析函数 `ParseRSAPrivateKeyPEM` / `ParseRSAPublicKeyPEM` /
  `ParseEd25519PrivateKeyPEM` / `ParseEd25519PublicKeyPEM`，支持 KMS、Vault、环境变量来源的密钥。
- `KeyRing`：按 `kid` 注册多个 `Verifier`，解析时自动选键并委托验签；空 kid 对应无 kid 的 token；
  未注册的 kid 返回新 sentinel `ErrUnknownKeyID`。实现 `Verifier`，并发安全，支持运行期 `Register` / `Unregister`。
- `WithParserOptions`：实例级 `jwtv5.ParserOption`，在默认选项之后、单次调用选项之前应用，缓存对其仍然生效。
- `WithRevocationCheck`：接收完整 `*claims.Claims` 的吊销回调，黑名单检查之后、缓存命中时同样执行，用于用户级吊销。
- `claims.Claims.Ext`（`ext`）与 `claims.WithExt`、`ExtString`、`ExtInt64`：承载 tenant_id、device_id 等业务扩展字段，缓存深拷贝覆盖嵌套结构。
- `GenerateHMACKeyString(method)`：按算法最小密钥长度生成随机密钥，返回可直接 `[]byte()` 使用的字符串。
- `ParseBearerToken` 与 sentinel `ErrAuthorizationMissing` / `ErrAuthorizationInvalid`。
- MIT `LICENSE`。

### Changed

- nil receiver 的 `ParallelVerify` / `ParallelVerifyContext` 返回与输入等长、全部为 `ErrJWTNotInit` 的错误切片（此前返回 `nil, nil`，按下标读取会越界）。
- 解析错误归一化时用 `%w` 同时包装 sentinel 与底层原因，`errors.Is` 判定不变，`err.Error()` 可见根因。
- 密钥加载错误统一：PEM 解码失败、长度错误、结构解析失败满足 `errors.Is(err, ErrInvalidKey)`，
  算法类型不符满足 `errors.Is(err, ErrInvalidKeyType)`，文件读取错误保留 `fs` 错误链并带路径。
- Ed25519 构造时校验公私钥匹配，不匹配返回 `ErrInvalidKey`。
- RSA 密钥长度要求统一为 RFC 7518 的 2048 bit 下限（此前 RS384/PS384 要求 3072、RS512/PS512 要求 4096）。
- `NewJwtHmac` / Ed25519 构造函数拒绝 `WithRSASigningMethod`，与 RSA 构造函数拒绝 `WithHMACSigningMethod` 对称。
- 错误文案：`ErrTokenUsedBeforeIssued` 改为 "Token 签发时间晚于当前时间"，`claims.ErrTokenPrv` 改为 "Token 业务域无效"。
- 密钥文件写入后 fsync；两个文件中任一创建失败时清理本次已创建的另一个。
- README 重写受影响章节：删除否定式清单，修正 HS512 密钥建议与 `iat` leeway 说法，补齐上述新能力用法与 Gin 接线示例。

### Deprecated

- `GenerateSecureKeyString`：改用 `GenerateHMACKeyString`，它按算法生成足够长的密钥。

### Removed

- `ErrHashUnavailable`。

## [v1.0.7] - 2026-09-15

### Added

- `ParseKeyID`：不验签地读出 token header 中的 `kid`，用于在验签前定位该用哪一把密钥。
  token 未携带 `kid` 时返回空字符串和 nil error；签名被篡改或 token 已过期时同样能读出。
  格式错误返回的错误满足 `errors.Is(err, ErrTokenMalformed)`。
  返回值来自未经验证的数据，只能用于挑选密钥，随后须用选中的密钥走一次 `ParseToken` 验签。

### Changed

- 测试依赖 `stretchr/testify` 升级到 v1.12.1
- README 的 `WithKeyID` 段落补上验证侧流程：密钥轮换与网关侧预校验两个示例
  均给出按 `kid` 选密钥后再验签的完整代码

## [v1.0.6] - 2026-09-15

### Added

- `WithKeyID`：签发时把密钥标识写入 JWT header 的 `kid` 字段，
  支持密钥轮换与网关侧按 `kid` 选择验签密钥。
  `JwtHmac` / `JwtEd25519` / `JwtRSA` 三种实现均生效，`RefreshToken` 产出的新 token 同样携带。
  不设置时 header 保持原样，对既有调用方无影响。
- `WithKeyID` 的测试覆盖三种签名实现的签发与刷新路径、向后兼容（未设置与空串均不写 kid）、
  需要 JSON 转义的 kid 取值，以及与 `WithHMACSigningMethod` 共存

## [v1.0.5] - 2026-06-15

### Added

- `WithCacheMaxEntries`：限制 `CachedParseToken` 的最大缓存条目数
- `WithBlacklistCheckContextFunc`：支持 context 取消和超时的黑名单检查函数
- `ParseTokenContext` / `CachedParseTokenContext` / `RefreshTokenContext`
- `ParallelVerifyContext`：支持 context 取消的并发验签
- `ContextParser` / `ContextCachedParser` / `ContextRefresher` / `ContextParallelVerifier` / `ContextTokener`
- fuzz 测试覆盖畸形 token 输入和 PEM key 解析入口
- GitHub Actions CI 固化 lint、vet、race test、coverage 和 fuzz seed 检查

### Changed

- `JwtHmac` / `JwtEd25519` / `JwtRSA` 文档明确说明可并发使用
- `NewJwtRSAFromKeys` 复制输入 RSA 密钥并预计算私钥
- `generateTokenImpl` 允许忽略 `nil` 的 claims option
- `CachedParseToken` 缓存改为严格容量上限的实例级 LRU

### Fixed

- `CachedParseToken` 在高基数 token 场景下不再无上限增长
- `ParallelVerify` 相关并发实现支持取消后的快速退出

## [v1.0.4] - 2026-06-15

### Changed

- `JwtHmac` / `JwtEd25519` / `JwtRSA` 的签发、解析、刷新逻辑抽象为共用实现，三种签名方式行为一致
- `helpers.go` 补充共用的 token 生成与解析辅助函数
- `doc.go` 补充包级文档，README 重写使用说明

## [v1.0.3] - 2025-04-10

### Added

- RSA 签名支持（RS256 / RS384 / RS512 / PS256 / PS384 / PS512）
- `NewJwtRSA`：从 PEM 文件加载密钥对创建实例
- `NewJwtRSAFromKeys`：从内存密钥对创建实例
- `GenerateRSAKeys`：RSA 密钥对生成工具
- `WithRSASigningMethod`：RSA 签名算法配置 Option
- `WithBlacklistCheckFunc`：支持返回错误的黑名单检查函数（fail closed）
- RSA 密钥长度校验（2048 bit 起，按算法要求递增）
- RSA 测试套件（签名/刷新/缓存/并发/黑名单/参数校验）

### Changed

- `JwtHmac` / `JwtEd25519` / `JwtRSA` 统一实现 `Tokener` 接口
- `ParseToken` / `CachedParseToken` 增加 nil receiver 保护

### Fixed

- `Ed25519` 创建时未校验 `hmacSigningSet` 配置冲突
- `JwtEd25519` 构造函数漏检 `hmacSigningSet` 配置冲突

## [v1.0.2] - 2025-04-09

### Added

- `RefreshToken` 刷新时自动轮换 TokenID/jti
- 黑名单增强接口 `BlacklistManager`，含 `AddToken` / `SweepExpired` / `Close`
- `NewBlacklistWithCleanup`：带后台清扫协程的黑名单工厂
- `AddWithExpiration`：带过期时间的黑名单加入
- `AddToken`：从 Claims 自动读取 TokenID 和 ExpiresAt 加入黑名单
- 黑名单惰性过期和主动清扫双机制
- `CachedParseToken`：带缓存的 token 解析
- `ParallelVerify`：有界 worker pool 并发验签
- 错误归一化：完整映射 golang-jwt 全部错误类型
- `claims.WithExpiresAtTime`：绝对过期时间 Option

### Changed

- `claims.WithExpiresAt` 标记为 Deprecated（原类型 `time.Duration` 语义混淆）
- 黑名单 `In` 方法增加双检锁，提升并发安全性
- 测试覆盖黑名单并发访问、缓存过期清扫、错误类型完整映射

### Fixed

- `RefreshToken` 刷新时未同步更新 `RegisteredClaims.ID`
- `alignTokenIdentifiers` 边界条件：TokenID 为空时未正确对齐

## [v1.0.1] - 2025-03-30

### Added

- 黑名单并发安全实现（`sync.RWMutex`）
- Claims 扩展字段：`Prv`（业务域）、`Roles`（角色）
- `WithBlacklistFunc`：外部黑名单函数注入
- 文档和示例补充

### Changed

- 优化黑名单 `In` 方法的双检锁模式

## [v1.0.0] - 2025-03-30

### Added

- 项目初始化
- HMAC-SHA 签名支持（默认 HS256、可选 HS384/HS512）
- `JwtHmac` 实现：签发、解析、刷新
- `claims.Claims` 结构：内嵌 JWT 标准字段 + 业务扩展
- Claims Option 模式：`WithRole` / `WithRoles` / `WithPrv` / `WithIssuer` / `WithSubject` / `WithAudience` / `WithExpiresIn`
- `Tokener` 统一接口
- `GenerateSecureKeyString` / `GenerateEd25519Keys` 密钥工具
- 内存黑名单基础实现 `Blacklist`
- sentinel error 体系

[v1.0.7]: https://github.com/gtkit/gojwt/compare/v1.0.6...v1.0.7
[v1.0.6]: https://github.com/gtkit/gojwt/compare/v1.0.5...v1.0.6
[v1.0.5]: https://github.com/gtkit/gojwt/compare/v1.0.4...v1.0.5
[v1.0.4]: https://github.com/gtkit/gojwt/compare/v1.0.3...v1.0.4
[v1.0.3]: https://github.com/gtkit/gojwt/compare/v1.0.2...v1.0.3
[v1.0.2]: https://github.com/gtkit/gojwt/compare/v1.0.1...v1.0.2
[v1.0.1]: https://github.com/gtkit/gojwt/compare/v1.0.0...v1.0.1
[v1.0.0]: https://github.com/gtkit/gojwt/releases/tag/v1.0.0
