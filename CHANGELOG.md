# Changelog

所有重要变更均记录在此文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
版本遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

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

[v1.0.6]: https://github.com/gtkit/gojwt/compare/v1.0.5...v1.0.6
[v1.0.5]: https://github.com/gtkit/gojwt/compare/v1.0.4...v1.0.5
[v1.0.4]: https://github.com/gtkit/gojwt/compare/v1.0.3...v1.0.4
[v1.0.3]: https://github.com/gtkit/gojwt/compare/v1.0.2...v1.0.3
[v1.0.2]: https://github.com/gtkit/gojwt/compare/v1.0.1...v1.0.2
[v1.0.1]: https://github.com/gtkit/gojwt/compare/v1.0.0...v1.0.1
[v1.0.0]: https://github.com/gtkit/gojwt/releases/tag/v1.0.0
