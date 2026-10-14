/*
Package gojwt 是一个轻量、面向生产使用的 JWT 工具库。

# 为什么封装 gojwt

Go 生态中已经有了 github.com/golang-jwt/jwt/v5 这样优秀的底层库，
但直接在业务代码中使用它，你需要重复处理很多「配套工作」：

- 每次签发要手动拼接 Claims、生成 TokenID、设置时间字段
- 每次解析要处理黑名单检查、错误归一化
- 刷新 token 时要重新生成 ID、重置时间，还要给会话设上界
- 缓存解析要自己维护
- 不同类型（HMAC / RSA / Ed25519）的签名切换需要改大量代码
- 密钥轮换要自己按 kid 选键

gojwt 把这些「反复要做但又不是业务核心」的事情全部标准化了，
让你只需要关心「谁、什么角色、能不能过」。

# 四类签名方式

- HMAC-SHA 家族：默认 HS256，可选 HS384、HS512
- Ed25519（EdDSA）：非对称签名
- ECDSA：ES256/P-256、ES384/P-384、ES512/P-521
- RSA 家族：默认 RS256，可选 RS384/RS512（PKCS1-v1_5）及 PS256/PS384/PS512（PSS）

非对称算法还提供只持公钥的验签实例（NewJwtRSAVerifier、NewJwtEd25519Verifier、NewJwtECDSAVerifier 及对应的 FromFile 变体），
供只做验签的服务与网关使用。

# 核心能力

- GenerateToken / ParseToken / ParseTokenContext：基础签发与验签
- RefreshToken / RefreshTokenContext：临期续签，自动轮换 TokenID，会话以 auth_time + refreshDuration 为上界
- CachedParseToken / CachedParseTokenContext：带缓存的解析，减少重复验签开销
- ParallelVerify / ParallelVerifyContext：有界 worker pool 并发验签
- NewVerifier / KeyResolver：第三方 JWT 验证与可信密钥来源扩展
- jwks 子包：公钥集编解码、发布、带 TTL/超时/节流的远程刷新
- KeyRing：按 kid 汇集多个验签方，密钥轮换期新旧密钥并存
- Blacklist / BlacklistManager：并发安全的内存黑名单，支持带过期时间
- WithBlacklistCheckContextFunc / WithRevocationCheck：接入外部黑名单与用户级吊销
- WithClaimsValidator：接入应用 claims 校验，缓存命中时仍执行，标准字段与 JSON 容器副本隔离
- claims.WithExt / ExtString / ExtInt64：承载 tenant_id、device_id 等业务扩展字段
- ParseBearerToken / ParseBearerRequest：提取 Bearer 凭据，拒绝非法字符与重复头部
- Tokener / Verifier / Issuer：统一接口，面向接口编程可无缝切换算法

# 续签与会话管理

RefreshToken / RefreshTokenContext 每次调用独立签发新 JWT；同一旧 token 可以被重复或并发续签，
旧 token 不会被自动消费或吊销。这些方法不提供刷新去重、幂等重试、独立 refresh token 轮换或重放检测。
一次性消费、重试结果与多实例一致性由应用的认证 service 和共享存储管理。
WithRevocationCheck 只检查吊销状态，不应在回调中消费凭证；回调可能并发执行，必须并发安全。
通过会话 ID 和版本检查，可以同时吊销原 token 与已经续签出的 token。

# 设计原则

- 零外部基础设施依赖（不依赖 Redis、DB）
- Functional Options 配置模式，非法组合在构造期报错
- 所有错误都是 sentinel error，统一用 errors.Is 判断，错误链保留底层原因
- 解析强制 exp、iat/nbf 时间校验和算法白名单；应用配置期望的 iss/aud/sub
- 内部使用 mutex、LRU map 和 RWMutex 确保并发安全
- Claims 深拷贝，防止外部意外篡改缓存
- 缓存默认最多 4096 条，按 LRU 淘汰，可通过 WithCacheMaxEntries 调整
*/
package gojwt
