# In-Memory Blacklist Expiration Design

**Date:** 2026-04-09

## Goal

让内存 `Blacklist` 支持按 token 自身 `exp` 自动失效，避免黑名单条目随进程运行时间无限增长，同时保持现有公开接口兼容。

## Scope

只改内存黑名单实现与相关文档、测试：

- 保留现有 `Blacklister` 接口不变
- 为具体实现 `Blacklist` 增加基于 token 过期时间的新增方法
- 让 `In` 对过期条目做惰性清理
- README 和示例优先展示 exp-aware 用法

不在本次范围内：

- Redis / DB 黑名单实现
- 后台清扫 goroutine
- `WithBlacklistCheckFunc` 的接口继续扩展

## Chosen Approach

采用兼容优先方案。

`Blacklister` 继续保留：

- `In(tokenID string) bool`
- `Add(tokenID string)`
- `Remove(tokenID string)`

`Blacklist` 内部存储从 `map[string]struct{}` 改为 `map[string]time.Time`，value 表示该黑名单记录的过期时间：

- `time.Time{}` 零值表示永久拉黑，对应兼容旧的 `Add(tokenID string)`
- 非零值表示条目会在指定时间后自动失效

新增 `Blacklist` 专属方法：

- `AddToken(tokenClaims *claims.Claims) error`
- `AddWithExpiration(tokenID string, expiresAt time.Time)`

## API Behavior

### Existing API

`Add(tokenID string)` 保持兼容，但语义明确为：

- 永久加入黑名单
- 直到调用 `Remove` 才会移除

### New API

`AddToken(tokenClaims *claims.Claims) error`

- 从 `tokenClaims.TokenID` 读取 key
- 从 `tokenClaims.ExpiresAt` 读取过期时间
- 缺少 `TokenID` 或 `ExpiresAt` 时返回错误

`AddWithExpiration(tokenID string, expiresAt time.Time)`

- 用于调用方已经拿到 tokenID 和 exp 的场景
- `expiresAt` 为零值时按永久拉黑处理

### Lookup Path

`In(tokenID string) bool` 增加惰性过期逻辑：

- 找不到条目：返回 `false`
- 条目为永久拉黑：返回 `true`
- 条目已过期：先删除，再返回 `false`
- 条目未过期：返回 `true`

## Compatibility

- 现有依赖 `Blacklister` 的调用方无需改动
- 现有直接调用 `Blacklist.Add(tokenID)` 的代码行为不变
- 新功能只对使用 `*Blacklist` 具体类型的调用方开放

## Testing Plan

新增测试覆盖：

- `AddToken` 会按 claims 的 `exp` 自动失效
- `AddWithExpiration` 会按指定时间自动失效
- `Add(tokenID)` 仍然是永久拉黑
- `In` 命中过期条目后会惰性删除
- `AddToken` 对缺少 `TokenID` / `ExpiresAt` 的输入返回错误

## Documentation Plan

README 需要同步：

- `Blacklist` 新增 exp-aware 用法
- 登出示例优先改为 `AddToken(tokenClaims)`
- 明确说明旧 `Add(tokenID)` 是永久拉黑的兼容接口

## Rationale

这个方案解决了“内存黑名单无限增长”的核心问题，同时不对现有公开接口做 breaking change。它也保留了手工永久拉黑的能力，适合兼容历史调用方和简单场景。
