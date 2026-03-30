package gojwt

import (
	"errors"

	"github.com/gtkit/gojwt/claims"
)

// 主包 sentinel error 定义。
// 推荐使用 errors.Is 进行判断。
var (
	ErrJWTNotInit                = errors.New("JWT 未初始化")
	ErrInvalidKey                = errors.New("密钥无效")
	ErrInvalidKeyType            = errors.New("密钥类型无效")
	ErrHashUnavailable           = errors.New("hash 算法不可用")
	ErrTokenMalformed            = errors.New("Token 格式错误")
	ErrTokenUnverifiable         = errors.New("Token 无法验证")
	ErrTokenSignatureInvalid     = errors.New("Token 签名无效")
	ErrTokenRequiredClaimMissing = errors.New("Token 缺少必要的参数")
	ErrTokenExpired              = errors.New("Token 已过期")
	ErrTokenUsedBeforeIssued     = errors.New("Token 已使用")
	ErrTokenInvalidIssuer        = errors.New("Token 签发者无效")
	ErrTokenInvalidSubject       = errors.New("Token 主题无效")
	ErrTokenNotValidYet          = errors.New("Token 尚未生效")
	ErrTokenInvalidID            = errors.New("Token ID 无效")
	ErrTokenInvalidClaims        = errors.New("Token 参数无效")
	ErrTokenInvalid              = errors.New("Token 无效")
	ErrTokenBlacklisted          = errors.New("Token 已被注销")
	ErrRefreshTooEarly           = errors.New("未到 Token 刷新时间窗口")
	ErrTokenRole                 = claims.ErrTokenRole
	ErrTokenPrv                  = claims.ErrTokenPrv
)
