package gojwt

import (
	"errors"

	"github.com/gtkit/gojwt/claims"
)

// 主包 sentinel error 定义。
// 推荐使用 errors.Is 进行判断。
var (
	// ErrHashUnavailable 保留已发布错误符号兼容；标准签名实现不再返回它。
	// Deprecated: 请使用 ErrTokenSignatureInvalid 或 ErrInvalidConfig 判断签名配置错误。
	ErrHashUnavailable           = errors.New("hash 算法不可用")
	ErrInvalidConfig             = errors.New("invalid config")
	ErrJWTNotInit                = errors.New("JWT 未初始化")
	ErrInvalidKey                = errors.New("密钥无效")
	ErrInvalidKeyType            = errors.New("密钥类型无效")
	ErrNoSigningKey              = errors.New("实例未持有私钥，仅可验签")
	ErrUnknownKeyID              = errors.New("未注册的密钥标识 kid")
	ErrTokenMalformed            = errors.New("Token 格式错误")       //nolint:staticcheck // preserve public error text compatibility.
	ErrTokenUnverifiable         = errors.New("Token 无法验证")       //nolint:staticcheck // preserve public error text compatibility.
	ErrTokenSignatureInvalid     = errors.New("Token 签名无效")       //nolint:staticcheck // preserve public error text compatibility.
	ErrTokenRequiredClaimMissing = errors.New("Token 缺少必要的参数")    //nolint:staticcheck // preserve public error text compatibility.
	ErrTokenInvalidAudience      = errors.New("Token 受众无效")       //nolint:staticcheck // preserve public error text compatibility.
	ErrTokenExpired              = errors.New("Token 已过期")        //nolint:staticcheck // preserve public error text compatibility.
	ErrTokenUsedBeforeIssued     = errors.New("Token 签发时间晚于当前时间") //nolint:staticcheck // preserve public error text compatibility.
	ErrTokenInvalidIssuer        = errors.New("Token 签发者无效")      //nolint:staticcheck // preserve public error text compatibility.
	ErrTokenInvalidSubject       = errors.New("Token 主题无效")       //nolint:staticcheck // preserve public error text compatibility.
	ErrTokenNotValidYet          = errors.New("Token 尚未生效")       //nolint:staticcheck // preserve public error text compatibility.
	ErrTokenInvalidID            = errors.New("Token ID 无效")      //nolint:staticcheck // preserve public error text compatibility.
	ErrTokenInvalidClaims        = errors.New("Token 参数无效")       //nolint:staticcheck // preserve public error text compatibility.
	ErrTokenInvalid              = errors.New("Token 无效")         //nolint:staticcheck // preserve public error text compatibility.
	ErrTokenBlacklisted          = errors.New("Token 已被注销")       //nolint:staticcheck // preserve public error text compatibility.
	ErrRefreshTooEarly           = errors.New("未到 Token 刷新时间窗口")
	ErrRefreshExpired            = errors.New("Token 已超出最长刷新期限") //nolint:staticcheck // Preserve the public error text.
	ErrAuthorizationMissing      = errors.New("缺少 Authorization 头")
	ErrAuthorizationInvalid      = errors.New("Authorization 头格式无效") //nolint:staticcheck // Preserve the public error text.
	ErrTokenRole                 = claims.ErrTokenRole
	ErrTokenPrv                  = claims.ErrTokenPrv
)
