package claims

import "errors"

// Claims 子包的 sentinel error 定义。
var (
	// ErrTokenRole 角色校验失败。
	ErrTokenRole = errors.New("Token 角色无效")
	// ErrTokenPrv 业务域校验失败。
	ErrTokenPrv = errors.New("Token 模型无效")
)
