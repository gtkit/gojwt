package claims

import "errors"

var (
	ErrTokenRole = errors.New("Token 角色无效")
	ErrTokenPrv  = errors.New("Token 模型无效")
)
