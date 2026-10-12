package claims

import (
	"encoding/json"
	"fmt"
	"strings"
)

// IsReservedName 报告字段名是否属于 Claims 的标准字段或内置业务字段。
// 大小写变体也保留，防止 encoding/json 的不区分大小写匹配产生歧义。
func IsReservedName(name string) bool {
	for _, reserved := range []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti", "uid", "prv", "roles", "token_id", "auth_time", "ext"} {
		if strings.EqualFold(name, reserved) {
			return true
		}
	}
	return false
}

// MarshalJSON 编码内置字段并合并 Custom 顶层字段，拒绝保留名称覆盖。
func (c Claims) MarshalJSON() ([]byte, error) {
	type plain Claims
	data, err := json.Marshal(plain(c))
	if err != nil || len(c.Custom) == 0 {
		return data, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	for key, value := range c.Custom {
		if IsReservedName(key) {
			return nil, fmt.Errorf("custom claim %q conflicts with a reserved field", key)
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("encode custom claim %q: %w", key, err)
		}
		fields[key] = encoded
	}
	return json.Marshal(fields)
}
