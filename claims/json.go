package claims

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
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
// 时间字段以 JSON NumericDate 保留纳秒精度，不修改 jwt/v5 的全局 TimePrecision。
func (c Claims) MarshalJSON() ([]byte, error) {
	type plain Claims
	// 外层时间字段覆盖嵌入字段，避免 NumericDate.MarshalJSON 再次截断小数秒。
	data, err := json.Marshal(struct {
		plain
		ExpiresAt json.RawMessage `json:"exp,omitempty"`
		NotBefore json.RawMessage `json:"nbf,omitempty"`
		IssuedAt  json.RawMessage `json:"iat,omitempty"`
		AuthTime  json.RawMessage `json:"auth_time,omitempty"`
	}{
		plain:     plain(c),
		ExpiresAt: marshalNumericDate(c.ExpiresAt),
		NotBefore: marshalNumericDate(c.NotBefore),
		IssuedAt:  marshalNumericDate(c.IssuedAt),
		AuthTime:  marshalNumericDate(c.AuthTime),
	})
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

func marshalNumericDate(date *jwtv5.NumericDate) json.RawMessage {
	if date == nil {
		return nil
	}
	seconds, nanos := date.Unix(), date.Nanosecond()
	if nanos == 0 {
		return json.RawMessage(strconv.FormatInt(seconds, 10))
	}
	// Unix 返回向下取整的秒数；负时间须转换成带符号的小数，例如 -0.5。
	negative := seconds < 0
	if negative {
		seconds++
		nanos = int(time.Second) - nanos
	}
	whole := strconv.FormatInt(seconds, 10)
	if negative && seconds == 0 {
		whole = "-0"
	}
	fraction := strconv.Itoa(nanos)
	fraction = strings.Repeat("0", 9-len(fraction)) + fraction
	return json.RawMessage(whole + "." + strings.TrimRight(fraction, "0"))
}
